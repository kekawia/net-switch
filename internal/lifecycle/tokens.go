package lifecycle

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"
)

// A session lasts as long as the desktop program's connection to Control; the
// key it hands the window lasts at most tokenLifetime. The desktop program
// asks for its session again every few minutes, and in the last tokenRenewal
// of a key's life it gets a new one. The key it replaces keeps working until
// its own end, so a request already sent with it, or a window that hasn't
// received the new one yet, isn't refused.
const (
	tokenLifetime = 12 * time.Hour
	tokenRenewal  = time.Hour
)

type session struct {
	expires      time.Time
	token, code  string
	previous     string
	previousEnds time.Time
	codeExpires  time.Time
	attempts     int
}
type Tokens struct {
	mu       sync.Mutex
	now      func() time.Time
	sessions map[string]*session
}

func NewTokens() *Tokens { return &Tokens{now: time.Now, sessions: map[string]*session{}} }
func (t *Tokens) Open(id string) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	token := randomID()
	t.sessions[id] = &session{expires: t.now().Add(tokenLifetime), token: token}
	return token
}

// Get returns the session's current key, replacing it when it ends within
// tokenRenewal or already has. A key that ran out while the connection stayed
// open (after the PC slept, for example) is replaced the same way.
func (t *Tokens) Get(id string) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.sessions[id]
	if s == nil {
		return "", errors.New("desktop session closed or revoked")
	}
	now := t.now()
	if !now.Before(s.expires.Add(-tokenRenewal)) {
		s.previous, s.previousEnds = s.token, s.expires
		s.token, s.expires = randomID(), now.Add(tokenLifetime)
	}
	return s.token, nil
}
func (t *Tokens) Close(id string) { t.mu.Lock(); defer t.mu.Unlock(); delete(t.sessions, id) }
func (t *Tokens) RevokeAll()      { t.mu.Lock(); defer t.mu.Unlock(); t.sessions = map[string]*session{} }
func equal(a, b string) bool {
	return a != "" && len(a) == len(b) && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
func (t *Tokens) Valid(token string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	for _, s := range t.sessions {
		if (now.Before(s.expires) && equal(s.token, token)) || (now.Before(s.previousEnds) && equal(s.previous, token)) {
			return true
		}
	}
	return false
}
func (t *Tokens) Pairing(id string) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.sessions[id]
	if s == nil || !t.now().Before(s.expires) {
		return "", errors.New("desktop session expired")
	}
	// One active browser fallback code at a time. Rotating a code is possible
	// only through the authenticated desktop connection.
	for _, old := range t.sessions {
		old.code = ""
	}
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}
	s.code = fmt.Sprintf("%06d", n.Int64())
	s.codeExpires = t.now().Add(2 * time.Minute)
	s.attempts = 0
	return s.code, nil
}
func (t *Tokens) Redeem(code string) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, s := range t.sessions {
		if s.code == "" || !t.now().Before(s.codeExpires) || !t.now().Before(s.expires) {
			continue
		}
		s.attempts++
		ok := equal(s.code, code)
		if ok || s.attempts >= 3 {
			s.code = ""
		}
		if ok {
			return s.token, nil
		}
		break
	}
	return "", errors.New("pairing code is invalid or expired")
}
