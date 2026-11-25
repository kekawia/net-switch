package lifecycle

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kekawia/net-switch/internal/localipc"
)

func TestPairingSingleUseAndConnectionLifetime(t *testing.T) {
	tokens := NewTokens()
	token := tokens.Open("desktop")
	if len(token) != 64 || !tokens.Valid(token) {
		t.Fatal("expected a 256-bit session token")
	}
	code, err := tokens.Pairing("desktop")
	if err != nil || len(code) != 6 {
		t.Fatal(code, err)
	}
	var successes int
	var mu sync.Mutex
	var group sync.WaitGroup
	for range 16 {
		group.Go(func() {
			if got, err := tokens.Redeem(code); err == nil {
				if got != token {
					t.Error("wrong token")
				}
				mu.Lock()
				successes++
				mu.Unlock()
			}
		})
	}
	group.Wait()
	if successes != 1 {
		t.Fatalf("code redeemed %d times", successes)
	}
	tokens.Close("desktop")
	if tokens.Valid(token) {
		t.Fatal("token survived disconnect")
	}
	if _, err := tokens.Pairing("desktop"); err == nil {
		t.Fatal("anonymous code reset")
	}
}
func TestPairingThreeTriesAcrossAllConnections(t *testing.T) {
	tokens := NewTokens()
	tokens.Open("desktop")
	code, _ := tokens.Pairing("desktop")
	wrong := "000000"
	if wrong == code {
		wrong = "000001"
	}
	for range 3 {
		if _, err := tokens.Redeem(wrong); err == nil {
			t.Fatal("wrong code accepted")
		}
	}
	if _, err := tokens.Redeem(code); err == nil {
		t.Fatal("fourth try accepted")
	}
	next, _ := tokens.Pairing("desktop")
	if _, err := tokens.Redeem(next); err != nil {
		t.Fatal("authenticated renewal failed", err)
	}
}
func TestTokenAndPairingExpiry(t *testing.T) {
	tokens := NewTokens()
	now := time.Now()
	tokens.now = func() time.Time { return now }
	token := tokens.Open("desktop")
	code, _ := tokens.Pairing("desktop")
	now = now.Add(2 * time.Minute)
	if _, err := tokens.Redeem(code); err == nil {
		t.Fatal("expired code accepted")
	}
	if !tokens.Valid(token) {
		t.Fatal("token expired too soon")
	}
	now = now.Add(12 * time.Hour)
	if tokens.Valid(token) {
		t.Fatal("12-hour token still valid")
	}
	if NewTokens().Valid(token) {
		t.Fatal("token survived Control restart")
	}
	if tokens.Valid("") || tokens.Valid(strings.Repeat("x", 64)) {
		t.Fatal("invalid token accepted")
	}
}

// A window left open for more than 12 hours: its desktop program stays
// connected, so asking for the session again must hand out a new key, and no
// key may work longer than 12 hours.
func TestTokenRenewalWhileConnected(t *testing.T) {
	tokens := NewTokens()
	start := time.Now()
	now := start
	tokens.now = func() time.Time { return now }
	first := tokens.Open("desktop")

	now = start.Add(tokenLifetime - tokenRenewal - time.Minute)
	if got, err := tokens.Get("desktop"); err != nil || got != first {
		t.Fatalf("key replaced before its last hour: %v", err)
	}

	now = start.Add(tokenLifetime - tokenRenewal)
	second, err := tokens.Get("desktop")
	if err != nil || second == first || len(second) != 64 {
		t.Fatalf("no new key in the last hour: %v", err)
	}
	if again, _ := tokens.Get("desktop"); again != second {
		t.Fatal("a fresh key was replaced again")
	}
	if !tokens.Valid(first) || !tokens.Valid(second) {
		t.Fatal("old and new keys must both work until the old one ends")
	}
	code, _ := tokens.Pairing("desktop")
	if got, err := tokens.Redeem(code); err != nil || got != second {
		t.Fatal("pairing after renewal must give the current key", err)
	}

	now = start.Add(tokenLifetime)
	if tokens.Valid(first) {
		t.Fatal("replaced key outlived its 12 hours")
	}
	if !tokens.Valid(second) {
		t.Fatal("new key refused")
	}

	// The PC slept past the new key's end while the program stayed connected.
	now = now.Add(tokenLifetime)
	if tokens.Valid(second) {
		t.Fatal("key outlived its 12 hours")
	}
	third, err := tokens.Get("desktop")
	if err != nil || third == second || !tokens.Valid(third) {
		t.Fatalf("connected session got no working key after its key ran out: %v", err)
	}
	if tokens.Valid(second) {
		t.Fatal("expired key came back after renewal")
	}

	tokens.Close("desktop")
	if tokens.Valid(third) {
		t.Fatal("key survived disconnect")
	}
	if _, err := tokens.Get("desktop"); err == nil {
		t.Fatal("closed session handed out a key")
	}
}

// The same renewal through the owner's pipe request, as Control answers the
// desktop program's "session" call.
func TestSessionRequestRenewsAnExpiredKeyForTheConnectedOwner(t *testing.T) {
	tokens := NewTokens()
	now := time.Now()
	tokens.now = func() time.Time { return now }
	a := &Access{Owner: Owner{User: "owner", Name: "Owner"}, Tokens: tokens, Port: 47821}
	first := tokens.Open("pipe")
	now = now.Add(tokenLifetime + time.Minute)
	if tokens.Valid(first) {
		t.Fatal("key outlived its 12 hours")
	}
	ask := func(user string) (string, error) {
		v, err := a.request(context.Background(), localipc.Peer{User: user}, false, "pipe", controlRequest{Method: "session"})
		reply, _ := v.(map[string]any)
		token, _ := reply["token"].(string)
		return token, err
	}
	if _, err := ask("stranger"); err == nil {
		t.Fatal("another account was handed the owner's key")
	}
	renewed, err := ask("owner")
	if err != nil || renewed == first || !tokens.Valid(renewed) {
		t.Fatalf("connected owner got no working key: %v", err)
	}
}
