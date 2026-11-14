// Package secrets stores outbound proxy credentials outside settings.json,
// control-journal.json, and policy hashes. On Windows, secrets are encrypted
// with LocalSystem/current-user DPAPI (never CRYPTPROTECT_LOCAL_MACHINE); on
// Unix, secrets live in a 0600 root-owned file written via atomic rename.
package secrets

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/AyoubAchour/net-switch/internal/engine/proxy"
	"github.com/AyoubAchour/net-switch/internal/settings"
)

const DefaultFileName = "proxy-secrets.json"

// Sealer encrypts and decrypts a secret payload bound to a credential reference.
type Sealer interface {
	Seal(ref string, plaintext []byte) (scheme string, sealed []byte, err error)
	Open(ref, scheme string, sealed []byte) ([]byte, error)
}

// Options configures a secret Store.
type Options struct {
	FileName   string
	Files      settings.Files
	Sealer     Sealer
	SyncFile   func(string) error
	SyncParent func(string) error
}

type filePayload struct {
	Version int                    `json:"version"`
	LastRev uint64                 `json:"lastRev"`
	Entries map[string]storedEntry `json:"entries"`
}

type storedEntry struct {
	Scheme     string `json:"scheme"`
	Rev        uint64 `json:"rev"`
	Ciphertext string `json:"ciphertext"`
}

type secretPlaintext struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Store lazily loads and atomically persists sealed proxy credentials.
// Constructing a Store performs zero filesystem reads or writes so non-proxy
// startups and trace replays incur no extra file operations.
type Store struct {
	mu      sync.Mutex
	file    string
	opts    settings.Options
	sealer  Sealer
	realOS  bool
	loaded  bool
	lastRev uint64
	entries map[string]storedEntry
}

func New(dir string, o Options) *Store {
	name := o.FileName
	if name == "" {
		name = DefaultFileName
	}
	sealer := o.Sealer
	if sealer == nil {
		sealer = defaultSealer{}
	}
	return &Store{
		file: filepath.Join(dir, name),
		opts: settings.Options{
			FileName:   name,
			Files:      o.Files,
			SyncFile:   o.SyncFile,
			SyncParent: o.SyncParent,
		},
		sealer:  sealer,
		realOS:  o.Files == nil,
		entries: map[string]storedEntry{},
	}
}

func (s *Store) File() string { return s.file }

// Put seals and atomically persists credentials for ref, returning a strictly
// increasing CredentialsRev suitable for inclusion in policy.Config.
func (s *Store) Put(ref string, creds proxy.Credentials) (uint64, error) {
	if ref == "" {
		return 0, errors.New("empty credentials reference")
	}
	if creds.Empty() {
		return 0, errors.New("empty proxy credentials")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureLoadedLocked(); err != nil {
		return 0, err
	}

	rawPlain, err := json.Marshal(secretPlaintext{
		Username: creds.Username,
		Password: creds.Password,
	})
	if err != nil {
		return 0, err
	}
	defer zeroBytes(rawPlain)

	scheme, sealed, err := s.sealer.Seal(ref, rawPlain)
	if err != nil {
		return 0, fmt.Errorf("seal credentials %q: %w", ref, err)
	}

	nextRev := s.lastRev + 1
	if prev, ok := s.entries[ref]; ok && prev.Rev >= nextRev {
		nextRev = prev.Rev + 1
	}

	nextEntries := cloneEntries(s.entries)
	nextEntries[ref] = storedEntry{
		Scheme:     scheme,
		Rev:        nextRev,
		Ciphertext: base64.StdEncoding.EncodeToString(sealed),
	}
	if err := s.saveLocked(nextRev, nextEntries); err != nil {
		return 0, err
	}
	s.lastRev = nextRev
	s.entries = nextEntries
	return nextRev, nil
}

// Get loads and unseals credentials for ref. If ref does not exist, ok is false
// and err is nil.
func (s *Store) Get(ref string) (proxy.Credentials, uint64, bool, error) {
	if ref == "" {
		return proxy.Credentials{}, 0, false, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureLoadedLocked(); err != nil {
		return proxy.Credentials{}, 0, false, err
	}
	entry, ok := s.entries[ref]
	if !ok {
		return proxy.Credentials{}, 0, false, nil
	}
	creds, err := s.openEntryLocked(ref, entry)
	if err != nil {
		return proxy.Credentials{}, 0, false, err
	}
	return creds, entry.Rev, true, nil
}

// Resolve unseals all requested non-empty credential references in a single
// pass. When refs contains no non-empty strings, Resolve returns nil without
// touching the filesystem.
func (s *Store) Resolve(refs []string) (map[string]proxy.Credentials, error) {
	needed := make([]string, 0, len(refs))
	seen := make(map[string]struct{}, len(refs))
	for _, ref := range refs {
		if ref == "" {
			continue
		}
		if _, dup := seen[ref]; dup {
			continue
		}
		seen[ref] = struct{}{}
		needed = append(needed, ref)
	}
	if len(needed) == 0 {
		return nil, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureLoadedLocked(); err != nil {
		return nil, err
	}
	out := make(map[string]proxy.Credentials, len(needed))
	for _, ref := range needed {
		entry, ok := s.entries[ref]
		if !ok {
			continue
		}
		creds, err := s.openEntryLocked(ref, entry)
		if err != nil {
			return nil, err
		}
		out[ref] = creds
	}
	return out, nil
}

// Delete removes stored credentials for ref while preserving the monotonic
// revision watermark so a later Put on the same ref receives a higher revision.
func (s *Store) Delete(ref string) error {
	if ref == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureLoadedLocked(); err != nil {
		return err
	}
	if _, ok := s.entries[ref]; !ok {
		return nil
	}
	nextEntries := cloneEntries(s.entries)
	delete(nextEntries, ref)
	if err := s.saveLocked(s.lastRev, nextEntries); err != nil {
		return err
	}
	s.entries = nextEntries
	return nil
}

func (s *Store) openEntryLocked(ref string, entry storedEntry) (proxy.Credentials, error) {
	cipherBytes, err := base64.StdEncoding.DecodeString(entry.Ciphertext)
	if err != nil {
		return proxy.Credentials{}, fmt.Errorf("decode ciphertext for %q: %w", ref, err)
	}
	rawPlain, err := s.sealer.Open(ref, entry.Scheme, cipherBytes)
	if err != nil {
		return proxy.Credentials{}, fmt.Errorf("unseal credentials %q: %w", ref, err)
	}
	defer zeroBytes(rawPlain)

	var plain secretPlaintext
	if err := json.Unmarshal(rawPlain, &plain); err != nil {
		return proxy.Credentials{}, fmt.Errorf("parse credentials %q: %w", ref, err)
	}
	return proxy.Credentials{
		Username: plain.Username,
		Password: plain.Password,
	}, nil
}

func (s *Store) ensureLoadedLocked() error {
	if s.loaded {
		return nil
	}
	readFile := os.ReadFile
	if s.opts.Files != nil {
		readFile = s.opts.Files.ReadFile
	}
	data, err := readFile(s.file)
	if errors.Is(err, fs.ErrNotExist) {
		s.entries = map[string]storedEntry{}
		s.lastRev = 0
		s.loaded = true
		return nil
	}
	if err != nil {
		return err
	}
	payload, err := parsePayload(data)
	if err != nil {
		// Fall back to .bak if primary file was torn or corrupted.
		bakData, bakErr := readFile(s.file + ".bak")
		if bakErr != nil {
			return fmt.Errorf("parse %s: %w", s.file, err)
		}
		payload, err = parsePayload(bakData)
		if err != nil {
			return fmt.Errorf("parse %s and backup: %w", s.file, err)
		}
	}
	if payload.Entries == nil {
		payload.Entries = map[string]storedEntry{}
	}
	maxRev := payload.LastRev
	for _, e := range payload.Entries {
		if e.Rev > maxRev {
			maxRev = e.Rev
		}
	}
	s.entries = payload.Entries
	s.lastRev = maxRev
	s.loaded = true
	return nil
}

func parsePayload(data []byte) (filePayload, error) {
	var p filePayload
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return filePayload{}, err
	}
	if p.Version != 1 {
		return filePayload{}, fmt.Errorf("unsupported secrets version %d", p.Version)
	}
	return p, nil
}

func (s *Store) saveLocked(lastRev uint64, entries map[string]storedEntry) error {
	if s.realOS {
		if err := os.MkdirAll(filepath.Dir(s.file), 0700); err != nil {
			return err
		}
	}
	payload := filePayload{
		Version: 1,
		LastRev: lastRev,
		Entries: entries,
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(payload); err != nil {
		return err
	}
	text := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
	if err := settings.AtomicWrite(s.file, text, s.opts); err != nil {
		return err
	}
	_ = settings.AtomicWrite(s.file+".bak", text, s.opts)
	if s.realOS {
		_ = enforceOwnerOnlyPerm(s.file)
		_ = enforceOwnerOnlyPerm(s.file + ".bak")
	}
	return nil
}

func cloneEntries(src map[string]storedEntry) map[string]storedEntry {
	out := make(map[string]storedEntry, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
