// updatefixture serves real installer bytes and a development-root signature
// chain only on loopback in the disposable hosted installer suite.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/kekawia/net-switch/internal/updates"
	"golang.org/x/crypto/blake2b"
)

func developmentRoot() string {
	seed := sha256.Sum256([]byte("Net Switch development root, never a release trust anchor"))
	private := ed25519.NewKeyFromSeed(seed[:])
	raw := make([]byte, 158)
	copy(raw[:2], "Ed")
	copy(raw[4:6], "B2")
	copy(raw[54:62], seed[:8])
	copy(raw[62:126], private)
	checksum := blake2b.Sum256(append(append([]byte("Ed"), seed[:8]...), private...))
	copy(raw[126:], checksum[:])
	return "untrusted comment: PUBLIC DEVELOPMENT TEST KEY\n" + base64.StdEncoding.EncodeToString(raw) + "\n"
}

type fixture struct {
	mu                                    sync.RWMutex
	mode, version, arch, installer, token string
	size                                  int64
	hash, releasePublic, releaseSecret    string
	now                                   time.Time
}

func (f *fixture) metadata() (map[string][]byte, string, error) {
	version := f.version
	if f.mode == "downgrade" {
		version = "0.9.0"
	}
	// All four GETs must describe the same exact signed bytes, including times.
	now := f.now
	key := updates.ReleaseKeyStatement{Purpose: "netswitch-release-signing", PublicKey: f.releasePublic, IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(24 * time.Hour)}
	manifest := updates.Manifest{Product: "net-switch", Architecture: f.arch, Version: version, URL: updates.InstallerURL(version, f.arch), SHA256: f.hash, Size: f.size, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(12 * time.Hour)}
	if f.mode == "expired" {
		manifest.IssuedAt = now.Add(-40 * time.Minute)
		manifest.ExpiresAt = now.Add(-time.Minute)
	}
	if f.mode == "wrong-arch" {
		manifest.Architecture = "arm64"
		if f.arch == "arm64" {
			manifest.Architecture = "x64"
		}
	}
	keyRaw, err := json.Marshal(key)
	if err != nil {
		return nil, "", err
	}
	keySig, err := updates.SignMinisign(developmentRoot(), keyRaw, "hosted development release key")
	if err != nil {
		return nil, "", err
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		return nil, "", err
	}
	sig, err := updates.SignMinisign(f.releaseSecret, raw, "hosted update fixture")
	if err != nil {
		return nil, "", err
	}
	if f.mode == "bad-signature" {
		sig[len(sig)-3] ^= 1
	}
	name := "update-manifest-" + f.arch + ".json"
	return map[string][]byte{"netswitch-release-key.json": keyRaw, "netswitch-release-key.json.minisig": keySig, name: raw, name + ".minisig": sig}, version, nil
}

func (f *fixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Update-Fixture") != f.token {
		http.Error(w, "unauthorized", 401)
		return
	}
	if r.Method == "POST" && r.URL.Path == "/mode" {
		var input struct {
			Mode string `json:"mode"`
		}
		if json.NewDecoder(io.LimitReader(r.Body, 1024)).Decode(&input) != nil {
			http.Error(w, "bad input", 400)
			return
		}
		switch input.Mode {
		case "valid", "bad-signature", "expired", "wrong-arch", "downgrade", "tampered-installer":
		default:
			http.Error(w, "unknown mode", 400)
			return
		}
		f.mu.Lock()
		f.mode = input.Mode
		f.mu.Unlock()
		w.WriteHeader(204)
		return
	}
	if r.Method != "GET" {
		http.Error(w, "GET required", 405)
		return
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	files, version, err := f.metadata()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	installerName := "NetSwitch-Setup-" + version + "-" + f.arch + ".exe"
	if r.URL.Path == "/repositories/1418987447/releases/latest" {
		assets := []map[string]string{}
		for name := range files {
			assets = append(assets, map[string]string{"name": name, "browser_download_url": updates.ReleaseBase + "download/v" + version + "/" + name})
		}
		assets = append(assets, map[string]string{"name": installerName, "browser_download_url": updates.InstallerURL(version, f.arch)})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"tag_name": "v" + version, "html_url": updates.ReleaseBase + "tag/v" + version, "assets": assets})
		return
	}
	prefix := "/kekawia/net-switch/releases/download/v" + version + "/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		http.NotFound(w, r)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, prefix)
	if raw, ok := files[name]; ok {
		_, _ = w.Write(raw)
		return
	}
	if name != installerName {
		http.NotFound(w, r)
		return
	}
	if f.mode == "tampered-installer" {
		_, _ = w.Write([]byte("invalid installer bytes"))
		return
	}
	http.ServeFile(w, r, f.installer)
}

func run() error {
	installer := flag.String("installer", "", "real target installer")
	version := flag.String("version", "1.0.11", "target version")
	arch := flag.String("arch", "", "x64 or arm64")
	state := flag.String("state", "", "protected fixture connection output")
	servicePaths := flag.Bool("service-paths", false, "read installed service paths with query-only SCM access")
	flag.Parse()
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		return errors.New("update installer fixture requires disposable hosted CI")
	}
	if *servicePaths {
		return printServicePaths()
	}
	if *state == "" || !filepath.IsAbs(*installer) || !updates.CanonicalVersion(*version) || (*arch != "x64" && *arch != "arm64") {
		return errors.New("invalid update fixture arguments")
	}
	root, err := updates.PublicKeyFromSecret(developmentRoot())
	if err != nil || root != updates.DevelopmentRootPublicKey {
		return errors.New("development root fixture differs")
	}
	input, err := os.Open(*installer)
	if err != nil {
		return err
	}
	defer input.Close()
	hash := sha256.New()
	size, err := io.Copy(hash, input)
	if err != nil {
		return err
	}
	public, secret, err := updates.GenerateKeyPair()
	if err != nil {
		return err
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	f := &fixture{mode: "valid", version: *version, arch: *arch, installer: *installer, size: size, hash: hex.EncodeToString(hash.Sum(nil)), releasePublic: public, releaseSecret: secret, token: hex.EncodeToString(random), now: time.Now().UTC()}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	raw, err := json.Marshal(map[string]string{"url": "http://" + listener.Addr().String(), "token": f.token})
	if err != nil {
		return err
	}
	if err := os.WriteFile(*state, raw, 0600); err != nil {
		return err
	}
	server := &http.Server{Handler: f, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 2 * time.Minute}
	return server.Serve(listener)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
