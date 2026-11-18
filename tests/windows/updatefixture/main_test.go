package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kekawia/net-switch/internal/updates"
)

type localTransport struct {
	base  *url.URL
	token string
}

func (tr localTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	copy := request.Clone(request.Context())
	location := *request.URL
	location.Scheme = tr.base.Scheme
	location.Host = tr.base.Host
	copy.URL = &location
	copy.Header.Set("X-Update-Fixture", tr.token)
	return http.DefaultTransport.RoundTrip(copy)
}

func TestFixtureServesStableSignedBytesAndRefusals(t *testing.T) {
	payload := []byte("installer bytes for transport verification; never executed")
	file := filepath.Join(t.TempDir(), "installer.exe")
	if err := os.WriteFile(file, payload, 0600); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(payload)
	public, secret, err := updates.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{mode: "valid", version: "1.0.11", arch: "x64", installer: file, token: "test-only", size: int64(len(payload)), hash: hex.EncodeToString(hash[:]), releasePublic: public, releaseSecret: secret, now: time.Now().UTC()}
	server := httptest.NewServer(f)
	defer server.Close()
	base, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &updates.Client{Root: updates.DevelopmentRootPublicKey, Platform: "windows", HTTP: &http.Client{Transport: localTransport{base: base, token: f.token}}}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	offer, err := client.Check(ctx, "1.0.10", "x64")
	if err != nil || offer == nil {
		t.Fatal("fixture's separate metadata GETs do not verify together", err)
	}
	manifest, err := updates.VerifyBundle(updates.DevelopmentRootPublicKey, *offer.Bundle, "1.0.10", "x64", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var downloaded bytes.Buffer
	if err := client.Download(ctx, manifest, &downloaded, nil); err != nil || !bytes.Equal(downloaded.Bytes(), payload) {
		t.Fatal("fixture installer mismatch", err)
	}
	for _, mode := range []string{"bad-signature", "expired", "wrong-arch", "downgrade", "tampered-installer"} {
		f.mu.Lock()
		f.mode = mode
		f.mu.Unlock()
		offer, err := client.Check(ctx, "1.0.10", "x64")
		switch mode {
		case "downgrade":
			if err != nil || offer != nil {
				t.Fatal("downgrade fixture was not refused", err)
			}
		case "tampered-installer":
			if err != nil || offer == nil {
				t.Fatal(err)
			}
			downloaded.Reset()
			if err := client.Download(ctx, manifest, &downloaded, nil); !errors.Is(err, updates.ErrInstallerIntegrity) {
				t.Fatal("tampered installer was not refused", err)
			}
		default:
			if !errors.Is(err, updates.ErrSignatureCheck) || offer != nil {
				t.Fatal("invalid metadata was not refused", mode, err)
			}
		}
	}
}
