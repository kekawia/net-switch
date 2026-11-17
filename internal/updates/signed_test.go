package updates

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/blake2b"
)

func TestMinisignBothSignaturesAndLegacyDomainSeparation(t *testing.T) {
	public, secret, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	message := []byte(`{"version":"1.1.0"}`)
	sig, err := SignMinisign(secret, message, "timestamp:123\tfile:manifest.json\thashed")
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyMinisign(public, message, sig); err != nil {
		t.Fatal(err)
	}
	if raw, err := PublicKeyFromSecret(secret); err != nil || !strings.Contains(public, raw) {
		t.Fatal("public/secret key disagreement", err)
	}
	lines := strings.Split(strings.TrimSpace(string(sig)), "\n")
	legacy, _ := base64.StdEncoding.DecodeString(lines[1])
	copy(legacy[:2], "Ed")
	legacyLines := append([]string{}, lines...)
	legacyLines[1] = base64.StdEncoding.EncodeToString(legacy)
	hash := blake2b.Sum512(message)
	for _, test := range []struct {
		name               string
		message, signature []byte
	}{
		{"wrong_file", []byte("changed"), sig},
		{"trusted_comment", message, []byte(strings.Replace(string(sig), "timestamp:123", "timestamp:124", 1))},
		{"missing_global_signature", message, []byte(strings.Join(lines[:3], "\n"))},
		{"trailing_content", message, append(append([]byte{}, sig...), []byte("extra\n")...)},
		{"legacy_hash_substitution", hash[:], []byte(strings.Join(legacyLines, "\n"))},
		{"truncated", message, []byte("untrusted comment: x\nAA==\ntrusted comment: x\nAA==\n")},
	} {
		t.Run(test.name, func(t *testing.T) {
			if VerifyMinisign(public, test.message, test.signature) == nil {
				t.Fatal("invalid signature accepted")
			}
		})
	}
	other, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if VerifyMinisign(other, message, sig) == nil {
		t.Fatal("wrong key accepted")
	}
	secretLines, _ := minisignLines(secret, 2)
	raw, _ := base64.StdEncoding.DecodeString(secretLines[1])
	raw[70] ^= 1
	secretLines[1] = base64.StdEncoding.EncodeToString(raw)
	if _, err := SignMinisign(strings.Join(secretLines, "\n"), message, "test"); err == nil {
		t.Fatal("corrupt private key accepted")
	}
}

func TestDevelopmentRootIsExplicitAndCannotShip(t *testing.T) {
	seed := sha256.Sum256([]byte("Net Switch development root, never a release trust anchor"))
	key := signingKey{private: ed25519.NewKeyFromSeed(seed[:])}
	copy(key.id[:], seed[:8])
	if key.publicText() != DevelopmentRootPublicKey {
		t.Fatal("development root fixture drifted")
	}
	if RootPublicKey == DevelopmentRootPublicKey && CheckProductionRoot() == nil {
		t.Fatal("development root passed release gate")
	}
}

func TestOfficialUnencryptedKeyWithoutChecksumStillChecksItsPublicHalf(t *testing.T) {
	public, secret, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	lines, err := minisignLines(secret, 2)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(lines[1])
	if err != nil {
		t.Fatal(err)
	}
	clear(raw[126:])
	keyText := func() string { return lines[0] + "\n" + base64.StdEncoding.EncodeToString(raw) + "\n" }
	sig, err := SignMinisign(keyText(), []byte("official unencrypted format"), "fixture")
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyMinisign(public, []byte("official unencrypted format"), sig); err != nil {
		t.Fatal(err)
	}
	raw[70] ^= 1
	if _, err := SignMinisign(keyText(), nil, "fixture"); err == nil {
		t.Fatal("unchecked private seed/public key mismatch")
	}
	raw[70] ^= 1
	raw[126] = 1
	if _, err := SignMinisign(keyText(), nil, "fixture"); err == nil {
		t.Fatal("invalid nonzero checksum accepted")
	}
}

func TestProductionRootRefusesDevelopmentKeyWithAnyLabelOrID(t *testing.T) {
	key, err := publicKeyBytes(DevelopmentRootPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	key[2] ^= 1
	for _, text := range []string{DevelopmentRootPublicKey, untrustedPrefix + "another label\n" + DevelopmentRootPublicKey + "\n", base64.StdEncoding.EncodeToString(key)} {
		if err := checkProductionRoot(text); err == nil {
			t.Fatal("development private key accepted as production root")
		}
	}
	public, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := checkProductionRoot(public); err != nil {
		t.Fatal("independent root refused", err)
	}
}

type signingFixture struct {
	root, rootSecret, releaseSecret string
	now                             time.Time
	key                             ReleaseKeyStatement
	manifest                        Manifest
	installer                       []byte
}

func newSigningFixture(t *testing.T) signingFixture {
	t.Helper()
	root, rootSecret, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	release, releaseSecret, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	installer := []byte("a signed test installer, never executed")
	digest := sha256.Sum256(installer)
	return signingFixture{root: root, rootSecret: rootSecret, releaseSecret: releaseSecret, now: now, installer: installer,
		key:      ReleaseKeyStatement{Purpose: "netswitch-release-signing", PublicKey: release, IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(48 * time.Hour)},
		manifest: Manifest{Product: "net-switch", Architecture: "x64", Version: "1.1.0", URL: InstallerURL("1.1.0", "x64"), SHA256: hex.EncodeToString(digest[:]), Size: int64(len(installer)), IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)},
	}
}

func (f signingFixture) bundle(t *testing.T) Bundle {
	t.Helper()
	key, err := json.Marshal(f.key)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := json.Marshal(f.manifest)
	if err != nil {
		t.Fatal(err)
	}
	keySig, err := SignMinisign(f.rootSecret, key, "Net Switch release key")
	if err != nil {
		t.Fatal(err)
	}
	manifestSig, err := SignMinisign(f.releaseSecret, manifest, "Net Switch x64 update")
	if err != nil {
		t.Fatal(err)
	}
	return Bundle{Key: key, KeySignature: keySig, Manifest: manifest, ManifestSignature: manifestSig}
}

func TestSignedChainRejectsAuthenticatedWrongContracts(t *testing.T) {
	fixture := newSigningFixture(t)
	manifest, err := VerifyBundle(fixture.root, fixture.bundle(t), "1.0.0", "x64", fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := manifest.VerifyInstaller(bytes.NewReader(fixture.installer)); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []struct {
		name   string
		change func(*signingFixture)
	}{
		{"key_purpose", func(f *signingFixture) { f.key.Purpose = "another-product" }},
		{"key_expired", func(f *signingFixture) { f.key.ExpiresAt = f.now }},
		{"key_future", func(f *signingFixture) { f.key.IssuedAt = f.now.Add(time.Minute) }},
		{"product", func(f *signingFixture) { f.manifest.Product = "another-product" }},
		{"architecture", func(f *signingFixture) { f.manifest.Architecture = "arm64" }},
		{"same_version", func(f *signingFixture) { f.manifest.Version = "1.0.0" }},
		{"downgrade", func(f *signingFixture) { f.manifest.Version = "0.9.9" }},
		{"noncanonical", func(f *signingFixture) { f.manifest.Version = "01.1.0" }},
		{"integer_overflow", func(f *signingFixture) { f.manifest.Version = "9007199254740993.0.0" }},
		{"expired", func(f *signingFixture) { f.manifest.ExpiresAt = f.now }},
		{"outlives_key", func(f *signingFixture) { f.manifest.ExpiresAt = f.key.ExpiresAt.Add(time.Hour) }},
		{"wrong_host", func(f *signingFixture) { f.manifest.URL = "https://example.com/setup.exe" }},
		{"wrong_asset_version", func(f *signingFixture) { f.manifest.URL = InstallerURL("1.0.0", "x64") }},
		{"invalid_hash", func(f *signingFixture) { f.manifest.SHA256 = "bad" }},
		{"oversized", func(f *signingFixture) { f.manifest.Size = MaxInstallerSize + 1 }},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			f := fixture
			mutate.change(&f)
			if _, err := VerifyBundle(f.root, f.bundle(t), "1.0.0", "x64", f.now); err == nil {
				t.Fatal("invalid signed contract accepted")
			}
		})
	}
	for _, data := range [][]byte{fixture.installer[:3], append(append([]byte{}, fixture.installer...), 'x'), bytes.Repeat([]byte{'x'}, len(fixture.installer))} {
		if manifest.VerifyInstaller(bytes.NewReader(data)) == nil {
			t.Fatal("wrong installer bytes accepted")
		}
	}
	bundle := fixture.bundle(t)
	bundle.Key[len(bundle.Key)-2] ^= 1
	if _, err := VerifyBundle(fixture.root, bundle, "1.0.0", "x64", fixture.now); err == nil {
		t.Fatal("changed root statement accepted")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return fn(r) }

func TestClientUsesNumericRepositorySignedAssetsAndBoundedDownload(t *testing.T) {
	f := newSigningFixture(t)
	b := f.bundle(t)
	files := map[string][]byte{
		"netswitch-release-key.json": b.Key, "netswitch-release-key.json.minisig": b.KeySignature,
		"update-manifest-x64.json": b.Manifest, "update-manifest-x64.json.minisig": b.ManifestSignature,
		"NetSwitch-Setup-1.1.0-x64.exe": f.installer,
	}
	var assets []any
	responses := map[string][]byte{}
	for name, data := range files {
		url := ReleaseBase + "download/v1.1.0/" + name
		assets = append(assets, map[string]any{"name": name, "browser_download_url": url})
		responses[url] = data
	}
	responses[LatestReleaseAPIURL], _ = json.Marshal(map[string]any{"tag_name": "v1.1.0", "html_url": ReleaseBase + "tag/v1.1.0", "assets": assets})
	var requests []string
	client := &Client{Root: f.root, Platform: "windows", Now: func() time.Time { return f.now }, HTTP: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		requests = append(requests, r.URL.String())
		body, ok := responses[r.URL.String()]
		if !ok {
			return nil, errors.New("unexpected request: " + r.URL.String())
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(body)), Header: make(http.Header), Request: r}, nil
	})}}
	offer, err := client.Check(context.Background(), "1.0.0", "x64")
	if err != nil || offer == nil || offer.Bundle == nil {
		t.Fatal("no verified offer", err)
	}
	if len(requests) != 5 || requests[0] != LatestReleaseAPIURL {
		t.Fatal("wrong discovery requests", requests)
	}
	manifest, err := VerifyBundle(f.root, *offer.Bundle, "1.0.0", "x64", f.now)
	if err != nil {
		t.Fatal(err)
	}
	var downloaded bytes.Buffer
	var progress int64
	if err := client.Download(context.Background(), manifest, &downloaded, func(n int64) { progress = n }); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(downloaded.Bytes(), f.installer) || progress != manifest.Size {
		t.Fatal("download or progress differs")
	}
	responses[manifest.URL] = append(append([]byte{}, f.installer...), 'x')
	if err := client.Download(context.Background(), manifest, io.Discard, nil); !errors.Is(err, ErrInstallerIntegrity) {
		t.Fatal("extra bytes accepted", err)
	}
	requests = nil
	client.Platform = "linux"
	offer, err = client.Check(context.Background(), "1.0.0", "arm64")
	if err != nil || offer == nil || !offer.PackageManager || offer.Installer != "" || len(requests) != 1 {
		t.Fatal("Linux fetched or offered an installer", offer, requests, err)
	}
	for _, target := range []string{"http://github.com/x", "https://example.com/x", "https://github.com:444/x", "https://user@github.com/x"} {
		request, _ := http.NewRequest(http.MethodGet, target, nil)
		if client.httpClient().CheckRedirect(request, nil) == nil {
			t.Fatal("unsafe redirect accepted", target)
		}
	}
}
