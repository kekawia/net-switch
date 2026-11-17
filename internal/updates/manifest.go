package updates

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

const MaxInstallerSize int64 = 512 << 20
const MaxMetadataSize int64 = 64 << 10

type ReleaseKeyStatement struct {
	Purpose   string    `json:"purpose"`
	PublicKey string    `json:"publicKey"`
	IssuedAt  time.Time `json:"issuedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type Manifest struct {
	Product      string    `json:"product"`
	Architecture string    `json:"architecture"`
	Version      string    `json:"version"`
	URL          string    `json:"url"`
	SHA256       string    `json:"sha256"`
	Size         int64     `json:"size"`
	IssuedAt     time.Time `json:"issuedAt"`
	ExpiresAt    time.Time `json:"expiresAt"`
}

// Bundle retains the exact signed bytes. Re-encoding JSON would change them.
type Bundle struct {
	Key               []byte `json:"key"`
	KeySignature      []byte `json:"keySignature"`
	Manifest          []byte `json:"manifest"`
	ManifestSignature []byte `json:"manifestSignature"`
}

func CanonicalVersion(v string) bool {
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if part == "" || len(part) > 10 || (len(part) > 1 && part[0] == '0') {
			return false
		}
		for _, c := range part {
			if c < '0' || c > '9' {
				return false
			}
		}
		if _, err := strconv.ParseUint(part, 10, 32); err != nil {
			return false
		}
	}
	return true
}

func InstallerURL(version, architecture string) string {
	return ReleaseBase + "download/v" + version + "/NetSwitch-Setup-" + version + "-" + architecture + ".exe"
}

func decodeMetadata(raw []byte, out any) error {
	if len(raw) == 0 || int64(len(raw)) > MaxMetadataSize {
		return errors.New("update metadata exceeds its size limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(out); err != nil {
		return fmt.Errorf("invalid update metadata: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("update metadata has trailing content")
	}
	return nil
}

func validPeriod(issued, expires, now time.Time) bool {
	return !issued.IsZero() && !issued.After(now) && expires.After(now) && expires.After(issued)
}

func VerifyReleaseKey(root string, data, signature []byte, now time.Time) (ReleaseKeyStatement, error) {
	var key ReleaseKeyStatement
	if err := VerifyMinisign(root, data, signature); err != nil {
		return key, err
	}
	if err := decodeMetadata(data, &key); err != nil {
		return key, err
	}
	if key.Purpose != "netswitch-release-signing" || !validPeriod(key.IssuedAt, key.ExpiresAt, now) {
		return key, errors.New("release signing key has the wrong purpose or is outside its validity period")
	}
	if _, err := publicKeyBytes(key.PublicKey); err != nil {
		return key, err
	}
	return key, nil
}

func VerifyBundle(root string, bundle Bundle, current, architecture string, now time.Time) (Manifest, error) {
	var manifest Manifest
	if architecture != "x64" && architecture != "arm64" {
		return manifest, errors.New("unsupported update architecture")
	}
	key, err := VerifyReleaseKey(root, bundle.Key, bundle.KeySignature, now)
	if err != nil {
		return manifest, err
	}
	if err := VerifyMinisign(key.PublicKey, bundle.Manifest, bundle.ManifestSignature); err != nil {
		return manifest, err
	}
	if err := decodeMetadata(bundle.Manifest, &manifest); err != nil {
		return manifest, err
	}
	if manifest.Product != "net-switch" || manifest.Architecture != architecture {
		return manifest, errors.New("update is for a different product or architecture")
	}
	if !CanonicalVersion(current) || !CanonicalVersion(manifest.Version) || !IsNewer(manifest.Version, current) {
		return manifest, errors.New("update must be newer than the installed version")
	}
	if !validPeriod(manifest.IssuedAt, manifest.ExpiresAt, now) || manifest.ExpiresAt.After(key.ExpiresAt) || manifest.IssuedAt.Before(key.IssuedAt) {
		return manifest, errors.New("update manifest is outside its signing key's validity period")
	}
	if manifest.URL != InstallerURL(manifest.Version, architecture) {
		return manifest, errors.New("update installer URL is not the expected release asset")
	}
	if manifest.Size <= 0 || manifest.Size > MaxInstallerSize {
		return manifest, errors.New("invalid update installer size")
	}
	if sum, err := hex.DecodeString(manifest.SHA256); err != nil || len(sum) != sha256.Size {
		return manifest, errors.New("invalid update installer hash")
	}
	return manifest, nil
}

func (m Manifest) VerifyInstaller(reader io.Reader) error {
	if m.Size <= 0 || m.Size > MaxInstallerSize {
		return errors.New("invalid update installer size")
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(reader, m.Size+1))
	if err != nil {
		return err
	}
	if n != m.Size {
		return fmt.Errorf("installer size mismatch: got %d, expected %d", n, m.Size)
	}
	want, err := hex.DecodeString(m.SHA256)
	if err != nil || !bytes.Equal(h.Sum(nil), want) {
		return errors.New("installer hash does not match the signed manifest")
	}
	return nil
}
