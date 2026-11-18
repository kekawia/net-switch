package updates

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

const untrustedPrefix = "untrusted comment: "
const trustedPrefix = "trusted comment: "

type signingKey struct {
	id      [8]byte
	private ed25519.PrivateKey
}

// Only the Control and signing entry points register BLAKE2b. Using Go's
// standard hash registry keeps that implementation out of the routing engine,
// whose shared lifecycle/version code also imports this package.
func minisignHash(algorithm crypto.Hash, message []byte) ([]byte, error) {
	if !algorithm.Available() {
		return nil, errors.New("Minisign hashing is unavailable in this executable")
	}
	h := algorithm.New()
	_, _ = h.Write(message)
	return h.Sum(nil), nil
}

func minisignLines(text string, count int) ([]string, error) {
	if len(text) > 16384 || strings.ContainsRune(text, 0) {
		return nil, errors.New("invalid Minisign document size or encoding")
	}
	text = strings.ReplaceAll(text, "\r\n", "\n")
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if len(lines) != count || !strings.HasPrefix(lines[0], untrustedPrefix) || len(lines[0]) > 1024 {
		return nil, errors.New("invalid Minisign document structure")
	}
	return lines, nil
}

func publicKeyBytes(text string) ([]byte, error) {
	if strings.HasPrefix(text, untrustedPrefix) {
		lines, err := minisignLines(text, 2)
		if err != nil {
			return nil, err
		}
		text = lines[1]
	}
	b, err := base64.StdEncoding.Strict().DecodeString(text)
	if err != nil || len(b) != 42 || !bytes.Equal(b[:2], []byte("Ed")) {
		return nil, errors.New("invalid Minisign public key")
	}
	return b, nil
}

// VerifyMinisign accepts only Minisign's ED format: Ed25519 over BLAKE2b-512,
// followed by the signature of the signature bytes and the trusted comment.
// This is deliberately not RFC 8032 Ed25519ph and never accepts legacy Ed.
func VerifyMinisign(public string, message, signature []byte) error {
	key, err := publicKeyBytes(public)
	if err != nil {
		return err
	}
	lines, err := minisignLines(string(signature), 4)
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(lines[1])
	if err != nil || len(sig) != 74 || !bytes.Equal(sig[:2], []byte("ED")) {
		return errors.New("a prehashed Minisign ED signature is required")
	}
	if !bytes.Equal(key[2:10], sig[2:10]) {
		return errors.New("Minisign key ID does not match")
	}
	if !strings.HasPrefix(lines[2], trustedPrefix) || len(lines[2]) > 8192 {
		return errors.New("invalid Minisign trusted comment")
	}
	global, err := base64.StdEncoding.Strict().DecodeString(lines[3])
	if err != nil || len(global) != ed25519.SignatureSize {
		return errors.New("invalid Minisign comment signature")
	}
	hash, err := minisignHash(crypto.BLAKE2b_512, message)
	if err != nil {
		return err
	}
	if !ed25519.Verify(key[10:], hash, sig[10:]) {
		return errors.New("Minisign file signature did not verify")
	}
	comment := append(append([]byte{}, sig[10:]...), []byte(strings.TrimPrefix(lines[2], trustedPrefix))...)
	if !ed25519.Verify(key[10:], comment, global) {
		return errors.New("Minisign trusted comment did not verify")
	}
	return nil
}

func parseSigningKey(text string) (signingKey, error) {
	var key signingKey
	lines, err := minisignLines(text, 2)
	if err != nil {
		return key, err
	}
	b, err := base64.StdEncoding.Strict().DecodeString(lines[1])
	if err != nil || len(b) != 158 || string(b[:2]) != "Ed" || string(b[4:6]) != "B2" {
		return key, errors.New("invalid Minisign secret key")
	}
	if b[2] != 0 || b[3] != 0 {
		return key, errors.New("use an unencrypted Minisign key (-W) kept in protected offline storage")
	}
	copy(key.id[:], b[54:62])
	key.private = append(ed25519.PrivateKey{}, b[62:126]...)
	expected := ed25519.NewKeyFromSeed(key.private[:ed25519.SeedSize])
	checksum, err := minisignHash(crypto.BLAKE2b_256, append(append([]byte("Ed"), key.id[:]...), key.private...))
	if err != nil {
		return signingKey{}, err
	}
	// Official Minisign -G -W leaves the checksum zeroed: it computes that
	// field only when encrypting a key. Converted or our own unencrypted keys
	// may retain a checksum. Always verify seed/public consistency, and check
	// any nonzero checksum rather than accepting arbitrary checksum bytes.
	checksumPresent := !bytes.Equal(b[126:], make([]byte, 32))
	if !bytes.Equal(expected, key.private) || (checksumPresent && !bytes.Equal(checksum, b[126:])) {
		return signingKey{}, errors.New("Minisign secret key checksum or public key does not match")
	}
	return key, nil
}

func (key signingKey) publicText() string {
	b := append(append([]byte("Ed"), key.id[:]...), key.private[32:]...)
	return base64.StdEncoding.EncodeToString(b)
}

// GenerateKeyPair returns the standard public and unencrypted secret key files.
// The caller must create the secret file with owner-only access, without replacing it.
func GenerateKeyPair() (public, secret string, err error) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	key := signingKey{private: private}
	if _, err := rand.Read(key.id[:]); err != nil {
		return "", "", err
	}
	secret, err = key.secretText()
	if err != nil {
		return "", "", err
	}
	return untrustedPrefix + "Net Switch public key\n" + key.publicText() + "\n", secret, nil
}

func (key signingKey) secretText() (string, error) {
	b := make([]byte, 158)
	copy(b[:2], "Ed")
	copy(b[4:6], "B2")
	copy(b[54:62], key.id[:])
	copy(b[62:126], key.private)
	checksum, err := minisignHash(crypto.BLAKE2b_256, append(append([]byte("Ed"), key.id[:]...), key.private...))
	if err != nil {
		return "", err
	}
	copy(b[126:], checksum)
	return untrustedPrefix + "Net Switch unencrypted secret key\n" + base64.StdEncoding.EncodeToString(b) + "\n", nil
}

func PublicKeyFromSecret(secret string) (string, error) {
	key, err := parseSigningKey(secret)
	if err != nil {
		return "", err
	}
	return key.publicText(), nil
}

func SignMinisign(secret string, message []byte, comment string) ([]byte, error) {
	key, err := parseSigningKey(secret)
	if err != nil {
		return nil, err
	}
	if comment == "" || len(comment)+len(trustedPrefix) > 8192 || strings.ContainsAny(comment, "\r\n\x00") {
		return nil, errors.New("invalid signing comment")
	}
	hash, err := minisignHash(crypto.BLAKE2b_512, message)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(key.private, hash)
	global := ed25519.Sign(key.private, append(append([]byte{}, sig...), []byte(comment)...))
	record := append(append([]byte("ED"), key.id[:]...), sig...)
	return []byte(fmt.Sprintf("%sNet Switch signature\n%s\n%s%s\n%s\n", untrustedPrefix,
		base64.StdEncoding.EncodeToString(record), trustedPrefix, comment, base64.StdEncoding.EncodeToString(global))), nil
}
