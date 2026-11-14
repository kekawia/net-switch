//go:build !windows

package secrets

import (
	"bytes"
	"errors"
	"fmt"
	"os"
)

const fileScheme = "file-v1"

type defaultSealer struct{}

func (defaultSealer) Seal(_ string, plaintext []byte) (string, []byte, error) {
	if len(plaintext) == 0 {
		return "", nil, errors.New("empty plaintext")
	}
	return fileScheme, bytes.Clone(plaintext), nil
}

func (defaultSealer) Open(_, scheme string, sealed []byte) ([]byte, error) {
	if scheme != fileScheme {
		return nil, fmt.Errorf("unexpected secret scheme %q (want %q)", scheme, fileScheme)
	}
	if len(sealed) == 0 {
		return nil, errors.New("empty secret payload")
	}
	return bytes.Clone(sealed), nil
}

func enforceOwnerOnlyPerm(path string) error {
	return os.Chmod(path, 0600)
}
