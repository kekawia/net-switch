//go:build windows

package secrets

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	dpapiScheme = "dpapi-v1"

	// dpapiProtectFlags forbids UI prompts (Session 0 service safety) and
	// intentionally omits CRYPTPROTECT_LOCAL_MACHINE so unprivileged local
	// accounts cannot decrypt secrets sealed by the LocalSystem service.
	dpapiProtectFlags uint32 = windows.CRYPTPROTECT_UI_FORBIDDEN
)

type defaultSealer struct{}

func (defaultSealer) Seal(ref string, plaintext []byte) (string, []byte, error) {
	if len(plaintext) == 0 {
		return "", nil, errors.New("empty plaintext")
	}
	entropy := buildEntropy(ref)
	inBlob := windows.DataBlob{
		Size: uint32(len(plaintext)),
		Data: &plaintext[0],
	}
	entBlob := windows.DataBlob{
		Size: uint32(len(entropy)),
		Data: &entropy[0],
	}
	var outBlob windows.DataBlob
	err := windows.CryptProtectData(&inBlob, nil, &entBlob, 0, nil, dpapiProtectFlags, &outBlob)
	runtime.KeepAlive(plaintext)
	runtime.KeepAlive(entropy)
	if err != nil {
		return "", nil, fmt.Errorf("CryptProtectData: %w", err)
	}
	defer freeDataBlob(&outBlob, false)

	out := make([]byte, outBlob.Size)
	if outBlob.Size > 0 && outBlob.Data != nil {
		copy(out, unsafe.Slice(outBlob.Data, outBlob.Size))
	}
	return dpapiScheme, out, nil
}

func (defaultSealer) Open(ref, scheme string, sealed []byte) ([]byte, error) {
	if scheme != dpapiScheme {
		return nil, fmt.Errorf("unexpected secret scheme %q (want %q)", scheme, dpapiScheme)
	}
	if len(sealed) == 0 {
		return nil, errors.New("empty ciphertext")
	}
	entropy := buildEntropy(ref)
	inBlob := windows.DataBlob{
		Size: uint32(len(sealed)),
		Data: &sealed[0],
	}
	entBlob := windows.DataBlob{
		Size: uint32(len(entropy)),
		Data: &entropy[0],
	}
	var outBlob windows.DataBlob
	err := windows.CryptUnprotectData(&inBlob, nil, &entBlob, 0, nil, dpapiProtectFlags, &outBlob)
	runtime.KeepAlive(sealed)
	runtime.KeepAlive(entropy)
	if err != nil {
		return nil, fmt.Errorf("CryptUnprotectData: %w", err)
	}
	defer freeDataBlob(&outBlob, true)

	out := make([]byte, outBlob.Size)
	if outBlob.Size > 0 && outBlob.Data != nil {
		copy(out, unsafe.Slice(outBlob.Data, outBlob.Size))
	}
	return out, nil
}

func buildEntropy(ref string) []byte {
	const prefix = "netswitch.proxy.secrets.v1:"
	b := make([]byte, len(prefix)+len(ref))
	copy(b, prefix)
	copy(b[len(prefix):], ref)
	return b
}

func freeDataBlob(blob *windows.DataBlob, wipe bool) {
	if blob == nil || blob.Data == nil {
		return
	}
	if wipe && blob.Size > 0 {
		zeroBytes(unsafe.Slice(blob.Data, blob.Size))
	}
	_, _ = windows.LocalFree(windows.Handle(unsafe.Pointer(blob.Data)))
	blob.Data = nil
	blob.Size = 0
}

func enforceOwnerOnlyPerm(string) error { return nil }
