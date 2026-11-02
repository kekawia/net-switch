//go:build linux && ownerbpfproof && (amd64 || arm64)

package ownerbpf

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

func verifiedFloor58Profile() bool {
	if os.Getenv("NS_OWNERBPF_FLOOR58") != "1" {
		return false
	}
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return false
	}
	if unix.ByteSliceToString(uts.Release[:]) != "5.8.0" {
		return false
	}
	wantSHA, ok := Floor58ResolvedConfigSHA256(runtime.GOARCH)
	if !ok {
		return false
	}
	gzBytes, err := os.ReadFile("/proc/config.gz")
	if err != nil {
		return false
	}
	zr, err := gzip.NewReader(bytes.NewReader(gzBytes))
	if err != nil {
		return false
	}
	cfgBytes, err := io.ReadAll(zr)
	_ = zr.Close()
	if err != nil {
		return false
	}
	sum := sha256.Sum256(cfgBytes)
	return hex.EncodeToString(sum[:]) == wantSHA
}
