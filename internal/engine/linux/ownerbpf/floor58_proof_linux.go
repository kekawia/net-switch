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

const (
	lockedFloor58ConfigSHA256AMD64 = "42309a5b01aef7aec5a856561eef8c049dd247501b3edaad746382413aff9252"
	lockedFloor58ConfigSHA256ARM64 = "8f2fd8ae8b40b3875083d636f8308d5b16e4b43c3e8abf1170780e6ea27e2a0b"
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
	wantSHA := ""
	switch runtime.GOARCH {
	case "amd64":
		wantSHA = lockedFloor58ConfigSHA256AMD64
	case "arm64":
		wantSHA = lockedFloor58ConfigSHA256ARM64
	default:
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
