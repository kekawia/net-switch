package ownerproof

import (
	"os"
	"strings"
	"testing"
)

func TestGuestLockAndKernelConfigs(t *testing.T) {
	lock, err := LoadGuestLock()
	if err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"amd64", "arm64"} {
		objs := lock.Initramfs.BPFObjects[arch]
		if len(objs) != 3 {
			t.Fatalf("%s expected 3 pinned BPF object digests, got %d", arch, len(objs))
		}
		for name, digest := range objs {
			if len(digest) != 64 {
				t.Fatalf("%s %s invalid sha256 %q", arch, name, digest)
			}
		}
	}
	scriptBytes, err := os.ReadFile("../../../scripts/build-owner-floor-guest.mjs")
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateBuildScriptAdjustments(string(scriptBytes), lock); err != nil {
		t.Fatal(err)
	}
	mutatedScript := strings.Replace(string(scriptBytes), `sed -i "s/-Werror//g"`, `sed -i "s/-Wall//g"`, 1)
	if err := ValidateBuildScriptAdjustments(mutatedScript, lock); err == nil {
		t.Fatal("mutated build script adjustment unexpectedly passed lock validation")
	}
	extraLock := *lock
	extraLock.Kernel.BuildAdjustments = append([]string(nil), lock.Kernel.BuildAdjustments...)
	extraLock.Kernel.BuildAdjustments = append(extraLock.Kernel.BuildAdjustments, "sed -i 's/foo/bar/g' Makefile")
	if err := ValidateBuildScriptAdjustments(string(scriptBytes), &extraLock); err == nil {
		t.Fatal("mismatched buildAdjustments count unexpectedly passed script validation")
	}
}
