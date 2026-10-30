package ownerproof

import "testing"

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
}
