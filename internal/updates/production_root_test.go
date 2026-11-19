//go:build !lifecycle_test

package updates

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestProductionRootVerifiesCommittedReleaseKey(t *testing.T) {
	if err := CheckProductionRoot(); err != nil {
		t.Fatalf("CheckProductionRoot: %v", err)
	}
	statementPath := filepath.Join("..", "..", "packaging", "updates", "netswitch-release-key.json")
	raw, err := os.ReadFile(statementPath)
	if err != nil {
		t.Fatalf("read release key statement: %v", err)
	}
	sig, err := os.ReadFile(statementPath + ".minisig")
	if err != nil {
		t.Fatalf("read release key signature: %v", err)
	}
	key, err := VerifyReleaseKey(RootPublicKey, raw, sig, time.Now().UTC())
	if err != nil {
		t.Fatalf("VerifyReleaseKey failed against production RootPublicKey: %v", err)
	}
	if key.Purpose != "netswitch-release-signing" {
		t.Fatalf("unexpected release key purpose %q", key.Purpose)
	}
}
