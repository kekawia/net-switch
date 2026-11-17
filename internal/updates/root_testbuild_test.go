//go:build lifecycle_test

package updates

import "testing"

func TestInstrumentedRootRemainsAFixtureAndCannotShip(t *testing.T) {
	if RootPublicKey != DevelopmentRootPublicKey {
		t.Fatal("instrumented build depends on the production root")
	}
	if err := CheckProductionRoot(); err == nil {
		t.Fatal("instrumented update binary passed the release gate")
	}
}
