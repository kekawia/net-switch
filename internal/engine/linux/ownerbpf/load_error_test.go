package ownerbpf

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

func TestLoadErrorRetainsEveryVerifierLine(t *testing.T) {
	cause := errors.New("bad relocation")
	ve := &ebpf.VerifierError{Cause: cause}
	for i := range 40 {
		ve.Log = append(ve.Log, fmt.Sprintf("unique verifier line %02d", i))
	}
	err := loadError("bridge verifier/load", fmt.Errorf("program perf_consume: %w", ve))
	for _, line := range ve.Log {
		if !strings.Contains(err.Error(), line) {
			t.Fatalf("lost verifier line %q", line)
		}
	}
	var recovered *ebpf.VerifierError
	if !errors.Is(err, cause) || !errors.As(err, &recovered) || recovered != ve {
		t.Fatal("diagnostic expansion lost typed error/cause")
	}
}
