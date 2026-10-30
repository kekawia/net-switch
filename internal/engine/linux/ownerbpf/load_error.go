package ownerbpf

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
)

// Keep the typed cause and print the full log even through Error().
// An external log viewer cannot recover lines we never printed.
func loadError(stage string, err error) error {
	var verifier *ebpf.VerifierError
	if errors.As(err, &verifier) {
		return fmt.Errorf("%s: %w\nFULL VERIFIER LOG:\n%+v", stage, err, verifier)
	}
	return fmt.Errorf("%s: %w", stage, err)
}
