//go:build lifecycle_test && !(linux && (amd64 || arm64))

package lifecycle

import "errors"

func nativeEBPFCapabilityEvidence(string) (any, error) {
	return nil, errors.New("Linux eBPF capability proof requires linux amd64 or arm64")
}
