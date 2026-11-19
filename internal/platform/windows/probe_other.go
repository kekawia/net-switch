//go:build !windows

package winplatform

import (
	"fmt"
	"os"
)

func runProbeOptions(probeOptions) int {
	fmt.Fprintln(os.Stderr, "probe: not supported on this system yet")
	return 1
}
