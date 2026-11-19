//go:build !windows

package observer

import (
	"fmt"
	"os"
)

func RunStream(args []string) int {
	return run(args)
}

func runOptions(opts options) int {
	fmt.Fprintf(os.Stderr, "%s: not supported on this system yet\n", opts.mode)
	return 1
}
