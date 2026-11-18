// Command netswitchctl manages services, enrollment, recovery and signed updates.
package main

import (
	"fmt"
	"os"

	"github.com/kekawia/net-switch/internal/lifecycle"
	// Signing and detached update application use Go's registered BLAKE2b hashes.
	_ "golang.org/x/crypto/blake2b"
)

func main() {
	if err := lifecycle.Ctl(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
