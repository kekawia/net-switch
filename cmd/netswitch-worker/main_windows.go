//go:build windows

package main

import (
	"fmt"
	"os"
	"runtime"
	"runtime/debug"

	"github.com/kekawia/net-switch/internal/buildinfo"
	"github.com/kekawia/net-switch/internal/platform/windows/observer"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "worker" {
		if os.Getenv("GOMAXPROCS") == "" {
			runtime.GOMAXPROCS(1)
		}
		if os.Getenv("GOGC") == "" {
			debug.SetGCPercent(25)
		}
		if os.Getenv("GOMEMLIMIT") == "" {
			debug.SetMemoryLimit(8 << 20)
		}
		os.Exit(observer.RunStream(os.Args[2:]))
	}
	if len(os.Args) == 2 && os.Args[1] == "version" {
		fmt.Println("netswitch-worker", buildinfo.String())
		return
	}
	fmt.Fprintln(os.Stderr, "expected a worker mode")
	os.Exit(2)
}
