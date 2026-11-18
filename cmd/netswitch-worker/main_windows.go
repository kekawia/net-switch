//go:build windows

package main

import (
	"fmt"
	"os"

	"github.com/kekawia/net-switch/internal/buildinfo"
	win "github.com/kekawia/net-switch/internal/platform/windows"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "worker" {
		os.Exit(win.RunStream(os.Args[2:]))
	}
	if len(os.Args) == 2 && os.Args[1] == "version" {
		fmt.Println("netswitch-worker", buildinfo.String())
		return
	}
	fmt.Fprintln(os.Stderr, "expected a worker mode")
	os.Exit(2)
}
