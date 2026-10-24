//go:build !control_compat

package main

import (
	"errors"
	"fmt"
	"os"
	"runtime"

	assets "github.com/AyoubAchour/net-switch"
	"github.com/AyoubAchour/net-switch/internal/buildinfo"
)

// compatibilityLauncher reports whether this build carries the 0.3.x desktop
// launcher. The product build does not.
const compatibilityLauncher = false

const productUsage = "usage: netswitch service <command> | netswitch worker <mode> | netswitch -version\n" +
	"Control runs as the installed Net Switch service, started by the service manager; install it with netswitchctl"

// run is what a product netswitch does when started as neither the service nor
// a worker: it explains itself and exits without starting anything. Control
// runs as the installed service (spec §2), and no path in this build can start
// sing-box or any other engine; that launcher exists only in the
// control_compat build the parity workflow uses.
func run() error {
	if len(os.Args) == 2 && (os.Args[1] == "-version" || os.Args[1] == "--version") {
		fmt.Printf("Net Switch control %s (build %s; %s/%s; %s)\n", assets.AppVersion(), buildinfo.String(), runtime.GOOS, runtime.GOARCH, runtime.Version())
		return nil
	}
	return errors.New(productUsage)
}
