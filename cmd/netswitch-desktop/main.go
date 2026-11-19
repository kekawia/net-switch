package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"syscall"

	"github.com/kekawia/net-switch/internal/buildinfo"
	"github.com/kekawia/net-switch/internal/desktop/host"
	"github.com/kekawia/net-switch/internal/lifecycle"
)

func main() {
	if delegated, code, err := lifecycle.MaybeDelegateVersionedDesktop(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	} else if delegated {
		os.Exit(code)
	}
	background := flag.Bool("background", false, "owner sign-in startup without opening the browser")
	resume := flag.Bool("resume", false, "reconnect after an update without changing routing")
	autostart := flag.String("autostart", "", "on, off or status; configure only this owner's sign-in entry")
	version := flag.Bool("version", false, "print build identity")
	flag.Parse()
	if *version {
		fmt.Println("netswitch-desktop", buildinfo.String())
		return
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if *autostart != "" {
		value, err := lifecycle.ConfigureAutostart(ctx, *autostart)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(value)
		return
	}
	if os.Getenv("GOMAXPROCS") == "" {
		runtime.GOMAXPROCS(2)
	}
	if os.Getenv("GOGC") == "" {
		debug.SetGCPercent(50)
	}
	if os.Getenv("GOMEMLIMIT") == "" {
		debug.SetMemoryLimit(32 << 20)
	}
	lifecycle.SetDesktopUIFactory(host.New)
	run := lifecycle.Desktop
	if *resume {
		run = lifecycle.ResumeDesktop
	}
	if err := run(ctx, !*background); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
