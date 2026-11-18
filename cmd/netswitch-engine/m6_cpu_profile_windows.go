//go:build m6profile && windows

package main

import (
	"os"
	"path/filepath"
	"runtime/pprof"
	"time"

	"github.com/kekawia/net-switch/internal/lifecycle"
)

// This isolated benchmark branch builds this file only into its disposable
// hosted diagnostic installer. The regular product and release have no hook.
func init() {
	if len(os.Args) < 3 || os.Args[1] != "native-child" || os.Args[2] != lifecycle.DefaultData() {
		return
	}
	go func() {
		dir := os.Args[2]
		start := filepath.Join(dir, "m6-cpu.start")
		for {
			if _, err := os.Stat(start); err == nil {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
		if lifecycle.CheckDirectory(dir) != nil {
			return
		}
		f, err := os.OpenFile(filepath.Join(dir, "m6-engine.pprof"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return
		}
		if err := pprof.StartCPUProfile(f); err != nil {
			f.Close()
			return
		}
		ready := filepath.Join(dir, "m6-cpu.ready")
		if err := os.WriteFile(ready, []byte("ready"), 0600); err != nil {
			pprof.StopCPUProfile()
			f.Close()
			return
		}
		end := time.Now().Add(110 * time.Second)
		for time.Now().Before(end) {
			if _, err := os.Stat(start); os.IsNotExist(err) {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		pprof.StopCPUProfile()
		if f.Close() == nil {
			os.Rename(ready, filepath.Join(dir, "m6-cpu.done"))
		}
	}()
}
