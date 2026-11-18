//go:build windows

package tcp

import "github.com/kekawia/net-switch/internal/winclock"

func m6NowUS() int64 { return winclock.Now().Microseconds() }
