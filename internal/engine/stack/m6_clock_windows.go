//go:build windows

package stack

import "github.com/kekawia/net-switch/internal/winclock"

func m6Now() int64 { return int64(winclock.Now()) }
