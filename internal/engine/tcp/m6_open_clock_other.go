//go:build !windows

package tcp

import "time"

func m6NowUS() int64 { return time.Now().UnixMicro() }
