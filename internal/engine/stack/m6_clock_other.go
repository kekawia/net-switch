//go:build !windows

package stack

import "time"

func m6Now() int64 { return time.Now().UnixNano() }
