//go:build !windows

package lifecycle

// raiseServicePriority is Windows-only: the Linux units set Nice=-5 before
// exec (internal/service), so the processes already start raised.
func raiseServicePriority() (string, error) { return "", nil }
