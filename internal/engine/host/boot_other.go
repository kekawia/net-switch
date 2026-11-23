//go:build !linux && !windows

package host

func CurrentBootID() (string, error) { return "", nil }
