//go:build linux && (amd64 || arm64)

package ownerbpf

// burstBarrier orders the TUN read's kernel loads before unrelated program
// statistics reads in the subsequent syscalls. The assembly function is not
// inlined; it also prevents compiler motion across this externally visible call.
func burstBarrier()
