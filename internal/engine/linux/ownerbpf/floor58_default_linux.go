//go:build linux && !ownerbpfproof && (amd64 || arm64)

package ownerbpf

func verifiedFloor58Profile() bool {
	return false
}
