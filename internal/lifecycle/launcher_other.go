//go:build !windows

package lifecycle

func MaybeDelegateVersionedDesktop([]string) (bool, int, error) {
	return false, 0, nil
}
