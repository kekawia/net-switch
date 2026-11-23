//go:build !windows

package diagnostics

import (
	"bufio"
	"os"
	"runtime"
	"strings"
)

// System names the operating system for the report header, such as
// "Ubuntu 24.04.3 LTS, kernel 6.14.0-1012-azure, arm64".
func System() string {
	name := runtime.GOOS
	if f, err := os.Open("/etc/os-release"); err == nil {
		s := bufio.NewScanner(f)
		for s.Scan() {
			if value, ok := strings.CutPrefix(s.Text(), "PRETTY_NAME="); ok {
				name = strings.Trim(value, `"'`)
				break
			}
		}
		f.Close()
	}
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		name += ", kernel " + strings.TrimSpace(string(b))
	}
	return name + ", " + runtime.GOARCH
}
