//go:build !windows

package lifecycle

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// systemLoad describes how busy the PC is right now, for logs written when a
// deadline is missed: the load average and available memory where /proc has
// them.
func systemLoad() string {
	parts := []string{}
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		if fields := strings.Fields(string(b)); len(fields) >= 3 {
			parts = append(parts, "load "+strings.Join(fields[:3], " "))
		}
	}
	if f, err := os.Open("/proc/meminfo"); err == nil {
		defer f.Close()
		s := bufio.NewScanner(f)
		for s.Scan() {
			fields := strings.Fields(s.Text())
			if len(fields) >= 2 && fields[0] == "MemAvailable:" {
				if kb, err := strconv.ParseFloat(fields[1], 64); err == nil {
					parts = append(parts, strconv.FormatFloat(kb/(1<<20), 'f', 1, 64)+" GB memory available")
				}
				break
			}
		}
	}
	if len(parts) == 0 {
		return "load unknown"
	}
	return strings.Join(parts, ", ")
}
