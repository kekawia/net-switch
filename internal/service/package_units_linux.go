package service

import (
	"errors"
	"path/filepath"
	"strings"
)

// PackageMaintenanceFile is private to the machine store. Its presence keeps
// systemd from activating an installation whose package replacement is unfinished.
const PackageMaintenanceFile = "package-maintenance"

// PackageUnits reuses the normal hardened units. Package managers own these
// under /usr/lib/systemd/system; the manual installer continues to own /etc.
func PackageUnits(c Config) (map[string]string, error) {
	for _, path := range []string{c.Directory, c.Data} {
		if !filepath.IsAbs(path) || strings.ContainsAny(path, " \t\n\r%\\") {
			return nil, errors.New("invalid package service path")
		}
	}
	c.Native = true
	units := unitFiles(c)
	condition := "ConditionPathExists=!" + filepath.Join(c.Data, PackageMaintenanceFile) + "\n"
	for name, body := range units {
		rest, ok := strings.CutPrefix(body, "[Unit]\n")
		if !ok {
			return nil, errors.New("service unit has no Unit section")
		}
		units[name] = "[Unit]\n" + condition + rest
	}
	return units, nil
}
