package service

import (
	"strings"
	"testing"
)

func TestPackageUnitsFenceEveryActivationAndRetainHardening(t *testing.T) {
	c := Config{Directory: "/usr/lib/netswitch", Data: "/var/lib/netswitch", Native: true}
	packaged, err := PackageUnits(c)
	if err != nil {
		t.Fatal(err)
	}
	manual := unitFiles(c)
	condition := "ConditionPathExists=!/var/lib/netswitch/package-maintenance\n"
	if len(packaged) != 3 {
		t.Fatal("package must ship both services and their activation socket")
	}
	for name, body := range packaged {
		if strings.Count(body, condition) != 1 {
			t.Fatalf("%s does not fence activation during package replacement", name)
		}
		if strings.Replace(body, condition, "", 1) != manual[name] {
			t.Fatalf("%s diverged from the installed security and cleanup contract", name)
		}
	}
	for _, path := range []string{"relative", "/var/lib/with space", "/var/lib/%n", "/var/lib/line\nbreak"} {
		c.Data = path
		if _, err := PackageUnits(c); err == nil {
			t.Fatalf("invalid systemd condition path was accepted: %q", path)
		}
	}
}
