package diagnostics

import (
	"fmt"
	"runtime"

	"golang.org/x/sys/windows"
)

// System names the operating system for the report header, such as
// "Windows 11 (10.0.26300), amd64". RtlGetVersion reports the real version
// whatever the program's compatibility manifest says.
func System() string {
	v := windows.RtlGetVersion()
	name := "Windows 10"
	if v.MajorVersion == 10 && v.BuildNumber >= 22000 {
		name = "Windows 11"
	} else if v.MajorVersion != 10 {
		name = "Windows"
	}
	return fmt.Sprintf("%s (%d.%d.%d), %s", name, v.MajorVersion, v.MinorVersion, v.BuildNumber, runtime.GOARCH)
}
