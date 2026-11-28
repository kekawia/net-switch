// Command versionstamp gives each Net Switch Windows program its name and
// version. It writes cmd/<program>/zz_version_windows_<arch>.syso for the
// next go build to link in, and prints each file it wrote, one per line.
// scripts/build-windows-installer.ps1 runs it before building the programs
// and deletes the files afterwards; .gitignore keeps them out of commits.
//
// Task Manager shows the description of a running program; Explorer's
// Details tab shows all of it; SignPath signs only files whose product name
// and version are set.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/kekawia/net-switch/internal/winres"
)

// Programs are the five the installer ships, in build order. Descriptions are
// what people read in Task Manager, so they say what each one is for.
var programs = []struct{ dir, description string }{
	{"netswitch", "Net Switch service"},
	{"netswitch-engine", "Net Switch routing engine"},
	{"netswitch-worker", "Net Switch network watcher"},
	{"netswitchctl", "Net Switch setup and repair"},
	{"netswitch-desktop", "Net Switch"},
}

const productName = "Net Switch"

func main() {
	root := flag.String("root", ".", "repository root")
	arch := flag.String("arch", "", "GOARCH of the programs: amd64 or arm64")
	version := flag.String("version", "", "release version, three plain numbers")
	flag.Parse()
	written, err := stamp(*root, *arch, *version)
	for _, path := range written {
		fmt.Println(path)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "versionstamp:", err)
		os.Exit(1)
	}
}

// stamp writes every program's object, or stops at the first error. It
// returns what it wrote either way, so the caller can delete it.
func stamp(root, arch, version string) ([]string, error) {
	v, err := winres.ParseVersion(version)
	if err != nil {
		return nil, err
	}
	var written []string
	for _, p := range programs {
		object, err := winres.Object(arch, winres.Info{
			Version:          v,
			ProductName:      productName,
			FileDescription:  p.description,
			CompanyName:      productName,
			InternalName:     p.dir,
			OriginalFilename: p.dir + ".exe",
		})
		if err != nil {
			return written, fmt.Errorf("%s: %w", p.dir, err)
		}
		dir := filepath.Join(root, "cmd", p.dir)
		if info, err := os.Stat(dir); err != nil || !info.IsDir() {
			return written, fmt.Errorf("%s is not a program folder", dir)
		}
		path := filepath.Join(dir, objectName(arch))
		if err := os.WriteFile(path, object, 0o644); err != nil {
			return written, err
		}
		written = append(written, path)
	}
	return written, nil
}

// The name ends in _windows_<arch>.syso, so only a Windows build for that
// architecture links it: a Linux build or another architecture never does.
func objectName(arch string) string { return "zz_version_windows_" + arch + ".syso" }
