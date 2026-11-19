package winplatform

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The privacy fallback is deliberately stronger than banning opcode 7:
// The 1.0 Windows reader packages must have no Native Wi-Fi entry point at all.
// Include build-constrained files and the extracted observer subpackage, not
// the frozen 0.3.x helper.
func TestSSIDNoLocationAPIs(t *testing.T) {
	files := 0
	observerFiles := 0
	err := filepath.WalkDir(".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		files++
		if filepath.Dir(path) == "observer" {
			observerFiles++
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if symbol := locationAPISymbol(body); symbol != "" {
			t.Errorf("%s imports or resolves location API %q", path, symbol)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files < 10 || observerFiles < 5 {
		t.Fatalf("source guard visited only %d files (%d in observer)", files, observerFiles)
	}
	t.Logf("checked %d production files (%d in observer); no Native Wi-Fi/location API symbols", files, observerFiles)
}

func locationAPISymbol(body []byte) string {
	f, err := parser.ParseFile(token.NewFileSet(), "source.go", body, 0)
	if err != nil {
		return "invalid Go source"
	}
	blocked := ""
	ast.Inspect(f, func(n ast.Node) bool {
		value := ""
		switch n := n.(type) {
		case *ast.BasicLit:
			if n.Kind == token.STRING {
				value, _ = strconv.Unquote(n.Value)
			}
		case *ast.Ident:
			value = n.Name
		}
		lower := strings.ToLower(value)
		for _, name := range []string{"wlanapi", "wlanqueryinterface", "wlangetavailablenetworklist", "wlangetnetworkbsslist", "wlanscan", "getlanidentifiers", "windows.devices.wifi", "windows.devices.geolocation"} {
			if strings.Contains(lower, name) {
				blocked = value
				return false
			}
		}
		return blocked == ""
	})
	return blocked
}

func TestSSIDLocationGuardRejectsOldAPI(t *testing.T) {
	for _, source := range []string{
		`package p; var dll = "wlanapi.dll"`,
		`package p; var proc = "WlanQueryInterface"`,
		`package p; func f() { WlanQueryInterface(7) }`,
		`package p; var proc = "GetLanIdentifiers"`,
	} {
		if locationAPISymbol([]byte(source)) == "" {
			t.Fatalf("guard accepted %s", source)
		}
	}
	if symbol := locationAPISymbol([]byte(`package p; var class = "Windows.Networking.Connectivity.NetworkInformation"`)); symbol != "" {
		t.Fatalf("safe source rejected: %s", symbol)
	}
}
