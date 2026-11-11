//go:build linux

package ownerbpf

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func validateBridgeTestPartition(testNames []string, guestSuites []FloorGuestSuite) error {
	if len(testNames) == 0 {
		return fmt.Errorf("no TestBridge functions discovered")
	}
	compiled := make([]*regexp.Regexp, len(guestSuites))
	for i, s := range guestSuites {
		re, err := regexp.Compile(s.Pattern)
		if err != nil {
			return fmt.Errorf("suite %q invalid pattern %q: %w", s.Name, s.Pattern, err)
		}
		compiled[i] = re
	}
	for _, name := range testNames {
		matches := 0
		for _, re := range compiled {
			if re.MatchString(name) {
				matches++
			}
		}
		if matches != 1 {
			return fmt.Errorf("bridge proof test %s matched %d floor guest suites (want 1)", name, matches)
		}
	}
	return nil
}

func TestFloorGuestSuitesPartitionEveryBridgeProof(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var bridgeTests []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		fileAST, err := parser.ParseFile(fset, filepath.Join(".", entry.Name()), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", entry.Name(), err)
		}
		for _, decl := range fileAST.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if ok && fn.Recv == nil && strings.HasPrefix(fn.Name.Name, "TestBridge") {
				bridgeTests = append(bridgeTests, fn.Name.Name)
			}
		}
	}
	guestSuites := FloorGuestSuites()
	if err := validateBridgeTestPartition(bridgeTests, guestSuites); err != nil {
		t.Fatal(err)
	}
	if err := validateBridgeTestPartition(append(append([]string(nil), bridgeTests...), "TestBridgeUnassignedCase"), guestSuites); err == nil {
		t.Fatal("unassigned TestBridge function unexpectedly passed floor guest suite partition check")
	}
	overlapping := append([]FloorGuestSuite(nil), guestSuites...)
	overlapping = append(overlapping, FloorGuestSuite{Name: "duplicate", Pattern: "^TestBridgeBurstCost$", Timeout: "5m"})
	if err := validateBridgeTestPartition(bridgeTests, overlapping); err == nil {
		t.Fatal("overlapping TestBridge suite pattern unexpectedly passed partition check")
	}
}
