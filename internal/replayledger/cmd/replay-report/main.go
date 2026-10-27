// replay-report joins passed test receipts from stdin; it never writes a log.
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"

	"github.com/AyoubAchour/net-switch/internal/replayledger"
)

func run() error {
	m, err := replayledger.DefaultMapping()
	if err != nil {
		return err
	}
	if err := replayledger.ValidateReferences(m, func(path string) (*ast.File, error) { return parser.ParseFile(token.NewFileSet(), path, nil, 0) }); err != nil {
		return err
	}
	traces, err := replayledger.Load(".", m)
	if err != nil {
		return err
	}
	r, err := replayledger.Build(m, traces)
	if err != nil {
		return err
	}
	r, err = replayledger.Aggregate(os.Stdin, r, os.Stdout)
	if err != nil {
		return err
	}
	fmt.Printf("covered %d / 7,894; uncovered %d; pending %v\n", r.Counts.Covered, r.Counts.Uncovered, r.Counts.Pending)
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
