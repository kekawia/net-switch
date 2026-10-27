package replayledger

import (
	"errors"
	"fmt"
	"go/ast"
	"io/fs"
	"path"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

func splitReference(ref string) (file, name, function string, ok bool) {
	file, name, ok = strings.Cut(ref, "#")
	function = strings.Split(name, "/")[0]
	if !ok || strings.Contains(name, "#") || !strings.HasSuffix(file, "_test.go") || !fs.ValidPath(file) || path.Clean(file) != file || !strings.HasPrefix(function, "Test") {
		return file, name, function, false
	}
	if suffix := strings.TrimPrefix(function, "Test"); suffix != "" {
		r, _ := utf8.DecodeRuneInString(suffix)
		if unicode.IsLower(r) {
			return file, name, function, false
		}
	}
	return file, name, function, true
}

func testReference(ref string) bool { _, _, _, ok := splitReference(ref); return ok }

// ValidateReferences checks every annotation, rule binding and supporting test.
// Only an absent function's FILE may be deferred, and only when every reference
// to that function is pending. A present file with a deleted test always fails.
func ValidateReferences(m Mapping, parse func(string) (*ast.File, error)) error {
	refs := map[string]bool{}
	add := func(ref string, pending bool) error {
		file, _, function, ok := splitReference(ref)
		if !ok {
			return fmt.Errorf("invalid test reference %q", ref)
		}
		key := file + "#" + function
		if old, exists := refs[key]; exists {
			pending = pending && old
		}
		refs[key] = pending
		return nil
	}
	for _, a := range m.Annotations {
		if err := add(a.Assertion, pendingStatus.MatchString(a.Status)); err != nil {
			return err
		}
	}
	for _, rule := range m.Rules {
		for _, ref := range rule.Bindings {
			if err := add(ref, false); err != nil {
				return err
			}
		}
	}
	for _, e := range m.SupportingEvidence {
		for _, ref := range e.Tests {
			if err := add(ref, false); err != nil {
				return err
			}
		}
	}
	for ref, pending := range refs {
		file, _, function, _ := splitReference(ref)
		parsed, err := parse(file)
		if errors.Is(err, fs.ErrNotExist) && pending {
			continue
		}
		if err != nil {
			return fmt.Errorf("test target %s: %w", ref, err)
		}
		alias := ""
		for _, imp := range parsed.Imports {
			value, _ := strconv.Unquote(imp.Path.Value)
			if value == "testing" {
				alias = "testing"
				if imp.Name != nil {
					alias = imp.Name.Name
				}
			}
		}
		found := false
		for _, decl := range parsed.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name.Name != function || fn.Recv != nil || fn.Type.Params.NumFields() != 1 || fn.Type.Results.NumFields() != 0 || fn.Type.TypeParams.NumFields() != 0 {
				continue
			}
			star, ok := fn.Type.Params.List[0].Type.(*ast.StarExpr)
			if !ok {
				continue
			}
			if sel, ok := star.X.(*ast.SelectorExpr); ok {
				pkg, ok := sel.X.(*ast.Ident)
				found = ok && alias != "" && alias != "_" && pkg.Name == alias && sel.Sel.Name == "T"
			}
			if id, ok := star.X.(*ast.Ident); ok {
				found = alias == "." && id.Name == "T"
			}
		}
		if !found {
			return fmt.Errorf("missing Test function with *testing.T signature: %s", ref)
		}
	}
	return nil
}
