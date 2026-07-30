package govlint

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// allowedPanicClasses are the only reasons a panic( call may remain in one of
// panicRatchetPackages. Sol15 P0-3: internal/quota shipped mustNanos, a
// helper that panicked the instant a config- or database-derived timestamp
// fell outside dbtime's supported range -- a syntactically valid
// `reset_at: "9999-01-01"` crashed the packaged `gov quota` binary. These
// three packages exist specifically to turn operator config, provider
// responses, and stored ledger rows into decisions; by construction every
// value flowing through them can originate outside the process. No panic
// belongs here today, and the zero-entry map is the point -- this must never
// gain an entry just to make a new panic pass.
var allowedPanicClasses = map[string]string{}

// panicRatchetPackages are scanned in full: every panic( in a non-test .go
// file under these directories must carry an adjacent
// //govratchet:panic-allow(<class>) marker naming a class in
// allowedPanicClasses. Session 1 deleted the one violation (quota.mustNanos);
// this keeps it deleted rather than gating on a param-type heuristic that a
// helper function could trivially dodge.
var panicRatchetPackages = []string{
	filepath.Join("internal", "quota"),
	filepath.Join("internal", "spend"),
	filepath.Join("internal", "config"),
}

func TestPanicReachabilityRatchet(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not resolve this test file's own path")
	}
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")
	var violations []string
	for _, pkg := range panicRatchetPackages {
		root := filepath.Join(repoRoot, pkg)
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, _ := filepath.Rel(repoRoot, path)
			hits, err := scanFileForBarePanic(path, rel)
			if err != nil {
				return err
			}
			violations = append(violations, hits...)
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
	if len(violations) > 0 {
		sort.Strings(violations)
		t.Fatalf("panic reachability ratchet: %d unmarked/invalid site(s):\n%s\n\nEvery panic( in %s must carry an adjacent //govratchet:panic-allow(<class>) marker naming one of: %s (today, none).", len(violations), strings.Join(violations, "\n"), strings.Join(panicRatchetPackages, ", "), strings.Join(sortedPanicClassNames(), ", "))
	}
}

func scanFileForBarePanic(path, label string) ([]string, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	var violations []string
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		ident, ok := call.Fun.(*ast.Ident)
		if !ok || ident.Name != "panic" {
			return true
		}
		line := fset.Position(call.Pos()).Line
		class, marked := panicMarkerNearLine(fset, file, line)
		switch {
		case !marked:
			violations = append(violations, fmt.Sprintf("%s:%d: panic( has no //govratchet:panic-allow(<class>) marker", label, line))
		case allowedPanicClasses[class] == "":
			violations = append(violations, fmt.Sprintf("%s:%d: //govratchet:panic-allow(%s) cites an unrecognized class", label, line, class))
		}
		return true
	})
	return violations, nil
}

func panicMarkerNearLine(fset *token.FileSet, file *ast.File, line int) (string, bool) {
	for _, group := range file.Comments {
		for _, comment := range group.List {
			commentLine := fset.Position(comment.Pos()).Line
			if commentLine != line && commentLine != line-1 {
				continue
			}
			const marker = "govratchet:panic-allow("
			index := strings.Index(comment.Text, marker)
			if index < 0 {
				continue
			}
			rest := comment.Text[index+len(marker):]
			end := strings.Index(rest, ")")
			if end >= 0 {
				return rest[:end], true
			}
		}
	}
	return "", false
}

func sortedPanicClassNames() []string {
	names := make([]string, 0, len(allowedPanicClasses))
	for name := range allowedPanicClasses {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func TestPanicReachabilityRatchetDetectsUnmarkedAndInvalidMarkers(t *testing.T) {
	write := func(body string) string {
		path := filepath.Join(t.TempDir(), "fixture.go")
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}
	tests := []struct {
		name string
		body string
		want int
	}{
		{"unmarked panic", "package fixture\nfunc f() { panic(\"boom\") }\n", 1},
		{"marked but unrecognized class", "package fixture\nfunc f() {\n\t// govratchet:panic-allow(made_up)\n\tpanic(\"boom\")\n}\n", 1},
		{"no panic at all", "package fixture\nfunc f() { return }\n", 0},
		{"panic in unrelated call is not matched", "package fixture\nfunc f() { notpanic(\"boom\") }\nfunc notpanic(s string) {}\n", 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := scanFileForBarePanic(write(test.body), "fixture.go")
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != test.want {
				t.Fatalf("violations = %v, want count %d", got, test.want)
			}
		})
	}
}
