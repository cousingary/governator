package runtime

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSol3NoConfigCurrentInExecutionCriticalPackages pins Sol Finding 2 /
// governator-sol3-repair-plan.md Session 3 (P0.2 immutable RunEnvironment):
// internal/runtime, internal/runner, and internal/router must never call
// config.Current() from execution-critical code again. Before this session,
// runOnce, auditTranscript, the route broker, and Docker credential-mount
// resolution each independently called config.Current() at different points
// during a single run — so an operator (or an attacker with file write
// access) editing config.yaml while a backend was mid-execution could change
// enforcement partway through a run whose identity and approval were
// computed against the *starting* configuration. The audit's reproduced
// exploit: doctrine.unenforceable_rule_action flipped from "block" to "flag"
// while the backend was sleeping, and the run was approved anyway.
//
// The fix threads one RunEnvironment (built via config.LoadStrict(), never
// the error-hiding config.Current()), frozen at the very top of runOnce
// before any decision, through every execution-critical consumer. This test
// parses the three packages' non-test source (skipping comments, which a
// plain text/grep scan would false-positive on — several of this session's
// own explanatory comments mention config.Current() by name) and fails if
// any function calls it, except the narrow, explicitly justified exceptions
// below.
func TestSol3NoConfigCurrentInExecutionCriticalPackages(t *testing.T) {
	// allowedCalls maps "<base filename>" -> set of function names permitted
	// to call config.Current() directly. Every entry here must be justified
	// in the session report: none of them are per-run enforcement decisions.
	allowedCalls := map[string]map[string]bool{
		// Home() resolves the ledger directory once per process/CLI
		// invocation, at Runner construction (runtime.New), before any run
		// begins. It is infrastructure plumbing (where the ledger DB lives),
		// never a re-read during an in-flight run, and is not part of the
		// enforcement/identity model RunEnvironment freezes.
		"runtime.go": {"Home": true},
	}

	dirs := []string{".", "../runner", "../router"}
	fset := token.NewFileSet()
	var violations []string

	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read dir %s: %v", dir, err)
		}
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			path := filepath.Join(dir, name)
			file, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				funcName := fn.Name.Name
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					sel, ok := call.Fun.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					pkgIdent, ok := sel.X.(*ast.Ident)
					if !ok || pkgIdent.Name != "config" || sel.Sel.Name != "Current" {
						return true
					}
					if allowedCalls[name][funcName] {
						return true
					}
					violations = append(violations, fmt.Sprintf("%s:%s calls config.Current() (func %s) — execution-critical code must use a frozen RunEnvironment/config.LoadStrict() value instead",
						path, fset.Position(call.Pos()), funcName))
					return true
				})
			}
		}
	}

	if len(violations) > 0 {
		t.Fatalf("config.Current() referenced from execution-critical code:\n%s", strings.Join(violations, "\n"))
	}
}
