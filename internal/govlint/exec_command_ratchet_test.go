// Package govlint hosts repo-wide static-analysis CI gates that are cheap
// enough to run as ordinary Go tests (part of `go test ./...`, the very
// first tier scripts/release.sh and CI run) rather than a separate linter
// binary or CI step of their own.
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

// allowedExecCommandClasses are the only justifications a
// //govratchet:exec-allow(<class>) marker may cite. Adding a class here is
// a deliberate, reviewable decision about what kind of raw exec.Command /
// exec.CommandContext call site the ratchet accepts -- it is not meant to
// grow casually.
var allowedExecCommandClasses = map[string]string{
	"production_launch_factory":   "the verified-handle/sealed-descriptor launch mechanism itself (internal/agents.LaunchCommand, internal/toolregistry.Handle.Command, and the CommandFactory closures that receive an already-verified bin from a Handle) -- expected to contain the terminal raw exec call",
	"diagnostic_only":             "gov doctor / --version / --help probes: sandboxed to a disposable scratch dir, never part of a governed run's authority path",
	"release_tooling":             "claims/release verification against an already-built artifact or repo history -- offline reconciliation, not a live governed run",
	"legacy_bridge":               "a best-effort, non-blocking side channel to the legacy Python harness whose failure never affects the governed run's outcome",
	"known_gap_pending_hardening": "a genuine authority-bearing pathname exec that Session 5 (rc3) found and explicitly did NOT fix -- narrowly grandfathered so the ratchet doesn't block unrelated work, not endorsed as correct; see the comment at each such site and docs/claims.yaml",
}

// TestExecCommandRatchet is the Sol9 P2-3 CI ratchet: every raw
// exec.Command / exec.CommandContext call site in non-test Governator
// source must carry an explicit //govratchet:exec-allow(<class>)
// justification comment on the same source line as the call. The marker
// travels with the code -- it survives refactors that move line numbers,
// unlike a separate allowlist file keyed by file:line -- and it is the one
// place a reader can find out WHY a given site is trusted to bypass the
// verified-handle/sealed-descriptor launch path Sessions 1-7 built.
//
// This is a ratchet, not a ban: every site marked as of Sol9 Session 8 stays
// green, including the containment/descendants.go known_gap_pending_hardening
// sites Session 5 flagged as genuinely unresolved (systemd-run/unshare still
// launched by pathname). Adding a NEW raw exec.Command/exec.CommandContext
// call site without a marker -- or citing a class not in
// allowedExecCommandClasses -- fails this test. Report attack surface: Sol9
// P2-3 ("architecture claims exceed current implementation" / "a CI ratchet
// should reject new raw execution sites and maintain an explicit allowlist
// for the remaining ones").
func TestExecCommandRatchet(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not resolve this test file's own path")
	}
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")

	var violations []string
	for _, root := range []string{filepath.Join(repoRoot, "internal"), filepath.Join(repoRoot, "cmd")} {
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, _ := filepath.Rel(repoRoot, path)
			hits, perr := scanFileForUnmarkedExecCommand(path, rel)
			if perr != nil {
				return perr
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
		t.Fatalf(
			"exec.Command ratchet: %d unmarked/invalid call site(s):\n%s\n\n"+
				"Every raw exec.Command/exec.CommandContext call outside _test.go must carry a "+
				"same-line comment `// govratchet:exec-allow(<class>)` naming one of: %s.\n"+
				"See internal/govlint/exec_command_ratchet_test.go.",
			len(violations), strings.Join(violations, "\n"), strings.Join(sortedClassNames(), ", "),
		)
	}
}

// scanFileForUnmarkedExecCommand parses one Go source file and returns one
// violation string per raw exec.Command/exec.CommandContext call that is
// unmarked or cites an unrecognized class. label prefixes each violation
// (the file's repo-relative path in production use; an arbitrary name in
// the synthetic-fixture test below).
func scanFileForUnmarkedExecCommand(path, label string) ([]string, error) {
	fset := token.NewFileSet()
	file, perr := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if perr != nil {
		return nil, fmt.Errorf("parse %s: %w", path, perr)
	}
	var violations []string
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkgIdent, ok := sel.X.(*ast.Ident)
		if !ok || pkgIdent.Name != "exec" {
			return true
		}
		if sel.Sel.Name != "Command" && sel.Sel.Name != "CommandContext" {
			return true
		}
		line := fset.Position(call.Pos()).Line
		class, marked := markerClassOnLine(fset, file, line)
		switch {
		case !marked:
			violations = append(violations, fmt.Sprintf("%s:%d: raw exec.%s call with no //govratchet:exec-allow(<class>) marker on the same line", label, line, sel.Sel.Name))
		case allowedExecCommandClasses[class] == "":
			violations = append(violations, fmt.Sprintf("%s:%d: //govratchet:exec-allow(%s) cites an unrecognized class", label, line, class))
		}
		return true
	})
	return violations, nil
}

// TestExecCommandRatchetDetectsUnmarkedAndInvalidSites is the ratchet's own
// meta-test: a static-analysis CI gate that could silently fail open (e.g.
// a typo in the marker string, or the AST match never firing) would be
// worse than no gate at all -- callers would trust a green run that proved
// nothing. This exercises scanFileForUnmarkedExecCommand directly against
// synthetic fixtures, independent of whatever the real tree currently
// contains.
func TestExecCommandRatchetDetectsUnmarkedAndInvalidSites(t *testing.T) {
	write := func(t *testing.T, body string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "fixture.go")
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}

	t.Run("unmarked call site is a violation", func(t *testing.T) {
		path := write(t, `package fixture

import "os/exec"

func run() {
	_ = exec.Command("echo", "hi")
}
`)
		got, err := scanFileForUnmarkedExecCommand(path, "fixture.go")
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || !strings.Contains(got[0], "no //govratchet:exec-allow") {
			t.Fatalf("expected exactly one unmarked-call violation, got %v", got)
		}
	})

	t.Run("unrecognized class is a violation", func(t *testing.T) {
		path := write(t, `package fixture

import "os/exec"

func run() {
	_ = exec.Command("echo", "hi") // govratchet:exec-allow(made_up_class)
}
`)
		got, err := scanFileForUnmarkedExecCommand(path, "fixture.go")
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || !strings.Contains(got[0], "unrecognized class") {
			t.Fatalf("expected exactly one unrecognized-class violation, got %v", got)
		}
	})

	t.Run("valid marker on the same line is clean", func(t *testing.T) {
		path := write(t, `package fixture

import "os/exec"

func run() {
	_ = exec.Command("echo", "hi") // govratchet:exec-allow(diagnostic_only)
}
`)
		got, err := scanFileForUnmarkedExecCommand(path, "fixture.go")
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 0 {
			t.Fatalf("expected no violations for a validly marked call, got %v", got)
		}
	})

	t.Run("exec.CommandContext is also caught", func(t *testing.T) {
		path := write(t, `package fixture

import (
	"context"
	"os/exec"
)

func run(ctx context.Context) {
	_ = exec.CommandContext(ctx, "echo", "hi")
}
`)
		got, err := scanFileForUnmarkedExecCommand(path, "fixture.go")
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 {
			t.Fatalf("expected exec.CommandContext to be caught too, got %v", got)
		}
	})
}

func markerClassOnLine(fset *token.FileSet, file *ast.File, line int) (string, bool) {
	for _, cg := range file.Comments {
		for _, c := range cg.List {
			if fset.Position(c.Pos()).Line != line {
				continue
			}
			const marker = "govratchet:exec-allow("
			idx := strings.Index(c.Text, marker)
			if idx < 0 {
				continue
			}
			rest := c.Text[idx+len(marker):]
			end := strings.Index(rest, ")")
			if end < 0 {
				continue
			}
			return rest[:end], true
		}
	}
	return "", false
}

func sortedClassNames() []string {
	names := make([]string, 0, len(allowedExecCommandClasses))
	for k := range allowedExecCommandClasses {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}
