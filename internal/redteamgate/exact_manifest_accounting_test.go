package redteamgate

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// TestExactManifestSetAccountsForEveryRedteamTaggedTest is the S9c "the gate
// proves it" exit criterion (Sol14 P1-2). It independently rediscovers the
// authoritative //go:build redteam-tagged test inventory from source -- the
// same discovery scripts/redteam_source_identity.py performs at release -- loads
// the real ManifestSet (numbered corpus plus the five exact manifests under
// internal/redteam/manifests/), and asserts every discovered test is accounted
// for in EXACTLY ONE place: a numbered corpus case, an exact-manifest entry, or
// one of the two non-production exclusions.
//
// This is the structural property "excluded but happened to pass" cannot
// survive: a test that leaves the exclusions list must land in an exact
// manifest, or it blocks the gate. It also catches the inverse drift -- a new
// security test added under //go:build redteam that nobody manifested.
//
// The discovery here is intentionally an independent re-implementation of the
// release identity script (go list -tags redteam for authoritative package
// selection, then Go's parser for AST-true Test* extraction so string literals
// cannot poison the inventory -- the same reason redteam_test_names.go exists).
// Agreement between the two is the cross-check; this test must not shell out to
// the identity script itself, or it would test the script against itself.
func TestExactManifestSetAccountsForEveryRedteamTaggedTest(t *testing.T) {
	if testing.Short() {
		t.Skip("inventory discovery shells out to `go list`")
	}
	repoRoot := s9cRepoRoot(t)
	corpusPath := filepath.Join(repoRoot, "internal", "redteam", "manifest.yaml")
	exactPaths := s9cExactManifestPaths(t, repoRoot)

	set, err := LoadManifestSet(corpusPath, exactPaths)
	if err != nil {
		t.Fatalf("LoadManifestSet: %v", err)
	}

	// S9c drain: only the two non-production exclusions remain.
	var nonProd []string
	for _, e := range set.Corpus.Exclusions {
		if e.Status != "non-production" {
			t.Errorf("exclusion %q carries status %q; after S9c only non-production exclusions remain", e.Name, e.Status)
		}
		nonProd = append(nonProd, e.Name)
	}
	if len(nonProd) != 2 {
		t.Errorf("expected exactly 2 non-production exclusions after S9c, got %d: %v", len(nonProd), nonProd)
	}

	corpusNames := make(map[string]bool, len(set.Corpus.Cases))
	for _, c := range set.Corpus.Cases {
		corpusNames[c.Name] = true
	}
	exactNames := make(map[string]bool)
	for _, em := range set.ExactManifests {
		for _, n := range em.Tests {
			exactNames[n] = true
		}
	}
	excludedNames := make(map[string]bool, len(nonProd))
	for _, n := range nonProd {
		excludedNames[n] = true
	}

	inventory := s9cDiscoverRedteamInventory(t, repoRoot)
	if len(inventory) == 0 {
		t.Fatal("discovered zero //go:build redteam-tagged tests; the inventory discovery is broken")
	}

	var unaccounted, multi []string
	for _, name := range inventory {
		hits := 0
		for _, m := range []map[string]bool{corpusNames, exactNames, excludedNames} {
			if m[name] {
				hits++
			}
		}
		switch hits {
		case 0:
			unaccounted = append(unaccounted, name)
		case 1:
			// accounted in exactly one place: correct.
		default:
			multi = append(multi, name)
		}
	}
	if len(unaccounted) > 0 {
		sort.Strings(unaccounted)
		t.Errorf("%d //go:build redteam-tagged test(s) not accounted for in any manifest (corpus / exact / non-production exclusion): %v", len(unaccounted), unaccounted)
	}
	if len(multi) > 0 {
		sort.Strings(multi)
		t.Errorf("%d //go:build redteam-tagged test(s) accounted for in MORE THAN ONE place (a test belongs to exactly one manifest): %v", len(multi), multi)
	}
}

// s9cRepoRoot resolves the governator repo root from this test file's path
// (internal/redteamgate -> up two directories). runtime.Caller keeps it robust
// to wherever `go test` is invoked from.
func s9cRepoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not resolve test file path")
	}
	root := filepath.Join(filepath.Dir(thisFile), "..", "..")
	abs, err := filepath.Abs(root)
	if err != nil {
		t.Fatal(err)
	}
	return abs
}

// s9cExactManifestPaths globs the real exact-manifest directory in stable order.
func s9cExactManifestPaths(t *testing.T, repoRoot string) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(repoRoot, "internal", "redteam", "manifests", "*.yaml"))
	if err != nil {
		t.Fatalf("glob exact manifests: %v", err)
	}
	if len(matches) == 0 {
		t.Fatalf("no exact manifests found under %s/internal/redteam/manifests", repoRoot)
	}
	sort.Strings(matches)
	return matches
}

// s9cDiscoverRedteamInventory rediscovers the //go:build redteam-tagged test
// inventory, mirroring scripts/redteam_source_identity.py: `go list -tags redteam`
// for authoritative package selection, then for each selected _test.go file
// whose build constraint mentions redteam, parse it and collect top-level Test*
// function declarations (methods excluded, AST-true so string literals cannot
// masquerade as tests -- the same discipline redteam_test_names.go enforces).
func s9cDiscoverRedteamInventory(t *testing.T, repoRoot string) []string {
	t.Helper()
	cmd := exec.Command("go", "list", "-tags", "redteam", "-json", "./...")
	cmd.Dir = repoRoot
	stdout, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			t.Fatalf("go list -tags redteam failed: %v: %s", err, ee.Stderr)
		}
		t.Fatalf("go list -tags redteam failed: %v", err)
	}
	dec := json.NewDecoder(strings.NewReader(string(stdout)))
	fset := token.NewFileSet()
	seen := make(map[string]bool)
	for {
		var pkg struct {
			Dir          string   `json:"Dir"`
			GoFiles      []string `json:"GoFiles"`
			TestGoFiles  []string `json:"TestGoFiles"`
			XTestGoFiles []string `json:"XTestGoFiles"`
		}
		if err := dec.Decode(&pkg); err != nil {
			break
		}
		if pkg.Dir == "" {
			continue
		}
		selected := make(map[string]bool, len(pkg.GoFiles)+len(pkg.TestGoFiles)+len(pkg.XTestGoFiles))
		for _, n := range pkg.GoFiles {
			selected[n] = true
		}
		for _, n := range pkg.TestGoFiles {
			selected[n] = true
		}
		for _, n := range pkg.XTestGoFiles {
			selected[n] = true
		}
		for name := range selected {
			if !strings.HasSuffix(name, "_test.go") {
				continue
			}
			path := filepath.Join(pkg.Dir, name)
			content, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			if !s9cHasRedteamBuildConstraint(string(content)) {
				continue
			}
			file, err := parser.ParseFile(fset, path, content, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Recv != nil || !strings.HasPrefix(fn.Name.Name, "Test") {
					continue
				}
				seen[fn.Name.Name] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// s9cHasRedteamBuildConstraint mirrors redteam_source_identity.py: a line that
// starts with the build-constraint directive and mentions the redteam tag.
func s9cHasRedteamBuildConstraint(content string) bool {
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(line, "//go:build") && strings.Contains(line, "redteam") {
			return true
		}
	}
	return false
}
