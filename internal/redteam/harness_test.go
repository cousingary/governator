//go:build redteam

// Package redteam is the permanent black-box attack corpus from Sol's v4
// red-team audit (agents/governator-sol-upgrade4.md §9). Every test builds a
// hostile fixture repo/backend in t.TempDir(), drives it through the real,
// exported internal/runtime API end to end, and asserts an observable
// security outcome (committed tree contents, live-root file presence,
// git history) — never an internal function's return value.
//
// Run via scripts/redteam.sh. Attacks not yet fixed carry
// t.Skip("expected-fail until S<n>") naming the session that closes them;
// the skip count is the project burn-down (see
// agents/governator-sol-upgrade4-plan.md).
package redteam

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/cousingary/governator/internal/contracts"
	"github.com/cousingary/governator/internal/enforce"
	govruntime "github.com/cousingary/governator/internal/runtime"
	"github.com/cousingary/governator/internal/toolregistry"
)

var (
	govBinaryOnce sync.Once
	govBinaryPath string
	govBinaryErr  error
)

// govBinary builds the real cmd/gov CLI exactly once per test process and
// returns the path to the resulting executable. Attacks that exercise
// CLI-protocol behavior (gate check, version, release artifact shape) need
// the real binary, not the internal Run() library call the rest of this
// corpus drives directly.
func govBinary(t *testing.T) string {
	t.Helper()
	govBinaryOnce.Do(func() {
		_, thisFile, _, _ := runtime.Caller(0)
		repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")
		dir, err := os.MkdirTemp("", "gov-redteam-bin")
		if err != nil {
			govBinaryErr = err
			return
		}
		out := filepath.Join(dir, "gov")
		cmd := exec.Command("go", "build", "-buildvcs=false", "-o", out, "./cmd/gov")
		cmd.Dir = repoRoot
		if combined, err := cmd.CombinedOutput(); err != nil {
			govBinaryErr = err
			govBinaryPath = string(combined)
			return
		}
		govBinaryPath = out
	})
	if govBinaryErr != nil {
		t.Fatalf("build gov binary: %v: %s", govBinaryErr, govBinaryPath)
	}
	return govBinaryPath
}

// git runs a git subcommand in dir, failing the test on error.
func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
}

// gitOutput runs a git subcommand in dir and returns stdout, failing the test
// on a nonzero exit.
func gitOutput(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git %v: %v", args, err)
	}
	return string(out)
}

// fixtureRepo creates a disposable git repo seeded with one committed file,
// the same shape every attack in this corpus stages its hostile content
// into.
func fixtureRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	git(t, root, "init", "-b", "main")
	git(t, root, "config", "user.email", "redteam@example.invalid")
	git(t, root, "config", "user.name", "Governator Redteam")
	if err := os.WriteFile(filepath.Join(root, "seed.txt"), []byte("seed\n"), 0644); err != nil {
		t.Fatal(err)
	}
	git(t, root, "add", ".")
	git(t, root, "commit", "-m", "seed")
	return root
}

// fakeBackend writes an executable POSIX shell script standing in for a
// governed backend CLI (claude-code's adapter shape: read RESULT.json/stdout
// JSON events after doing whatever the attack script says).
func fakeBackend(t *testing.T, body string) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "fake-backend")
	script := "#!/bin/sh\nset -eu\n" + body
	if err := os.WriteFile(bin, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	return bin
}

// baseContract is the minimal valid job contract every attack starts from:
// permitted to write output/**, one required file, quarantine on violation.
// Individual tests narrow or widen Allowed/Forbidden/Success as the attack
// requires.
func baseContract(root string) contracts.Contract {
	return contracts.Contract{
		Task: "redteam corpus fixture", JobID: "redteam-fixture", JobType: "test", Agent: "claude-code", Mode: contracts.ModeSurgeon,
		Workspace:   contracts.Workspace{Root: root, Worktree: "auto"},
		Allowed:     contracts.Permissions{Read: []string{"**"}, Write: []string{"output/**"}, Execute: []string{"test"}},
		Forbidden:   contracts.Forbidden{Paths: []string{".git/**"}, Commands: []string{"rm -rf"}, Behaviors: []string{"network"}},
		Budget:      contracts.Budget{MaxMinutes: 1, MaxCommands: 5, MaxFilesChanged: 5, MaxLinesChanged: 20, MaxNewFiles: 5, MaxDeleted: 0},
		Preflight:   contracts.Preflight{IntendedWrites: []string{"output/**"}},
		Success:     contracts.Success{RequiredFiles: []string{"output/result.txt"}, Validators: []string{"test -f output/result.txt"}},
		OnViolation: "quarantine",
	}
}

// runGoverned runs c through the real runtime engine (RunWithAutoRepair,
// exactly what `gov run` invokes) with GOV_HOME/GOV_CLAUDE_BIN pointed at
// disposable per-test fixtures.
func runGoverned(t *testing.T, home, bin string, c contracts.Contract) govruntime.RunRecord {
	t.Helper()
	rec, err := runGovernedAllowError(t, home, bin, c)
	if err != nil {
		t.Fatalf("RunWithAutoRepair: %v", err)
	}
	return rec
}

func runGovernedAllowError(t *testing.T, home, bin string, c contracts.Contract) (govruntime.RunRecord, error) {
	t.Helper()
	// Authority-derived containment makes effectful local fixtures use the
	// same Landlock/netns prerequisites as production.
	enrollRealControllerTools(t)
	ownSelfExe := enforce.SelfExeOverride == ""
	if ownSelfExe {
		enforce.SelfExeOverride = govBinary(t)
		defer func() { enforce.SelfExeOverride = "" }()
	}
	t.Setenv("GOV_HOME", home)
	t.Setenv("GOV_CLAUDE_BIN", bin)
	return govruntime.New().RunWithAutoRepair(context.Background(), c)
}

// enrollRealControllerTools pins the controller tools every ordinary
// governed run needs before any hostile PATH poisoning happens. v6 S2 made
// ordinary execution fail closed when git/bash are not enrolled; older
// redteam fixtures that only care about a different attack surface should
// not fail at workspace creation just because their disposable registry is
// intentionally fresh.
func enrollRealControllerTools(t *testing.T) {
	t.Helper()
	for _, tool := range []struct{ name, abs string }{
		{"git", "/usr/bin/git"},
		{"bash", "/usr/bin/bash"},
		{"unshare", "/usr/bin/unshare"},
	} {
		path := tool.abs
		if _, err := os.Stat(path); err != nil {
			looked, lookErr := exec.LookPath(tool.name)
			if lookErr != nil {
				if tool.name == "unshare" {
					continue
				}
				t.Fatal(lookErr)
			}
			path = looked
		}
		if canonical, err := filepath.EvalSymlinks(path); err == nil {
			path = canonical
		}
		if _, err := toolregistry.Enroll(tool.name, path); err != nil {
			t.Fatal(err)
		}
	}
}

// committedPaths lists every path git actually knows about in root's HEAD
// tree, NUL-delimited so hostile filenames (newlines, pathspec magic) can
// never be misparsed the way human-readable porcelain output can.
func committedPaths(t *testing.T, root string) []string {
	t.Helper()
	cmd := exec.Command("git", "-C", root, "ls-tree", "-r", "--name-only", "-z", "HEAD")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git ls-tree: %v", err)
	}
	var paths []string
	for _, p := range splitNUL(string(out)) {
		if p != "" {
			paths = append(paths, p)
		}
	}
	return paths
}

func splitNUL(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == 0 {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

func contains(paths []string, target string) bool {
	for _, p := range paths {
		if p == target {
			return true
		}
	}
	return false
}

func hasPrefixAny(paths []string, prefix string) bool {
	for _, p := range paths {
		if p == prefix || (len(p) > len(prefix) && p[:len(prefix)+1] == prefix+"/") {
			return true
		}
	}
	return false
}

// standardBackendBody is the shared shape every attack's fake backend ends
// on: declare output/result.txt as the sole intended change via RESULT.json
// and a completion event with a plausible cost. extra runs first, so an
// attack script can create hostile content before the well-behaved part
// signals success — mirroring the report's "the backend created only the
// permitted output" attacks, where the damage comes from something other
// than the backend's own declared file list.
func standardBackendBody(extra string) string {
	return extra + `
mkdir -p output
printf 'ok\n' > output/result.txt
printf '{"status":"complete","files_changed":["output/result.txt"],"commands_run":0,"validation":{"self_checked":true},"violations":[],"blockers":[],"next_recommended_action":"none"}\n' > RESULT.json
printf '{"type":"result","total_cost_usd":0.25}\n'
`
}
