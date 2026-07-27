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
	"strings"
	"sync"
	"testing"

	"github.com/cousingary/governator/internal/containment"
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

// useDegradedContainmentScopeForTest swaps in the test-only descendant-
// fixture can drive Governator's approval/merge/replay paths end to end on a
// host that lacks systemd --user, a usable cgroup v2 subtree, or a PID
// namespace. It is the sanctioned substitute for the Sol11 P0-3 production
// bypass GOV_CONTAINMENT_FORCE_DEGRADED (an inherited env var that could force
// degraded containment for a stage that should fail closed) and for the Sol11
// P0-4 env weakening GOV_CONTAINMENT_LOCAL_EFFECTFUL_TIERING: a package-level
// Go variable cannot be flipped by a launcher/wrapper/compromised shell, so
// production authority is never weakened, while the corpus still runs without
// real kernel primitives. The seam is reset on test cleanup. Note this does
// NOT put the run in development containment mode (local_effectful_tiering:
// off) -- the run still enforces host containment (Landlock) as production
// does; only the descendant-owning primitive is simulated as degraded.
func useDegradedContainmentScopeForTest(t *testing.T) {
	t.Helper()
	containment.ForceDegradedScopeForTesting.Store(true)
	t.Cleanup(func() { containment.ForceDegradedScopeForTesting.Store(false) })
}

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

var (
	shellReadRootsOnce sync.Once
	shellReadRootsList []string
)

// shellReadRootsForFixtures declares the exact Landlock read roots every
// fakeBackend fixture's POSIX shell script needs to actually launch under a
// real Landlock-enforced run instead of crashing before it ever attempts
// the behavior the test means to exercise. enforce.exactReadClosure's own
// doc comment requires a script's interpreter be contract-declared (a
// script isn't ELF, so it gets no automatic runtime closure the way the
// backend executable itself would); the corpus's fixture bodies also shell
// out to a handful of externally-invoked (non-builtin) coreutils that need
// the same treatment. Computed once per test process via
// enforce.ExecutableReadClosure, which resolves each tool's own ELF
// dependency closure (dynamic loader + shared libraries) — never a bare
// /bin or /usr/bin directory, which forbiddenBroadReadRoots rejects outright.
func shellReadRootsForFixtures() []string {
	shellReadRootsOnce.Do(func() {
		var out []string
		add := func(path string) {
			closure, err := enforce.ExecutableReadClosure(path)
			if err != nil {
				return
			}
			out = append(out, closure...)
		}
		add("/bin/sh")
		for _, tool := range []string{"mkdir", "cat", "chmod", "find", "ls", "rm", "sed", "sleep", "dd", "setsid", "timeout"} {
			if resolved, lerr := exec.LookPath(tool); lerr == nil {
				add(resolved)
			}
		}
		shellReadRootsList = out
	})
	return shellReadRootsList
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
		Success:     contracts.Success{RequiredFiles: []string{"output/result.txt"}, Validators: []string{"test -f output/result.txt"}, ValidatorSpecs: []contracts.ValidatorSpec{{Command: "test -f output/result.txt", Tools: []string{"test"}}}},
		OnViolation: "quarantine",
		Local:       &contracts.LocalRunnerConfig{ReadRoots: shellReadRootsForFixtures()},
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
		{"systemd-run", "/usr/bin/systemd-run"},
	} {
		path := tool.abs
		if _, err := os.Stat(path); err != nil {
			looked, lookErr := exec.LookPath(tool.name)
			if lookErr != nil {
				if tool.name == "unshare" || tool.name == "systemd-run" {
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
	// Tools baseContract's structured validators declare. Enrolled only when
	// absent so a test that deliberately re-enrolls one at a manipulated inode
	// (e.g. TestV7Case17 re-enrolls "test" at a fresh copy to invalidate
	// replay) is not clobbered back to the canonical path on every runGoverned.
	for _, tool := range []struct{ name, abs string }{
		{"test", "/usr/bin/test"},
		{"cat", "/usr/bin/cat"},
		{"setsid", "/usr/bin/setsid"},
		{"sh", "/usr/bin/sh"},
		{"sleep", "/usr/bin/sleep"},
		{"printf", "/usr/bin/printf"},
	} {
		if r, err := toolregistry.Load(); err == nil {
			if e, ok := r.Entry(tool.name); ok && strings.TrimSpace(e.Path) != "" {
				continue
			}
		}
		path := tool.abs
		if _, err := os.Stat(path); err != nil {
			looked, lookErr := exec.LookPath(tool.name)
			if lookErr != nil {
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

// buildFakeCodegraphBinary compiles a tiny real ELF binary standing in for
// a governed graph-provider tool. Unlike fakeBackend's POSIX shell scripts
// (which need their interpreter's Landlock read-closure separately
// declared -- see shellReadRootsForFixtures), a real compiled binary's own
// exactReadClosure is self-sufficient: internal/contextgraph/graph.go's
// scopedCommandOutput (Sol redteam v7 S1/contextgraph gap-closure, Task #3)
// only ever declares the executable's own path, no interpreter, matching
// how a production graph-provider tool (a real compiled binary, not a
// script) is actually shaped. statusJSON defaults to a plain
// not-yet-initialized status line when empty, so most callers can pass "".
func buildFakeCodegraphBinary(t *testing.T, extraImports, statusBody, statusJSON string) string {
	t.Helper()
	if statusJSON == "" {
		statusJSON = `{"version":"1.0.0","initialized":false}`
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "main.go")
	source := `package main

import (
	"fmt"
	"os"
` + extraImports + `
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("{}")
		return
	}
	switch os.Args[1] {
	case "version":
		fmt.Println("codegraph 1.0.0")
	case "status":
` + statusBody + `
		fmt.Println(` + "`" + statusJSON + "`" + `)
	default:
		fmt.Println("{}")
	}
}
`
	if err := os.WriteFile(src, []byte(source), 0644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "codegraph")
	cmd := exec.Command("go", "build", "-buildvcs=false", "-o", out, src)
	cmd.Dir = dir
	if combined, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build fake codegraph binary: %v: %s", err, combined)
	}
	return out
}
