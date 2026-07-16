package stage

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// TestNoRawProcessLaunchOutsideStageExecutor is Session 7's CI grep
// invariant (agents/governator-sol-upgrade7-plan.md, report §"Required
// correction": "no exec.Command / exec.CommandContext / os.StartProcess
// anywhere outside StageExecutor and tightly-approved bootstrap").
//
// StageExecutor (this package) is not yet the *only* launch path — Session 1
// built the executor but did not finish routing every governed stage through
// it (see the S0/S1/S5/S6 findings entry in
// agents/governator-sol-upgrade7-findings.md). Making this check strict
// ("zero occurrences outside internal/stage") today would fail the whole
// build on work that belongs to S1, not S7. Instead this is a *ratchet*: an
// explicit, per-file exact count of every current call site, categorized
// below. Any NEW call site (a file not listed, or a listed file's count
// increasing) fails immediately — no more raw launches can be added
// silently. Any file whose migration is completed must have its count
// (ideally the whole entry) removed here in the same change, so this list
// visibly shrinks as S1/S4/S6 finish routing their stages through
// StageExecutor — a stale, too-high count is a coverage gap, not safety.
func TestNoRawProcessLaunchOutsideStageExecutor(t *testing.T) {
	repoRoot := repoRootFromTestFile(t)

	// Category A: permanently legitimate — genuinely outside the scope of
	// "launch a governed external stage" (release/CI verification tooling,
	// health-probe diagnostics, and the git plumbing / containment / sealed-
	// handle primitives StageExecutor is built ON TOP OF, not launches it
	// should itself wrap).
	permanent := map[string]int{
		// Release-time / CI verification tooling: inspects an already-built
		// artifact (`gov version --json`) or runs read-only git plumbing to
		// check claims against history. Not a governed runtime stage.
		"internal/claims/claims.go": 4,
		// git plumbing primitive (report §standing rule 4: "internal/gitplumb
		// ... all already exist" — S1 threads existing primitives through
		// the executor, it does not replace them).
		"internal/gitplumb/gitplumb.go": 1,
		// `git init` for the attestation harness's own throwaway workspace
		// setup, not a governed stage.
		"internal/attest/attest.go": 1,
		// Read-only `--version`/`--help`/`worktree -h` diagnostic probes for
		// the doctor health-check command; never executes a governed job.
		"internal/doctor/doctor.go": 7,
		// The systemd-run descendant-scope probe and scope launch: this is
		// the containment PRIMITIVE StageExecutor's DescendantPolicy is
		// built on, not a bypass of it.
		"internal/containment/descendants.go": 5,
		// The sealed-handle `/proc/self/fd/<n>` launch mechanism itself
		// (report §S4 "Required correction": "launch via fexecve or
		// /proc/self/fd/<n>") — foundational launch primitive, not a bypass.
		"internal/toolregistry/handle.go": 1,
		// gov's own `--claude-shadow` maintenance script invocation
		// (unrelated to contract/backend execution).
		"cmd/gov/main.go": 1,
	}

	// Category B: known S1/S4/S6 migration gaps — real governed-stage
	// launches that have NOT yet been routed through StageExecutor. Each is
	// tracked in the findings log; this list exists so the count cannot grow
	// further while those sessions are pending, and must shrink (ideally to
	// zero, with the file's entry deleted) as each is migrated.
	migrationPending := map[string]int{
		// agents.LaunchCommand and friends: the backend/validator launch
		// path findings.md's S2 entry documents as discarding the
		// StageExecutor-computed enforcement wrap for sealed handles.
		"internal/agents/handle.go": 5,
		// Tool-version resolution probes (pre-launch identity resolution,
		// not stage execution) plus a legacy launch path.
		"internal/agents/resolution.go": 1,
		// Real Assayer CLI invocation (corpus cases 11/12 target this
		// exact call site).
		"internal/assay/assay.go": 1,
		// Assayer environment probes (git rev-parse / python3 --version)
		// used to resolve the Assayer toolchain before launch.
		"internal/assay/environment.go": 2,
		// Docker CLI launches for the container backend/runner path.
		"internal/runner/docker.go": 6,
		// Bash validator/backend command execution — the pre-S1 path
		// StageExecutor is meant to fully replace.
		"internal/runner/runner.go":   1,
		"internal/runtime/runtime.go": 1,
		// Python snapshot pre-delete hook execution.
		"internal/runtime/gate.go": 1,
	}

	allowed := map[string]int{}
	for k, v := range permanent {
		allowed[k] = v
	}
	for k, v := range migrationPending {
		if _, dup := allowed[k]; dup {
			t.Fatalf("test bug: %s listed in both permanent and migrationPending", k)
		}
		allowed[k] = v
	}

	found := findRawLaunchCalls(t, repoRoot)

	var problems []string
	for file, count := range found {
		want, known := allowed[file]
		switch {
		case !known:
			problems = append(problems, "new/unmanifested raw launch site: "+file+" ("+strconv.Itoa(count)+" occurrence(s)) — either route it through internal/stage.Executor or add it to this test's allowlist with a reason")
		case count != want:
			problems = append(problems, file+": expected "+strconv.Itoa(want)+" raw launch call(s), found "+strconv.Itoa(count)+" — update this test's allowlist to match (a decrease means progress: shrink the entry; an increase is new drift and must be justified)")
		}
	}
	for file, want := range allowed {
		if _, present := found[file]; !present && want > 0 {
			problems = append(problems, file+": allowlisted for "+strconv.Itoa(want)+" raw launch call(s) but none found — the file was migrated or removed; shrink/delete this allowlist entry")
		}
	}

	if len(problems) > 0 {
		sort.Strings(problems)
		t.Fatalf("no-launch-outside-StageExecutor invariant violated:\n%s", strings.Join(problems, "\n"))
	}
}

var rawLaunchCallRE = regexp.MustCompile(`\b(exec\.Command|exec\.CommandContext|os\.StartProcess)\(`)

// findRawLaunchCalls counts exec.Command/exec.CommandContext/os.StartProcess
// call expressions per repo-relative .go file, skipping _test.go files (test
// fixtures — including internal/redteam's own black-box harnesses, which
// legitimately shell out to build and run real binaries under test — are not
// governed runtime stages) and internal/stage itself (the executor's own
// implementation is where these calls are expected to live).
func findRawLaunchCalls(t *testing.T, repoRoot string) map[string]int {
	t.Helper()
	found := map[string]int{}
	err := filepath.Walk(repoRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			base := info.Name()
			if base == ".git" || base == "dist" || base == "bin" || base == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(repoRoot, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "internal/stage/stage.go" || strings.HasPrefix(rel, "internal/stage/") {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		count := 0
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") {
				continue
			}
			count += len(rawLaunchCallRE.FindAllString(line, -1))
		}
		if count > 0 {
			found[rel] = count
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", repoRoot, err)
	}
	return found
}

func repoRootFromTestFile(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..")
}
