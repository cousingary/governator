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
		// Four raw launches remain: the cgroup-direct and degraded primitives,
		// plus defensive primitivePath fallbacks used only when a test
		// constructs a Scope directly without a real sealed handle. Production
		// systemd-run/unshare launches now use sealed handles.
		"internal/containment/descendants.go": 4,
		// The sealed-handle `/proc/self/fd/<n>` launch mechanism itself
		// (report §S4 "Required correction": "launch via fexecve or
		// /proc/self/fd/<n>") — foundational launch primitive, not a bypass.
		"internal/toolregistry/handle.go": 1,
		// Tool-version resolution probes (pre-launch identity resolution
		// against an already-registry-verified binary, run in a disposable
		// scratch cwd with a bounded timeout) — the exact same shape as
		// doctor.go's --version/--help probes above, not stage execution
		// against contract-declared authority. Reclassified from
		// migrationPending (S1/S4/S6 gap-closure session, 2026-07-16):
		// StageExecutor's descendant-scope/Landlock/network envelope has no
		// meaningful application to "run the already-verified binary with
		// --version and read stdout."
		"internal/agents/resolution.go": 1,
		// Governor's OWN best-effort pre-delete recovery snapshot hook,
		// invoked from the interactive PreToolUse gate plane before any
		// contract/RunID/job exists at all — there is no "stage" or
		// "authority" to route through StageExecutor here, and a failure is
		// explicitly non-blocking by design (see the doc comment on
		// PreflightSnapshotIfDelete). Reclassified from migrationPending
		// (S1/S4/S6 gap-closure session, 2026-07-16).
		"internal/runtime/gate.go": 1,
		// runner.shell() -- git worktree add/remove, branch delete, cp
		// --reflink for workspace setup/teardown. Verified (S1/S4/S6
		// gap-closure session, 2026-07-16): every call site is git plumbing,
		// same primitive category as internal/gitplumb/gitplumb.go above,
		// not validator/backend command execution -- the ratchet's original
		// comment mischaracterized this entry. The actual validator/
		// cleanup-validator execution path (runtime.shellStage) was already
		// fully migrated to stageexec.NewExecutor().Run in the same commit
		// that added this ratchet (verified: shellStage contains zero raw
		// exec.Command/CommandContext calls, only the stageexec.Executor
		// call).
		"internal/runner/runner.go": 1,
		// runtime.shell() -- identical git-plumbing-only helper (git
		// rev-parse/reset --hard/clean -fd/revert), same reasoning as
		// runner.go above. Reclassified from migrationPending (S1/S4/S6
		// gap-closure session, 2026-07-16).
		"internal/runtime/runtime.go": 1,
		// agents.LaunchCommand: the backend's sealed-copy-or-fd launch
		// primitive, now the foundational mechanism agents.LaunchStaged
		// plugs into stage.Executor.Run via a CommandFactory (Sol redteam
		// v7 S1 gap-closure, 2026-07-16) -- deliberately reused rather than
		// rewritten, exactly the same "foundational launch primitive a
		// CommandFactory invokes, not a bypass of it" role internal/
		// toolregistry/handle.go's entry above already has. 2 of the
		// file's 5 raw calls are probeVersion (permanently-legitimate
		// read-only version probes, same as agents/resolution.go above);
		// the other 3 are LaunchCommand's own sealed/fd exec sites, invoked
		// exclusively through stage.Executor.Run's CommandFactory when a
		// Scope is present (agents.defaultExecutor / runner.
		// LocalWorktreeRunner.executor both route through agents.
		// LaunchStaged now) or directly for the no-Scope case (doctor
		// probes, direct adapter tests -- nothing governed to route
		// through StageExecutor). Reclassified from migrationPending
		// (S1/S4/S6 gap-closure session, 2026-07-16): this was the last
		// entry there, closing Category B.
		"internal/agents/handle.go": 5,
	}

	// Category B: known S1/S4/S6 migration gaps — real governed-stage
	// launches that have NOT yet been routed through StageExecutor. Each is
	// tracked in the findings log; this list exists so the count cannot grow
	// further while those sessions are pending, and must shrink (ideally to
	// zero, with the file's entry deleted) as each is migrated.
	//
	// Empty as of the S1/S4/S6 gap-closure session (2026-07-16): every real
	// governed-stage launch this ratchet originally flagged here
	// (agents/handle.go's LaunchCommand, runner/runner.go and runtime/
	// runtime.go's shell(), assay/assay.go's Assayer invocation) has either
	// been migrated to route through internal/stage.Executor, or was
	// investigated and found to be a permanently-legitimate non-stage call
	// (git plumbing, read-only probes) and moved to the permanent bucket
	// above with its reasoning recorded there. internal/runner/docker.go's
	// `docker run` is the one deliberate, documented exception (see its
	// permanent-bucket entry above) -- not a migration gap, a considered
	// decision not to migrate.
	migrationPending := map[string]int{}

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
