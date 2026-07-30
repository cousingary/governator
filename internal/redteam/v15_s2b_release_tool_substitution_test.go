//go:build redteam

package redteam

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// v15_s2b_release_tool_substitution_test.go is the Sol15 rc8-upg15 Session
// 2b corpus (agents/governator-sol-upgrade15-rc8-plan.md Session 2b,
// agents/governator-sol-upgrade15.md "Release tool substitution"): manifest
// cases 354-361. Every test drives the REAL scripts/release_toolset.py and
// scripts/release_tier_pipeline.sh as OS subprocesses against synthetic
// fixtures, never an internal Go function -- the sibling pattern
// internal/redteam/v13_s4_release_tool_trust_test.go established for
// release_toolset.py alone, and internal/redteam/v11_s3_release_checkpoint_test.go
// established for release_tier_pipeline.sh.
//
// Cases 354-359 (Sol's six "tool substitution" attacks, table-driven over
// the widened ten-tool set: go, python3, git, sha256sum, tar, bash, gzip,
// minisign, date, awk) prove the PRIMARY mechanism scripts/release.sh relies
// on for every one of these tools: scripts/release_toolset.py's --toolbin
// builds a private directory of policy-verified symlinks, and
// `export PATH="$TOOLBIN_DIR"` (release.sh) makes that directory the ONLY
// place a bare command name can resolve from. Each test proves this two
// ways: a hostile directory placed ahead of the toolbin on PATH DOES reach a
// loud fake (the non-vacuous control, proving the harness can actually
// detect the vulnerability it exists to catch), while PATH narrowed to the
// toolbin alone -- release.sh's real configuration -- never does.
//
// Cases 360-361 exercise this session's NEW code: scripts/release_tier_pipeline.sh
// now re-verifies the approved toolset (scripts/release_toolset.py --verify)
// immediately before AND after every tier it actually runs, closing the
// window a single pipeline-wide preflight check cannot -- a same-UID
// substitution between preflight and this tier, or during the tier's own
// execution.

func s2bRepoRoot(t *testing.T) string { return repoRootForBundleTests(t) }

func s2bToolsetScript(t *testing.T) string {
	return filepath.Join(s2bRepoRoot(t), "scripts", "release_toolset.py")
}

func s2bTierPipelineScript(t *testing.T) string {
	return filepath.Join(s2bRepoRoot(t), "scripts", "release_tier_pipeline.sh")
}

// s2bFakeTool writes a loud, always-successful fake executable named
// exactly `name`: it records its own invocation into `sentinel` before
// exiting 0, so "never invoked" is a positive assertion about an absent
// file, never merely an absence of failure.
func s2bFakeTool(t *testing.T, dir, name, sentinel string) {
	t.Helper()
	path := filepath.Join(dir, name)
	body := "#!/bin/sh\necho fake-" + name + "-executed >>'" + sentinel + "'\nexit 0\n"
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
}

// s2bProbeArgs returns a read-only, version-reporting invocation for each
// tool -- "version" for go (a subcommand, not a flag), "-v" for minisign,
// "--version" for everything else.
func s2bProbeArgs(tool string) string {
	switch tool {
	case "go":
		return "version"
	case "minisign":
		return "-v"
	default:
		return "--version"
	}
}

// s2bHermeticToolSet is release.sh's real pattern: ONE toolbin holding
// every approved tool together, never a single-tool one. This matters
// beyond realism -- on this host /home/lam/bin/git (the policy-approved
// git) is itself a `#!/usr/bin/env bash` wrapper script, so a toolbin
// containing git alone (missing env/bash) fails closed on its own shebang
// once PATH is narrowed to it, which would be a fixture-construction bug,
// not a Sol15 defect.
var s2bHermeticToolSet = []string{"go", "python3", "git", "bash", "sha256sum", "tar", "gzip", "minisign", "date", "awk", "env"}

// s2bBuildFullToolbin resolves and hashes every tool in s2bHermeticToolSet
// on this host, writes the matching policy, and builds one real,
// policy-verified toolbin covering all of them -- mirroring
// scripts/release.sh's actual single hermetic toolbin. The toolbin's mode
// 0500 (release_toolset.py's own enforcement primitive) blocks
// t.TempDir()'s RemoveAll cleanup, so this registers a cleanup that
// restores write access first (t.Cleanup runs LIFO, so this -- registered
// after t.TempDir()'s own -- unlocks the directory before TempDir's
// removal runs).
func s2bBuildFullToolbin(t *testing.T, work string) (toolbin, toolsetPath string) {
	t.Helper()
	var policyLines strings.Builder
	policyLines.WriteString("tools:\n")
	for _, tool := range s2bHermeticToolSet {
		resolved, err := exec.LookPath(tool)
		if err != nil {
			t.Skipf("%s is not installed on this host -- cannot build the full hermetic toolbin without it (standing rule 12)", tool)
		}
		policyLines.WriteString("  " + tool + ":\n    path: " + resolved + "\n    sha256: " + fileSHA256Hex(t, resolved) + "\n")
	}
	policyPath := filepath.Join(work, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte(policyLines.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	toolbin = filepath.Join(work, "toolbin")
	toolsetPath = filepath.Join(work, "toolset.json")
	preflight := exec.Command("python3", s2bToolsetScript(t), "--policy", policyPath, "--out", toolsetPath, "--toolbin", toolbin, "--tools", strings.Join(s2bHermeticToolSet, ","))
	if out, err := preflight.CombinedOutput(); err != nil {
		t.Fatalf("preflight full toolbin: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = os.Chmod(toolbin, 0o700) })
	return toolbin, toolsetPath
}

// s2bAssertToolbinIsHermetic is the shared table-driven body for cases
// 354-359: build the real, policy-verified toolbin, and prove a fake of
// `tool`'s name sitting on a hostile PATH is reachable ONLY when that
// hostile directory precedes the toolbin (the control) and never when PATH
// is narrowed to the toolbin alone (release.sh's actual configuration).
func s2bAssertToolbinIsHermetic(t *testing.T, tool string) {
	t.Helper()
	if _, err := exec.LookPath(tool); err != nil {
		t.Skipf("%s is not installed on this host -- cannot reproduce this attack without it (standing rule 12)", tool)
	}

	work := t.TempDir()
	hostile := filepath.Join(work, "hostile-bin")
	if err := os.MkdirAll(hostile, 0o755); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(work, "sentinel")
	s2bFakeTool(t, hostile, tool, sentinel)

	toolbin, _ := s2bBuildFullToolbin(t, work)

	probe := tool + " " + s2bProbeArgs(tool) + " >/dev/null 2>&1"
	run := func(pathValue string) error {
		c := exec.Command("/bin/sh", "-c", probe)
		c.Env = []string{"PATH=" + pathValue}
		out, err := c.CombinedOutput()
		if err != nil {
			return fmt.Errorf("%v: %s", err, out)
		}
		return nil
	}

	// Non-vacuous control: hostile-first PATH must reach the fake.
	if err := run(hostile + ":" + toolbin); err != nil {
		t.Fatalf("control run (hostile-first PATH) unexpectedly failed for %s: %v", tool, err)
	}
	if _, statErr := os.Stat(sentinel); os.IsNotExist(statErr) {
		t.Fatalf("control run did not reach the fake %s -- this test cannot distinguish secure from insecure PATH ordering", tool)
	}
	if err := os.Remove(sentinel); err != nil {
		t.Fatal(err)
	}

	// The real property under test: PATH narrowed to the verified toolbin
	// alone (release.sh's real `export PATH="$TOOLBIN_DIR"`) never reaches
	// the fake, however far away on the filesystem it sits.
	if err := run(toolbin); err != nil {
		t.Fatalf("real %s via the hermetic toolbin-only PATH failed: %v", tool, err)
	}
	if _, statErr := os.Stat(sentinel); !os.IsNotExist(statErr) {
		t.Fatalf("fake %s was invoked even though PATH was narrowed to the verified toolbin only", tool)
	}
}

func TestV15Case354FakeGoReturningSuccessWithoutCompilingIsNeverInvoked(t *testing.T) {
	t.Run("go", func(t *testing.T) { s2bAssertToolbinIsHermetic(t, "go") })
}

func TestV15Case355FakePython3WritingFabricatedEvidenceIsNeverInvoked(t *testing.T) {
	t.Run("python3", func(t *testing.T) { s2bAssertToolbinIsHermetic(t, "python3") })
}

func TestV15Case356FakeGitReportingAttackerSelectedCommitIsNeverInvoked(t *testing.T) {
	t.Run("git", func(t *testing.T) { s2bAssertToolbinIsHermetic(t, "git") })
}

func TestV15Case357FakeSha256sumApprovingInvalidHashesIsNeverInvoked(t *testing.T) {
	t.Run("sha256sum", func(t *testing.T) { s2bAssertToolbinIsHermetic(t, "sha256sum") })
}

// TestV15Case358FakeTarInjectingExtraArchiveMembersIsNeverInvoked also
// covers gzip -- Sol's widened-set instruction folds tar's usual archive
// partner into the same table.
func TestV15Case358FakeTarInjectingExtraArchiveMembersIsNeverInvoked(t *testing.T) {
	for _, tool := range []string{"tar", "gzip"} {
		tool := tool
		t.Run(tool, func(t *testing.T) { s2bAssertToolbinIsHermetic(t, tool) })
	}
}

// TestV15Case359FakeBashAlteringCommandExecutionIsNeverInvoked also covers
// minisign, date and awk -- the remainder of Sol's widened tool set.
func TestV15Case359FakeBashAlteringCommandExecutionIsNeverInvoked(t *testing.T) {
	for _, tool := range []string{"bash", "minisign", "date", "awk"} {
		tool := tool
		t.Run(tool, func(t *testing.T) { s2bAssertToolbinIsHermetic(t, tool) })
	}
}

// s2bRunTierPipeline runs the real release_tier_pipeline.sh with the given
// --policy/--toolset-json (this session's new per-tier re-verification
// flags) plus every explicit --*-bin flag release.sh itself always supplies.
func s2bRunTierPipeline(t *testing.T, stateDir, identityFile, spec, policy, toolsetJSON string) (string, error) {
	t.Helper()
	pythonBin, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not installed on this host")
	}
	bashBin, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not installed on this host")
	}
	sha256sumBin, err := exec.LookPath("sha256sum")
	if err != nil {
		t.Skip("sha256sum not installed on this host")
	}
	dateBin, err := exec.LookPath("date")
	if err != nil {
		t.Skip("date not installed on this host")
	}
	awkBin, err := exec.LookPath("awk")
	if err != nil {
		t.Skip("awk not installed on this host")
	}
	cmd := exec.Command("bash", s2bTierPipelineScript(t), "run",
		"--state-dir", stateDir, "--identity-file", identityFile, "--spec", spec,
		"--python-bin", pythonBin, "--bash-bin", bashBin, "--sha256sum-bin", sha256sumBin,
		"--date-bin", dateBin, "--awk-bin", awkBin,
		"--policy", policy, "--toolset-json", toolsetJSON,
	)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// TestV15Case360ToolExecutableReplacedAfterPreflightFailsTheTier: a
// policy-approved tool's file is overwritten in place (same path, different
// bytes) AFTER scripts/release_toolset.py's preflight recorded its hash.
// The tier must fail BEFORE its command ever runs -- release_tier_pipeline.sh's
// new pre-check catches the mismatch and never invokes "$BASH_BIN -c $CMD"
// at all.
func TestV15Case360ToolExecutableReplacedAfterPreflightFailsTheTier(t *testing.T) {
	work := t.TempDir()
	toolPath := filepath.Join(work, "tool")
	if err := os.WriteFile(toolPath, []byte("#!/bin/sh\necho original\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(work, "policy.yaml")
	policyBody := "tools:\n  tool:\n    path: " + toolPath + "\n    sha256: " + fileSHA256Hex(t, toolPath) + "\n"
	if err := os.WriteFile(policyPath, []byte(policyBody), 0o644); err != nil {
		t.Fatal(err)
	}
	toolsetPath := filepath.Join(work, "toolset.json")
	preflight := exec.Command("python3", s2bToolsetScript(t), "--policy", policyPath, "--out", toolsetPath, "--tools", "tool")
	if out, err := preflight.CombinedOutput(); err != nil {
		t.Fatalf("preflight toolset: %v\n%s", err, out)
	}

	// Replace the tool's content AFTER preflight -- same path, different
	// bytes, Sol's "tool executable replaced after preflight" attack.
	if err := os.WriteFile(toolPath, []byte("#!/bin/sh\necho substituted\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	stateDir := filepath.Join(work, "state")
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	identityFile := s3InitAttempt(t, stateDir, s3DefaultIdentity(), "attempt-case360")

	marker := filepath.Join(work, "ran.marker")
	spec := filepath.Join(work, "spec.tsv")
	log := filepath.Join(work, "probe.log")
	if err := os.WriteFile(spec, []byte("probe\t"+log+"\ttouch "+marker+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := s2bRunTierPipeline(t, stateDir, identityFile, spec, policyPath, toolsetPath)
	if err == nil {
		t.Fatalf("expected the tier to FAIL when a policy-approved tool changed after preflight, got success:\n%s", out)
	}
	if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
		t.Fatal("tier command ran (marker exists) even though the tool identity check should have failed the tier BEFORE execution")
	}
	ckptRaw, err2 := os.ReadFile(filepath.Join(stateDir, "probe.json"))
	if err2 != nil {
		t.Fatalf("expected a checkpoint recording the failed tier: %v", err2)
	}
	if !strings.Contains(string(ckptRaw), `"tool_identity_pre": "FAIL"`) {
		t.Fatalf("expected checkpoint to record tool_identity_pre FAIL, got:\n%s", ckptRaw)
	}
	if !strings.Contains(string(ckptRaw), `"result": "FAIL"`) {
		t.Fatalf("expected checkpoint result FAIL, got:\n%s", ckptRaw)
	}
}

// TestV15Case361SymlinkedToolTargetChangedAfterResolutionFailsTheTier: the
// policy names a SYMLINK; after scripts/release_toolset.py's preflight
// resolves and hashes its target, the symlink is re-pointed at a different
// target (same policy path, different resolved bytes) -- Sol's "symlinked
// tool target changed after resolution" attack. Must fail the tier before
// its command ever runs, same as case 360.
func TestV15Case361SymlinkedToolTargetChangedAfterResolutionFailsTheTier(t *testing.T) {
	work := t.TempDir()
	targetA := filepath.Join(work, "target-a")
	targetB := filepath.Join(work, "target-b")
	if err := os.WriteFile(targetA, []byte("#!/bin/sh\necho a\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(targetB, []byte("#!/bin/sh\necho b\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(work, "tool-link")
	if err := os.Symlink(targetA, link); err != nil {
		t.Fatal(err)
	}

	policyPath := filepath.Join(work, "policy.yaml")
	policyBody := "tools:\n  tool:\n    path: " + link + "\n    sha256: " + fileSHA256Hex(t, targetA) + "\n"
	if err := os.WriteFile(policyPath, []byte(policyBody), 0o644); err != nil {
		t.Fatal(err)
	}
	toolsetPath := filepath.Join(work, "toolset.json")
	preflight := exec.Command("python3", s2bToolsetScript(t), "--policy", policyPath, "--out", toolsetPath, "--tools", "tool")
	if out, err := preflight.CombinedOutput(); err != nil {
		t.Fatalf("preflight toolset: %v\n%s", err, out)
	}

	// Re-target the symlink AFTER resolution.
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(targetB, link); err != nil {
		t.Fatal(err)
	}

	stateDir := filepath.Join(work, "state")
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	identityFile := s3InitAttempt(t, stateDir, s3DefaultIdentity(), "attempt-case361")

	marker := filepath.Join(work, "ran.marker")
	spec := filepath.Join(work, "spec.tsv")
	log := filepath.Join(work, "probe.log")
	if err := os.WriteFile(spec, []byte("probe\t"+log+"\ttouch "+marker+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := s2bRunTierPipeline(t, stateDir, identityFile, spec, policyPath, toolsetPath)
	if err == nil {
		t.Fatalf("expected the tier to FAIL when a policy-approved tool's symlink target changed after resolution, got success:\n%s", out)
	}
	if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
		t.Fatal("tier command ran (marker exists) even though the retargeted symlink should have failed the tier BEFORE execution")
	}
	ckptRaw, err2 := os.ReadFile(filepath.Join(stateDir, "probe.json"))
	if err2 != nil {
		t.Fatalf("expected a checkpoint recording the failed tier: %v", err2)
	}
	if !strings.Contains(string(ckptRaw), `"tool_identity_pre": "FAIL"`) {
		t.Fatalf("expected checkpoint to record tool_identity_pre FAIL, got:\n%s", ckptRaw)
	}
}
