package runtime

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cousingary/governator/internal/agents"
	"github.com/cousingary/governator/internal/config"
	"github.com/cousingary/governator/internal/contracts"
	"github.com/cousingary/governator/internal/policy"
	"github.com/cousingary/governator/internal/prompts"
	"github.com/cousingary/governator/internal/runner"
)

// writePromptVersion writes a single prompt file at <root>/<agent>/<mode>/<ver>.md
// so a test can control exactly which version prompts.Resolve selects.
func writePromptVersion(t *testing.T, root, agent, mode, ver string) {
	t.Helper()
	dir := filepath.Join(root, agent, mode)
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ver+".md"), []byte("test prompt "+ver), 0644); err != nil {
		t.Fatal(err)
	}
}

// replayEnv stands up the same fixture/TestApprovedReplayRedactionAndRollback
// environment: a git root, a fake claude backend, an isolated GOV_HOME, and a
// prompt registry with one version. Each Sol-Critical-1 regression test starts
// from this baseline, runs an approving first run, then mutates one
// trust-bearing input and proves the second run does NOT replay the stale
// approval.
func replayEnv(t *testing.T) (root, bin, home, promptRoot string) {
	t.Helper()
	root, bin = fixture(t)
	home = t.TempDir()
	t.Setenv("GOV_HOME", home)
	t.Setenv("GOV_CLAUDE_BIN", bin)
	t.Setenv("FAKE_ALLOWED_COMMAND", "1")
	promptRoot = t.TempDir()
	writePromptVersion(t, promptRoot, "claude-code", "surgeon", "v007")
	t.Setenv("GOV_PROMPTS", promptRoot)
	return root, bin, home, promptRoot
}

func runOnce(t *testing.T, root string) RunRecord {
	t.Helper()
	r, err := New().Run(context.Background(), contract(root))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return r
}

// TestExecutionIdentityHashSensitiveToEveryField proves each trust-bearing
// input contributes to the replay key: flipping one field (and only that
// field) mints a different digest. This is the unit-level guarantee behind
// every integration regression below — if two identities differing in any one
// field ever hashed equally, a stale approval could replay against a changed
// environment (Sol Critical 1).
func TestExecutionIdentityHashSensitiveToEveryField(t *testing.T) {
	base := ExecutionIdentity{
		ContractHash: "h1", ApprovedHead: "g1", ConfigHash: "c1",
		ProtectedManifestHash: "p1", OrgPolicyHash: "o1", ProjectDoctrineHash: "d1",
		PromptVersion: "v007", PromptChecksum: "s1", ValidatorSetHash: "vs1",
		AssayerProfileHash: "ap1", BackendAdapter: "claude-code", BackendAdapterVersion: "av1",
		BackendBinaryPath: "/bin/claude", BackendBinarySHA256: "b1", ModelID: "claude-code",
		CapabilityAttestID: "att1", RunnerConfigHash: "rc1", GovernatorVersion: "gv1",
	}
	baseHash := base.Hash()
	if baseHash == "" {
		t.Fatal("base hash empty")
	}
	mutations := map[string]func(*ExecutionIdentity){
		"ContractHash":          func(e *ExecutionIdentity) { e.ContractHash = "h2" },
		"ApprovedHead":          func(e *ExecutionIdentity) { e.ApprovedHead = "g2" },
		"ConfigHash":            func(e *ExecutionIdentity) { e.ConfigHash = "c2" },
		"ProtectedManifestHash": func(e *ExecutionIdentity) { e.ProtectedManifestHash = "p2" },
		"OrgPolicyHash":         func(e *ExecutionIdentity) { e.OrgPolicyHash = "o2" },
		"ProjectDoctrineHash":   func(e *ExecutionIdentity) { e.ProjectDoctrineHash = "d2" },
		"PromptVersion":         func(e *ExecutionIdentity) { e.PromptVersion = "v008" },
		"PromptChecksum":        func(e *ExecutionIdentity) { e.PromptChecksum = "s2" },
		"ValidatorSetHash":      func(e *ExecutionIdentity) { e.ValidatorSetHash = "vs2" },
		"AssayerProfileHash":    func(e *ExecutionIdentity) { e.AssayerProfileHash = "ap2" },
		"BackendAdapter":        func(e *ExecutionIdentity) { e.BackendAdapter = "codex" },
		"BackendAdapterVersion": func(e *ExecutionIdentity) { e.BackendAdapterVersion = "av2" },
		"BackendBinaryPath":     func(e *ExecutionIdentity) { e.BackendBinaryPath = "/bin/other" },
		"BackendBinarySHA256":   func(e *ExecutionIdentity) { e.BackendBinarySHA256 = "b2" },
		"ModelID":               func(e *ExecutionIdentity) { e.ModelID = "codex" },
		"CapabilityAttestID":    func(e *ExecutionIdentity) { e.CapabilityAttestID = "att2" },
		"RunnerConfigHash":      func(e *ExecutionIdentity) { e.RunnerConfigHash = "rc2" },
		"GovernatorVersion":     func(e *ExecutionIdentity) { e.GovernatorVersion = "gv2" },
	}
	for name, mut := range mutations {
		flipped := base
		mut(&flipped)
		if h := flipped.Hash(); h == baseHash {
			t.Errorf("flipping %s did not change the identity hash (both %s)", name, baseHash)
		}
	}
}

// TestRunnerConfigHashesLocalConfig pins that runnerConfig (the input to
// ExecutionIdentity.RunnerConfigHash) reflects Contract.Local the same way it
// already reflected Contract.Docker — otherwise a tightened
// local.require_complete_transcript or local.output_cap_bytes setting could
// silently replay a stale approval minted under a looser one (Sol High 11).
func TestRunnerConfigHashesLocalConfig(t *testing.T) {
	base := contracts.Contract{}
	tightened := contracts.Contract{Local: &contracts.LocalRunnerConfig{RequireCompleteTranscript: true}}
	capped := contracts.Contract{Local: &contracts.LocalRunnerConfig{OutputCapBytes: 1024}}

	baseHash := hashJSON(runnerConfig(base, nil, ""))
	tightenedHash := hashJSON(runnerConfig(tightened, nil, ""))
	cappedHash := hashJSON(runnerConfig(capped, nil, ""))

	if baseHash == tightenedHash {
		t.Fatal("setting local.require_complete_transcript did not change runnerConfig's hash")
	}
	if baseHash == cappedHash {
		t.Fatal("setting local.output_cap_bytes did not change runnerConfig's hash")
	}
	if tightenedHash == cappedHash {
		t.Fatal("two distinct local configs hashed equally")
	}
}

// TestReplayPositiveIdenticalEnvironmentReplays proves the core invariant the
// identity model preserves: with nothing changed between runs, the second run
// replays the first approval rather than re-invoking the agent. This is the
// "do not disable replay" non-goal (Sol §11) — replay still works, it just can
// no longer bypass current trust gates.
func TestReplayPositiveIdenticalEnvironmentReplays(t *testing.T) {
	root, _, _, _ := replayEnv(t)
	r1 := runOnce(t, root)
	if r1.Status != "APPROVED" {
		t.Fatalf("first run: %s: %s", r1.Status, r1.Message)
	}
	r2 := runOnce(t, root)
	if !r2.Replayed {
		t.Fatal("identical environment should replay, got a fresh run")
	}
	if r2.ID != r1.ID {
		t.Fatalf("expected replay of %s, got %s", r1.ID, r2.ID)
	}
}

// bareBackendReplayEnv is replayEnv's sibling for the Sol Finding 5 /
// Session 2 corpus #2 reproduction. replayEnv installs the fake backend at an
// arbitrary absolute path and points GOV_CLAUDE_BIN straight at it — which
// never exercises the bug, since os.ReadFile(absolutePath) works whether or
// not PATH resolution is fixed. bareBackendReplayEnv instead leaves
// GOV_CLAUDE_BIN unset (config.BackendBin("claude-code") then returns the
// built-in bare name "claude" — the exact `backends: pi: bin: pi` shape the
// finding describes) and installs the fake backend under that bare name on
// PATH, so identity/replay must actually resolve it through exec.LookPath.
func bareBackendReplayEnv(t *testing.T) (root, binPath, home, promptRoot string) {
	t.Helper()
	root, fakeBin := fixture(t)
	script, err := os.ReadFile(fakeBin)
	if err != nil {
		t.Fatal(err)
	}
	binDir := t.TempDir()
	binPath = filepath.Join(binDir, "claude")
	if err := os.WriteFile(binPath, script, 0755); err != nil {
		t.Fatal(err)
	}
	// Prepend (not replace): fixture()'s git commands already ran, but Run()
	// itself still shells out to git for worktree creation, and prepending
	// guarantees our fake "claude" is found first even if a real one is also
	// on PATH somewhere else on the host.
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	home = t.TempDir()
	t.Setenv("GOV_HOME", home)
	t.Setenv("FAKE_ALLOWED_COMMAND", "1")
	promptRoot = t.TempDir()
	writePromptVersion(t, promptRoot, "claude-code", "surgeon", "v007")
	t.Setenv("GOV_PROMPTS", promptRoot)
	return root, binPath, home, promptRoot
}

// TestSol3ReplayInvalidatedByBarePathBackendSwap is the Session 2 / Sol
// Finding 5 corpus #2 reproduction. Before the fix, computeExecutionIdentity
// hashed config.BackendBin("claude-code") (the bare string "claude") via
// os.ReadFile directly — a relative filename never resolves through PATH, so
// this always produced the fixed "unreadable:claude" sentinel regardless of
// which binary "claude" actually pointed to on PATH. A prior APPROVED run
// therefore replayed forever even after the bare-name-resolved backend was
// replaced with a different program at the same PATH location — the
// replacement was never launched. agents.ResolvePath fixes this by resolving
// through exec.LookPath before hashing, so the swap must mint a fresh
// identity and the run must NOT replay.
func TestSol3ReplayInvalidatedByBarePathBackendSwap(t *testing.T) {
	root, binPath, _, _ := bareBackendReplayEnv(t)
	r1 := runOnce(t, root)
	if r1.Status != "APPROVED" {
		t.Fatalf("first run: %s: %s", r1.Status, r1.Message)
	}
	orig, err := os.ReadFile(binPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binPath, append(orig, []byte("\n# swapped bare-path binary for Sol Finding 5 replay test\n")...), 0755); err != nil {
		t.Fatal(err)
	}
	r2 := runOnce(t, root)
	if r2.Replayed {
		t.Fatal("Sol Finding 5 regression: a bare-name PATH-resolved backend was replaced at the same name/path and the run still replayed the stale approval")
	}
	if r2.ID == r1.ID {
		t.Fatalf("expected a fresh run id after the bare-path backend swap, got the stale approval %s", r1.ID)
	}
	if r2.Status != "APPROVED" {
		t.Fatalf("re-run with equivalent binary should still approve: %s: %s", r2.Status, r2.Message)
	}
}

// TestReplayInvalidatedByBackendBinaryChange reproduces the Sol reproduction
// (Critical 1 consequence): a prior approval must NOT be reused after the
// backend binary content changes. The replay probe now hashes the executable,
// so a swapped/modified binary mints a different identity and the agent re-runs.
func TestReplayInvalidatedByBackendBinaryChange(t *testing.T) {
	root, bin, _, _ := replayEnv(t)
	r1 := runOnce(t, root)
	if r1.Status != "APPROVED" {
		t.Fatalf("first run: %s: %s", r1.Status, r1.Message)
	}
	// Append a harmless comment to the fake backend: behavior is identical
	// (still produces valid output) but the SHA-256 of the executable changes,
	// which the identity captures. Appended at the tail so the #!/bin/sh
	// shebang stays the first line (prepending would break exec).
	orig, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, append(orig, []byte("\n# swapped binary for replay test\n")...), 0755); err != nil {
		t.Fatal(err)
	}
	r2 := runOnce(t, root)
	if r2.Replayed {
		t.Fatal("replay fired after backend binary content changed (Critical 1 regression)")
	}
	if r2.ID == r1.ID {
		t.Fatalf("expected a fresh run id, got the stale approval %s", r1.ID)
	}
	if r2.Status != "APPROVED" {
		t.Fatalf("re-run with equivalent binary should still approve: %s: %s", r2.Status, r2.Message)
	}
}

// TestReplayInvalidatedByPromptVersionChange proves a prior approval is NOT
// reused after the resolved prompt version changes. The prompt checksum is part
// of the identity, so deploying a new prompt (v008) invalidates replay even
// though the contract itself is unchanged.
func TestReplayInvalidatedByPromptVersionChange(t *testing.T) {
	root, _, _, promptRoot := replayEnv(t)
	r1 := runOnce(t, root)
	if r1.Status != "APPROVED" {
		t.Fatalf("first run: %s: %s", r1.Status, r1.Message)
	}
	// Deploy a newer prompt version. prompts.Resolve selects the highest, so
	// v008 supersedes v007 on the next run, changing the identity.
	writePromptVersion(t, promptRoot, "claude-code", "surgeon", "v008")
	r2 := runOnce(t, root)
	if r2.Replayed {
		t.Fatal("replay fired after prompt version changed (Critical 1 regression)")
	}
	if r2.ID == r1.ID {
		t.Fatalf("expected a fresh run id, got the stale approval %s", r1.ID)
	}
	if r2.PromptVersion != "v008" {
		t.Fatalf("expected re-run to resolve v008, got %q", r2.PromptVersion)
	}
}

// TestReplayInvalidatedByConfigChange proves a prior approval is NOT reused
// after the effective configuration changes. The whole loaded config is hashed
// into the identity, so any operator-declared field change (here, the daily
// spend cap) invalidates replay.
func TestReplayInvalidatedByConfigChange(t *testing.T) {
	root, _, home, _ := replayEnv(t)
	cfgPath := filepath.Join(home, "config.yaml")
	// Run 1: an explicit (but benign) config so the baseline hash is fixed by
	// this file rather than whatever the ambient home happens to contain.
	if err := os.WriteFile(cfgPath, []byte("spend:\n  daily_cap_usd: 0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_CONFIG", cfgPath)
	r1 := runOnce(t, root)
	if r1.Status != "APPROVED" {
		t.Fatalf("first run: %s: %s", r1.Status, r1.Message)
	}
	// Change a config field. daily_cap_usd stays generous (the test run is
	// cheap) so the spend gate still passes — the point is the identity hash
	// changed, not that the run is blocked.
	if err := os.WriteFile(cfgPath, []byte("spend:\n  daily_cap_usd: 100\n"), 0644); err != nil {
		t.Fatal(err)
	}
	r2 := runOnce(t, root)
	if r2.Replayed {
		t.Fatal("replay fired after configuration changed (Critical 1 regression)")
	}
	if r2.ID == r1.ID {
		t.Fatalf("expected a fresh run id, got the stale approval %s", r1.ID)
	}
}

// TestReplayInvalidatedByOrgPolicyDeny reproduces the headline Sol
// reproduction: an org policy DENY added AFTER an approval must NOT be
// bypassed by replay. With the replay probe moved past the policy gate, the
// DENY quarantines the second run instead of returning the stale APPROVED.
func TestReplayInvalidatedByOrgPolicyDeny(t *testing.T) {
	root, _, home, _ := replayEnv(t)
	cfgPath := filepath.Join(home, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("spend:\n  daily_cap_usd: 0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_CONFIG", cfgPath)
	r1 := runOnce(t, root)
	if r1.Status != "APPROVED" {
		t.Fatalf("first run: %s: %s", r1.Status, r1.Message)
	}
	// Add an org-policy DENY rule for the claude-code backend. This is the
	// exact mutation Sol used: policy changed to forbid the backend after an
	// approval existed.
	deny := "spend:\n  daily_cap_usd: 0\npolicy_rules:\n  - id: deny-claude-test\n    when:\n      - {field: backend, op: eq, value: claude-code}\n    verdict: DENY\n    reason: \"test: deny claude-code after approval\"\n"
	if err := os.WriteFile(cfgPath, []byte(deny), 0644); err != nil {
		t.Fatal(err)
	}
	r2 := runOnce(t, root)
	if r2.Replayed {
		t.Fatal("replay fired despite an org-policy DENY added after approval (Critical 1 regression)")
	}
	if r2.Status != "QUARANTINED" {
		t.Fatalf("expected the DENY to quarantine, got %s: %s", r2.Status, r2.Message)
	}
	if r2.FailureTaxonomy != policyDeniedTaxonomy {
		t.Fatalf("expected POLICY_DENIED taxonomy, got %q", r2.FailureTaxonomy)
	}
}

// TestConfigHashReflectsConfigChanges is a focused unit check that the
// effective-config hash — one identity input — actually changes when an
// operator-declared field changes, and stays stable when it doesn't. Guards
// against a future refactor accidentally dropping a field from the hash.
func TestConfigHashReflectsConfigChanges(t *testing.T) {
	a := config.BuiltIn()
	hA := a.Hash()
	// Identical config => identical hash.
	if a2 := config.BuiltIn(); a2.Hash() != hA {
		t.Fatal("identical config produced a different hash")
	}
	// A changed spend cap => different hash.
	b := a
	b.Spend.DailyCapUSD = 42
	if b.Hash() == hA {
		t.Fatal("changing spend.daily_cap_usd did not change the config hash")
	}
	// A changed org policy rule => different hash.
	c := a
	c.PolicyRules = []policy.ConditionRule{{ID: "x", When: []policy.Condition{{Field: policy.FactBackend, Op: "eq", Value: "glm"}}, Verdict: policy.VerdictDeny, Reason: "r"}}
	if c.Hash() == hA {
		t.Fatal("adding an org policy rule did not change the config hash")
	}
}

// TestComputeIdentityCapturesBackendBinary proves the identity's backend binary
// hash tracks the actual executable content, so a binary swap is detectable
// without a full end-to-end run.
func TestComputeIdentityCapturesBackendBinary(t *testing.T) {
	binA := filepath.Join(t.TempDir(), "fake")
	if err := os.WriteFile(binA, []byte("#!/bin/sh\necho a\n"), 0755); err != nil {
		t.Fatal(err)
	}
	binB := filepath.Join(t.TempDir(), "fake2")
	if err := os.WriteFile(binB, []byte("#!/bin/sh\necho b\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_CLAUDE_BIN", binA)
	c := contract(t.TempDir())
	agent, err := agents.New("claude-code")
	if err != nil {
		t.Fatal(err)
	}
	pv := prompts.Version{ID: "builtin"}
	resA, err := agents.ResolvePath(agent)
	if err != nil {
		t.Fatal(err)
	}
	idA := computeExecutionIdentity(config.BuiltIn(), c, agent, resA, agents.BackendIdentity{}, nil, "", "dead", "ch", pv, "attest-1", PolicyBundle{})
	t.Setenv("GOV_CLAUDE_BIN", binB)
	resB, err := agents.ResolvePath(agent)
	if err != nil {
		t.Fatal(err)
	}
	idB := computeExecutionIdentity(config.BuiltIn(), c, agent, resB, agents.BackendIdentity{}, nil, "", "dead", "ch", pv, "attest-1", PolicyBundle{})
	if idA.BackendBinarySHA256 == idB.BackendBinarySHA256 {
		t.Fatal("different backend binaries produced the same identity binary hash")
	}
	if idA.Hash() == idB.Hash() {
		t.Fatal("a backend binary change did not change the full identity hash")
	}
}

// TestComputeIdentityCapturesDockerImageIdentity is report P1-1's unit-level
// proof: a resolved Docker image identity feeds the execution identity hash,
// so a retagged mutable tag (same contract, same c.Docker.Image string, but
// a different resolved image ID/digest) mints a different identity and never
// replays a prior approval against the swapped image. Uses fabricated
// runner.ImageIdentity values -- internal/runner's own docker_test.go proves
// ResolveImageIdentity itself detects a real retag against a live daemon.
func TestComputeIdentityCapturesDockerImageIdentity(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "fake")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\necho a\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_CLAUDE_BIN", bin)
	c := contract(t.TempDir())
	c.Docker = &contracts.DockerRunnerConfig{Image: "example/agent:latest"}
	agent, err := agents.New("claude-code")
	if err != nil {
		t.Fatal(err)
	}
	res, err := agents.ResolvePath(agent)
	if err != nil {
		t.Fatal(err)
	}
	pv := prompts.Version{ID: "builtin"}

	imgA := &runner.ImageIdentity{Reference: "example/agent:latest", ID: "sha256:" + strings.Repeat("a", 64)}
	imgB := &runner.ImageIdentity{Reference: "example/agent:latest", ID: "sha256:" + strings.Repeat("b", 64)}

	idA := computeExecutionIdentity(config.BuiltIn(), c, agent, res, agents.BackendIdentity{}, imgA, "", "dead", "ch", pv, "attest-1", PolicyBundle{})
	idB := computeExecutionIdentity(config.BuiltIn(), c, agent, res, agents.BackendIdentity{}, imgB, "", "dead", "ch", pv, "attest-1", PolicyBundle{})
	if idA.Hash() == idB.Hash() {
		t.Fatal("a different resolved Docker image ID (same configured tag) did not change the full identity hash")
	}

	idNone := computeExecutionIdentity(config.BuiltIn(), c, agent, res, agents.BackendIdentity{}, nil, "", "dead", "ch", pv, "attest-1", PolicyBundle{})
	if idA.Hash() == idNone.Hash() {
		t.Fatal("a resolved image identity vs. none (same tag) did not change the full identity hash")
	}
}

func TestExecutionIdentityBindsControllerEnvironmentHash(t *testing.T) {
	original := ExecutionIdentity{ContractHash: "contract", ControllerEnvironmentHash: "environment-a"}
	changed := original
	changed.ControllerEnvironmentHash = "environment-b"
	if original.Hash() == changed.Hash() {
		t.Fatal("controller environment change did not invalidate replay identity")
	}
}

func TestResolveValidatorToolsetBindsDeclaredFileBytes(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "validator.py")
	if err := os.WriteFile(path, []byte("print('a')\n"), 0644); err != nil {
		t.Fatal(err)
	}
	c := contracts.Contract{Success: contracts.Success{
		Validators:     []string{"python3 validator.py"},
		ValidatorSpecs: []contracts.ValidatorSpec{{Command: "python3 validator.py", Files: []string{"validator.py"}}},
	}}
	first, err := resolveValidatorToolset(c, root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("print('b')\n"), 0644); err != nil {
		t.Fatal(err)
	}
	second, err := resolveValidatorToolset(c, root)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("validator file byte change did not change resolved toolset hash")
	}
}

func TestResolveValidatorToolsetRejectsEscapingFile(t *testing.T) {
	c := contracts.Contract{Success: contracts.Success{
		Validators:     []string{"python3 validator.py"},
		ValidatorSpecs: []contracts.ValidatorSpec{{Command: "python3 validator.py", Files: []string{"../validator.py"}}},
	}}
	if _, err := resolveValidatorToolset(c, t.TempDir()); err == nil || !strings.Contains(err.Error(), "escapes workspace root") {
		t.Fatalf("expected workspace escape error, got %v", err)
	}
}
