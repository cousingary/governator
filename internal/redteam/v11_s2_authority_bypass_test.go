//go:build redteam

// v11_s2_authority_bypass_test.go is the Sol v11 rc5 Session 2 corpus
// (agents/governator-sol-upgrade11-rc5-plan.md Session 2,
// agents/governator-sol-upgrade11.md P0-3/P0-4): report corpus cases 20-26,
// "Remove production authority bypasses".
//
// P0-3 was that internal/containment/descendants.go's NewScope read
// GOV_CONTAINMENT_FORCE_DEGRADED=1 from the ambient environment and returned
// a degraded (bare process-group) scope BEFORE the requireStrong refusal --
// any launcher, wrapper, or compromised shell that could export an env var
// could force degraded containment for a stage that should fail closed. The
// fix removed that env read entirely; the sanctioned test substitute is the
// package-level containment.ForceDegradedScopeForTesting atomic.Bool, which
// cannot be flipped by environment.
//
// P0-4 was that containment.local_effectful_tiering: "off" (config AND the
// GOV_CONTAINMENT_LOCAL_EFFECTFUL_TIERING env var) let effectful local work
// skip host containment while the run could still reach APPROVED -- an env
// variable alone weakening production authority, not going through the
// existing signed containment.VerifyOverride flow. The fix (1) makes
// config.applyEnv ignore the env variant entirely (local_effectful_tiering is
// config-file-only), and (2) makes the development-only "off" mode
// non-approving by construction in internal/runtime/runtime.go's runOnce:
// strict replay is disabled AND -- critically -- the violation that blocks
// approval is appended BEFORE the merge block begins, not merely before the
// final APPROVED/QUARANTINED decision. (An earlier draft of this fix
// appended the violation only at the final decision point, which correctly
// produced QUARANTINED but had already run the git commit / live-root copy
// by then -- development-mode work would have landed on the live root before
// being retroactively quarantined. Cases 12 and 15 below exist specifically
// to catch that class of regression.)
package redteam

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/cousingary/governator/internal/config"
	"github.com/cousingary/governator/internal/containment"
	"github.com/cousingary/governator/internal/contracts"
)

// writeTieringConfig writes a minimal config.yaml declaring
// containment.local_effectful_tiering and points GOV_CONFIG at it. Empty mode
// omits the field entirely (exercising the built-in "enforce" default).
func writeTieringConfig(t *testing.T, mode string) string {
	t.Helper()
	body := "containment: {}\n"
	if mode != "" {
		body = "containment:\n  local_effectful_tiering: " + mode + "\n"
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestV11Case9ForceDegradedEnvOnHighRiskRunHasNoEffect is corpus case 20:
// GOV_CONTAINMENT_FORCE_DEGRADED=1 on a high-risk (requireStrong) descendant
// scope selection. Since the fix removes the env read entirely, the
// env-var-set call must select the identical primitive the same call would
// select with the var absent -- proving the var is now inert rather than
// asserting a specific primitive (which would make this test host-dependent).
func TestV11Case9ForceDegradedEnvOnHighRiskRunHasNoEffect(t *testing.T) {
	env := containment.ContainmentEnvironment{}

	baseline, err := containment.NewScope("redteam-case9-baseline", true, env)
	baselineErr := err
	if baseline != nil {
		defer func() { _, _ = baseline.Extinguish(context.Background(), 5*time.Second, t.TempDir()) }()
	}

	t.Setenv("GOV_CONTAINMENT_FORCE_DEGRADED", "1")
	attacked, err := containment.NewScope("redteam-case9-attacked", true, env)
	attackedErr := err
	if attacked != nil {
		defer func() { _, _ = attacked.Extinguish(context.Background(), 5*time.Second, t.TempDir()) }()
	}

	if (baselineErr == nil) != (attackedErr == nil) {
		t.Fatalf("GOV_CONTAINMENT_FORCE_DEGRADED changed whether a high-risk (requireStrong) scope was obtained at all: baseline err=%v, with env var err=%v", baselineErr, attackedErr)
	}
	if baseline != nil && attacked != nil && baseline.Method() != attacked.Method() {
		t.Fatalf("GOV_CONTAINMENT_FORCE_DEGRADED changed the selected descendant-owning primitive for a requireStrong scope: baseline=%s, with env var=%s -- the removed env var must be completely inert in production code", baseline.Method(), attacked.Method())
	}
}

// TestV11Case10ForceDegradedEnvOnEffectfulLowRiskRunHasNoEffect is corpus
// case 21: the same property as case 9, for the requireStrong=false path an
// effectful low/unset-risk contract uses (containment.RequiresStrongDescendantContainment
// is false only when risk isn't "high" and enforceLocalEffectful/Effectful
// don't both hold; this test drives NewScope directly with requireStrong=false
// to prove the removed env var is inert on that path too, not just the
// requireStrong=true path case 9 covers).
func TestV11Case10ForceDegradedEnvOnEffectfulLowRiskRunHasNoEffect(t *testing.T) {
	env := containment.ContainmentEnvironment{}

	baseline, err := containment.NewScope("redteam-case10-baseline", false, env)
	if err != nil {
		t.Fatalf("NewScope(requireStrong=false) must never fail (it falls back to a degraded scope by design): %v", err)
	}
	defer func() { _, _ = baseline.Extinguish(context.Background(), 5*time.Second, t.TempDir()) }()

	t.Setenv("GOV_CONTAINMENT_FORCE_DEGRADED", "1")
	attacked, err := containment.NewScope("redteam-case10-attacked", false, env)
	if err != nil {
		t.Fatalf("NewScope(requireStrong=false) must never fail: %v", err)
	}
	defer func() { _, _ = attacked.Extinguish(context.Background(), 5*time.Second, t.TempDir()) }()

	if baseline.Method() != attacked.Method() {
		t.Fatalf("GOV_CONTAINMENT_FORCE_DEGRADED changed the selected primitive for an effectful low-risk (requireStrong=false) scope: baseline=%s, with env var=%s -- the removed env var must be completely inert", baseline.Method(), attacked.Method())
	}
}

// TestV11Case11WrapperInjectedDegradedEnvironmentHasNoEffect is corpus case
// 22: "a wrapper injects the degraded environment". Cases 9-10 prove the
// property against the internal API directly; this drives the REAL COMPILED
// gov binary as an actual OS subprocess (mirroring
// TestV9Case1ProductionSandboxHelperReachesGovernatorNotUnshare's pattern)
// with GOV_CONTAINMENT_FORCE_DEGRADED=1 set only in the child process's own
// environment -- exactly what a malicious launcher/wrapper script that execs
// gov would do. A real high-risk governed run is executed twice, once with
// and once without the injected var; if the var were still honored anywhere
// in the production binary the two outcomes could diverge (a run that should
// refuse for lack of a real descendant primitive instead silently
// "succeeding" degraded). Identical outcomes both times is the proof the
// wrapper's injected variable has zero effect on the shipped binary.
func TestV11Case11WrapperInjectedDegradedEnvironmentHasNoEffect(t *testing.T) {
	root := fixtureRepo(t)
	bin := fakeBackend(t, standardBackendBody(""))
	c := baseContract(root)
	c.RiskClass = "high"
	contractPath := writeContractYAML(t, c)

	run := func(injectDegraded bool) runRecordStatus {
		home := t.TempDir()
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, govBinary(t), "run", contractPath)
		cmd.Env = append(os.Environ(), "GOV_HOME="+home, "GOV_CLAUDE_BIN="+bin)
		if injectDegraded {
			cmd.Env = append(cmd.Env, "GOV_CONTAINMENT_FORCE_DEGRADED=1")
		}
		var out bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &out
		_ = cmd.Run()
		var rec runRecordStatus
		if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &rec); err != nil {
			t.Fatalf("gov run did not print a parseable record (injectDegraded=%v): %v\noutput: %s", injectDegraded, err, out.String())
		}
		return rec
	}

	without := run(false)
	with := run(true)
	if without.Status != with.Status {
		t.Fatalf("a wrapper-injected GOV_CONTAINMENT_FORCE_DEGRADED=1 changed the real subprocess gov binary's outcome: without var status=%s, with var status=%s -- the removed env var must have zero effect even through the compiled production binary", without.Status, with.Status)
	}
}

// TestV11Case12LocalEffectfulTieringOffCannotReachApprovedOrMerge is corpus
// case 23: "local_effectful_tiering: off attempts approval". Drives a full
// governed run, in-process, through the real runtime engine
// (RunWithAutoRepair) with containment.local_effectful_tiering: off
// authored in config -- the development-only compatibility mode. The
// contract deliberately omits forbidden.behaviors: [network] (unlike
// baseContract's default) so containment.RequiresHostContainment depends
// solely on the tiering-controlled branch, not the always-on
// network-forbidden requirement -- isolating exactly the mechanism P0-4
// governs, independent of whether this host can provide real Landlock
// enforcement.
//
// Both invariants are checked: the run must not reach APPROVED, AND -- the
// specific regression this case exists to catch -- the effectful work must
// never have been merged/committed to the live root at all. A fix that only
// changes the final status to QUARANTINED after already running the merge
// (git commit / live-root copy) leaves development-mode work on disk before
// retroactively quarantining it; that is not "merge disabled".
func TestV11Case12LocalEffectfulTieringOffCannotReachApprovedOrMerge(t *testing.T) {
	root := fixtureRepo(t)
	home := t.TempDir()
	bin := fakeBackend(t, standardBackendBody(""))

	t.Setenv("GOV_CONFIG", writeTieringConfig(t, "off"))

	c := baseContract(root)
	c.Forbidden.Behaviors = nil

	rec := runGoverned(t, home, bin, c)
	if rec.Status == "APPROVED" {
		t.Fatalf("run reached APPROVED under development containment mode (local_effectful_tiering: off) -- this mode must never produce an approving production transaction (status=%s message=%s)", rec.Status, rec.Message)
	}
	if _, err := os.Stat(filepath.Join(root, "output", "result.txt")); err == nil {
		t.Fatal("development containment mode (local_effectful_tiering: off) merged effectful work into the live root before quarantining -- merge must be skipped entirely for a non-approving development-mode run, not merely marked QUARANTINED after the merge already ran")
	}
}

// TestV11Case13LocalEffectfulTieringOffEnvVariantCannotWeakenApproval is
// corpus case 24: "the environment variant attempts approval". config.yaml
// declares no local_effectful_tiering (the built-in "enforce" default);
// GOV_CONTAINMENT_LOCAL_EFFECTFUL_TIERING=off is set only in the process
// environment, simulating a launcher/wrapper/compromised shell trying to
// weaken tiering without an operator ever authoring "off" into the config
// file. This exercises the exact composition internal/runtime's
// enforceContainment performs (config.Load() -> containment.EnforcePolicy)
// with externallyEnforced pinned false so the assertion is host-independent
// (does not depend on this host's real Landlock/systemd availability): if
// the env variant were still honored anywhere, an effectful contract with no
// qualifying containment and no override would incorrectly pass.
func TestV11Case13LocalEffectfulTieringOffEnvVariantCannotWeakenApproval(t *testing.T) {
	t.Setenv("GOV_CONFIG", writeTieringConfig(t, ""))
	t.Setenv("GOV_CONTAINMENT_LOCAL_EFFECTFUL_TIERING", "off")

	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !containment.LocalEffectfulTieringEnforced(cfg.Containment.LocalEffectfulTiering) {
		t.Fatalf("GOV_CONTAINMENT_LOCAL_EFFECTFUL_TIERING=off weakened tiering despite no config-file authorization: loaded local_effectful_tiering=%q", cfg.Containment.LocalEffectfulTiering)
	}

	c := baseContract(t.TempDir())
	c.Forbidden.Behaviors = nil
	c.RiskClass = ""

	enforceLocalEffectful := containment.LocalEffectfulTieringEnforced(cfg.Containment.LocalEffectfulTiering)
	if err := containment.EnforcePolicy(c, false, cfg.Containment.OverridePublicKey, enforceLocalEffectful); err == nil {
		t.Fatal("an effectful local run with no qualifying containment and no override passed EnforcePolicy after GOV_CONTAINMENT_LOCAL_EFFECTFUL_TIERING=off -- the env variant must never weaken production authority")
	}
}

// TestV11Case14UnsignedContainmentOverrideCannotDowngradeHighRiskRun is
// corpus case 25: "an unsigned containment downgrade". A high-risk local
// contract carries a containment override reason but a signature produced by
// an ATTACKER's own ed25519 keypair, never the operator key configured via
// GOV_CONFIG's containment.override_public_key -- an untrusted-key downgrade
// attempt, not merely an empty/garbage signature. containment.EnforcePolicy
// (the exact function internal/runtime's enforceContainment calls) must
// refuse it with externallyEnforced pinned false, independent of this host's
// real containment capability.
func TestV11Case14UnsignedContainmentOverrideCannotDowngradeHighRiskRun(t *testing.T) {
	trustedPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, attackerPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	configPath := filepath.Join(t.TempDir(), "config.yaml")
	body := "containment:\n  override_public_key: " + hex.EncodeToString(trustedPub) + "\n"
	if err := os.WriteFile(configPath, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_CONFIG", configPath)

	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Containment.OverridePublicKey != hex.EncodeToString(trustedPub) {
		t.Fatalf("config did not load the configured override_public_key: got %q", cfg.Containment.OverridePublicKey)
	}

	c := baseContract(t.TempDir())
	c.RiskClass = "high"
	c.Containment = &contracts.Containment{OverrideReason: "attacker-forged downgrade"}

	msg, err := containment.SigningMessage(c)
	if err != nil {
		t.Fatal(err)
	}
	c.Containment.OverrideSignature = hex.EncodeToString(ed25519.Sign(attackerPriv, msg))

	enforceLocalEffectful := containment.LocalEffectfulTieringEnforced(cfg.Containment.LocalEffectfulTiering)
	if err := containment.EnforcePolicy(c, false, cfg.Containment.OverridePublicKey, enforceLocalEffectful); err == nil {
		t.Fatal("a high-risk local run's containment override, signed with an untrusted attacker key rather than the configured operator key, was accepted as a valid downgrade authorization")
	}
}

// TestV11Case15StrictReplayRefusedUnderDevelopmentContainmentMode is corpus
// case 26: "strict replay attempted under development containment mode".
// Runs a byte-identical contract twice under containment.local_effectful_tiering:
// off. Neither run may replay a prior result: a development-mode run's
// result is non-approving by construction and must never be treated as a
// trusted prior approval a later identical contract can replay instead of
// re-executing.
func TestV11Case15StrictReplayRefusedUnderDevelopmentContainmentMode(t *testing.T) {
	root := fixtureRepo(t)
	home := t.TempDir()
	bin := fakeBackend(t, standardBackendBody(""))

	t.Setenv("GOV_CONFIG", writeTieringConfig(t, "off"))

	c := baseContract(root)
	c.Forbidden.Behaviors = nil

	r1 := runGoverned(t, home, bin, c)
	if r1.Replayed {
		t.Fatal("first run under development containment mode reported Replayed=true -- there was no prior run to replay")
	}
	r2 := runGoverned(t, home, bin, c)
	if r2.Replayed {
		t.Fatal("a byte-identical run replayed a prior development-containment-mode (local_effectful_tiering: off) result as a trusted approval -- development-mode results must never be strict-replay eligible")
	}
}
