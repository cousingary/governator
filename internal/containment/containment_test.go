package containment

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/cousingary/governator/internal/contracts"
)

// digestPinned is a fully-hardened docker config used across the high-risk
// docker cases below: non-root, read-only rootfs, cap-drop, no-new-privileges,
// and a digest-pinned image.
var digestImage = "ghcr.io/acme/agent@sha256:" + repeat("a", 64)

func hardenedDocker() *contracts.DockerRunnerConfig {
	return &contracts.DockerRunnerConfig{
		Image: digestImage, User: "65532:65532", ReadOnlyRootfs: true,
		CapDropAll: true, NoNewPrivileges: true,
	}
}

func highRiskContract(runner string, docker *contracts.DockerRunnerConfig, cont *contracts.Containment) contracts.Contract {
	return contracts.Contract{
		JobID: "high-risk-1", JobType: "batch_worker", Agent: "codex", Mode: contracts.ModeBatchWorker,
		RiskClass: "high", Runner: runner, Docker: docker, Containment: cont,
		OnViolation: "quarantine",
		Budget:      contracts.Budget{MaxMinutes: 5, MaxTokens: 1000},
	}
}

func TestEnforceNonHostRiskIsNoOp(t *testing.T) {
	// Non-effectful read-only contracts at empty/low/medium risk remain
	// no-ops. S2 selects containment from authority; high risk may strengthen
	// this baseline, but low/unset labels cannot weaken effectful work.
	for _, risk := range []string{"", "low"} {
		c := highRiskContract("local", nil, nil)
		c.RiskClass = risk
		if err := Enforce(c, false, ""); err != nil {
			t.Fatalf("risk_class %q: expected no error, got %v", risk, err)
		}
	}
	c := highRiskContract("local", nil, nil)
	c.RiskClass = "medium"
	c.Allowed.Write = nil
	c.Preflight.IntendedWrites = nil
	c.Produces = nil
	if err := Enforce(c, false, ""); err != nil {
		t.Fatalf("read-only medium risk should remain a no-op: %v", err)
	}
}

func TestEnforceMediumRiskEffectfulLocalFailsByDefault(t *testing.T) {
	c := highRiskContract("local", nil, nil)
	c.RiskClass = "medium"
	c.Allowed.Write = []string{"output/**"}
	if err := Enforce(c, false, ""); err == nil {
		t.Fatal("expected medium-risk effectful local without containment to fail, got nil")
	}
}

func TestEnforceMediumRiskEffectfulPolicyOffPasses(t *testing.T) {
	c := highRiskContract("local", nil, nil)
	c.RiskClass = "medium"
	c.Allowed.Write = []string{"output/**"}
	if err := EnforcePolicy(c, false, "", false); err != nil {
		t.Fatalf("policy-off compatibility mode should allow medium-risk effectful local: %v", err)
	}
}

func TestEnforceHighRiskLocalWithoutContainmentFailsClosed(t *testing.T) {
	// The acceptance criterion: a high-risk local run without qualifying
	// containment (no native sandbox, no override, no operator key) fails
	// before launch.
	c := highRiskContract("local", nil, nil)
	if err := Enforce(c, false, ""); err == nil {
		t.Fatal("expected high-risk local without containment to fail, got nil")
	}
}

func TestEnforceHighRiskLocalWithNativeSandboxPasses(t *testing.T) {
	c := highRiskContract("local", nil, nil)
	if err := Enforce(c, true, ""); err != nil {
		t.Fatalf("native-sandbox-capable backend should pass high-risk local: %v", err)
	}
}

func TestEnforceHighRiskDockerHardenedPasses(t *testing.T) {
	c := highRiskContract("docker", hardenedDocker(), nil)
	if err := Enforce(c, false, ""); err != nil {
		t.Fatalf("hardened docker should pass high-risk: %v", err)
	}
}

func TestEnforceHighRiskDockerNotHardenedFails(t *testing.T) {
	c := highRiskContract("docker", &contracts.DockerRunnerConfig{Image: "agent:latest"}, nil)
	if err := Enforce(c, false, ""); err == nil {
		t.Fatal("expected non-hardened docker to fail high-risk, got nil")
	}
}

func TestEnforceHighRiskLocalWithoutSandboxWithBadOverrideFails(t *testing.T) {
	// An override against a configured key but with a wrong signature must
	// still fail closed.
	pub, _, _ := ed25519.GenerateKey(nil)
	c := highRiskContract("local", nil, &contracts.Containment{
		OverrideReason: "trusted host", OverrideSignature: hex.EncodeToString([]byte("not-a-real-signature")),
	})
	if err := Enforce(c, false, hex.EncodeToString(pub)); err == nil {
		t.Fatal("expected bad-signature override to fail, got nil")
	}
}

// signOverride signs c's containment override in place: it computes
// SigningMessage over the contract exactly as VerifyOverride will (containment
// block cleared for the hash) and fills in OverrideSignature.
func signOverride(t *testing.T, priv ed25519.PrivateKey, c *contracts.Contract) {
	t.Helper()
	msg, err := SigningMessage(*c)
	if err != nil {
		t.Fatalf("SigningMessage: %v", err)
	}
	c.Containment.OverrideSignature = hex.EncodeToString(ed25519.Sign(priv, msg))
}

func TestEnforceHighRiskLocalWithValidOverridePasses(t *testing.T) {
	// A real signed override for this job_id, verified against the configured
	// public key, is the explicit operator escape hatch.
	pub, priv, _ := ed25519.GenerateKey(nil)
	c := highRiskContract("local", nil, &contracts.Containment{OverrideReason: "trusted isolated host"})
	signOverride(t, priv, &c)
	if err := Enforce(c, false, hex.EncodeToString(pub)); err != nil {
		t.Fatalf("valid signed override should pass: %v", err)
	}
}

func TestEnforceOverrideNotReplayableAcrossJobs(t *testing.T) {
	// An override minted for one job_id must not authorize a different job.
	pub, priv, _ := ed25519.GenerateKey(nil)
	c := highRiskContract("local", nil, &contracts.Containment{OverrideReason: "ok"})
	signOverride(t, priv, &c)
	c.JobID = "high-risk-2"
	if err := Enforce(c, false, hex.EncodeToString(pub)); err == nil {
		t.Fatal("override signed for a different job_id must not authorize this run")
	}
}

func TestEnforceOverrideInvalidatedByContractMutation(t *testing.T) {
	// The sharper replay: same job_id, same reason, but the contract BODY is
	// edited after the operator signed — e.g. the docker network is opened.
	// The signature binds the contract hash, so any content edit must refuse.
	pub, priv, _ := ed25519.GenerateKey(nil)
	c := highRiskContract("local", nil, &contracts.Containment{OverrideReason: "trusted isolated host"})
	signOverride(t, priv, &c)
	if err := Enforce(c, false, hex.EncodeToString(pub)); err != nil {
		t.Fatalf("pre-mutation override should verify: %v", err)
	}
	c.Docker = &contracts.DockerRunnerConfig{Image: "agent:latest", Network: "allow"}
	if err := Enforce(c, false, hex.EncodeToString(pub)); err == nil {
		t.Fatal("override signed for a different contract body must not authorize this run")
	}
}

func TestEnforceHighRiskDockerNotHardenedWithOverridePasses(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	c := highRiskContract("docker", &contracts.DockerRunnerConfig{Image: "agent:latest"}, &contracts.Containment{
		OverrideReason: "staging image",
	})
	signOverride(t, priv, &c)
	if err := Enforce(c, false, hex.EncodeToString(pub)); err != nil {
		t.Fatalf("override should rescue non-hardened high-risk docker: %v", err)
	}
}

func TestVerifyOverrideNoKeyRefuses(t *testing.T) {
	// Fail-closed: with no operator public key configured, no override is
	// accepted, even a structurally-complete one.
	c := highRiskContract("local", nil, &contracts.Containment{
		OverrideReason: "x", OverrideSignature: "ab",
	})
	if VerifyOverride(c, "") {
		t.Fatal("empty public key must refuse every override")
	}
}

func TestOverrideMessageFormat(t *testing.T) {
	got := string(OverrideMessage("job-1", "deadbeef", "because"))
	if got != "job-1:deadbeef:because" {
		t.Fatalf("OverrideMessage = %q, want %q", got, "job-1:deadbeef:because")
	}
}

func TestSigningMessageStableAcrossSignatureField(t *testing.T) {
	// SigningMessage must not change when the signature itself is filled in —
	// otherwise nothing could ever be signed (the signature would invalidate
	// its own message).
	c := highRiskContract("local", nil, &contracts.Containment{OverrideReason: "r"})
	before, err := SigningMessage(c)
	if err != nil {
		t.Fatalf("SigningMessage: %v", err)
	}
	c.Containment.OverrideSignature = "aabbcc"
	after, err := SigningMessage(c)
	if err != nil {
		t.Fatalf("SigningMessage: %v", err)
	}
	if string(before) != string(after) {
		t.Fatalf("SigningMessage changed when signature was added:\n%q\n%q", before, after)
	}
}

// repeat avoids pulling strings into this test file just for one padding call.
func repeat(s string, n int) string {
	b := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		b = append(b, s...)
	}
	return string(b)
}
