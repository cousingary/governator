package runtime

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"runtime/debug"
	"strings"

	"github.com/cousingary/governator/internal/agents"
	"github.com/cousingary/governator/internal/config"
	"github.com/cousingary/governator/internal/contracts"
	"github.com/cousingary/governator/internal/prompts"
	"github.com/cousingary/governator/internal/runner"
)

// ExecutionIdentity captures every trust-bearing input that must remain
// identical for a prior APPROVED run to be safely replayed. Per Sol's Critical
// 1 finding and §11 Phase A: the old replay key (contract_hash + approved_head
// + status=APPROVED) let a stale approval bypass every current gate. This
// identity is computed AFTER all pre-launch gates (config, spend, routing,
// breaker, containment, layered policy, quota, prompt resolution) have
// evaluated, and its Hash() is the replay key — so changing any trust-bearing
// input simply makes the old approval never match.
//
// The ApprovedHead field is finalized to the post-merge HEAD for an approved
// git run (mirroring the historical approved_head column), so a subsequent run
// — whose current HEAD equals that post-merge HEAD — matches. Every other
// field is a snapshot of the environment at replay-check time.
type ExecutionIdentity struct {
	ContractHash          string
	ApprovedHead          string
	ConfigHash            string
	ProtectedManifestHash string
	OrgPolicyHash         string
	ProjectDoctrineHash   string
	PromptVersion         string
	PromptChecksum        string
	ValidatorSetHash      string
	AssayerProfileHash    string
	BackendAdapter        string
	BackendAdapterVersion string
	BackendBinaryPath     string
	BackendBinarySHA256   string
	ModelID               string
	CapabilityAttestID    string
	RunnerConfigHash      string
	GovernatorVersion     string

	// Sol P1-2: model/provider identity declared on the backend's
	// config.Backend entry (agents.BackendIdentity). "model = backend name,
	// account = default" is not identity -- these fields let a swapped
	// account, org, or model revision behind the same CLI wrapper mint a
	// different identity hash rather than silently matching the prior one.
	// BackendIdentityKnown is false whenever the operator left Provider or
	// ModelRevision undeclared (agents.BackendIdentity.Known()); an unknown
	// identity still hashes (so it stays part of the replay key) but callers
	// authorizing high-risk native-sandbox reuse must treat it as blocking,
	// never as "unchanged since last time" (see attest.VerifyHighRiskNative).
	BackendProvider       string
	BackendAccountID      string
	BackendOrgID          string
	BackendModelRevision  string
	BackendEndpoint       string
	BackendReasoningMode  string
	BackendApprovalMode   string
	BackendSandboxMode    string
	BackendIdentityHash   string
	BackendIdentityKnown  bool
}

// Hash returns the canonical SHA-256 digest of the full identity. This is the
// replay key: two runs replay only when every trust-bearing input is
// bit-for-bit identical. A single changed field (a new org DENY, a swapped
// backend binary, a different prompt version) mints a different digest and the
// old APPROVED record simply never matches.
func (id ExecutionIdentity) Hash() string {
	var b strings.Builder
	fmt.Fprintf(&b, "contract_hash=%s\n", id.ContractHash)
	fmt.Fprintf(&b, "approved_head=%s\n", id.ApprovedHead)
	fmt.Fprintf(&b, "config_hash=%s\n", id.ConfigHash)
	fmt.Fprintf(&b, "protected_manifest_hash=%s\n", id.ProtectedManifestHash)
	fmt.Fprintf(&b, "org_policy_hash=%s\n", id.OrgPolicyHash)
	fmt.Fprintf(&b, "project_doctrine_hash=%s\n", id.ProjectDoctrineHash)
	fmt.Fprintf(&b, "prompt_version=%s\n", id.PromptVersion)
	fmt.Fprintf(&b, "prompt_checksum=%s\n", id.PromptChecksum)
	fmt.Fprintf(&b, "validator_set_hash=%s\n", id.ValidatorSetHash)
	fmt.Fprintf(&b, "assayer_profile_hash=%s\n", id.AssayerProfileHash)
	fmt.Fprintf(&b, "backend_adapter=%s\n", id.BackendAdapter)
	fmt.Fprintf(&b, "backend_adapter_version=%s\n", id.BackendAdapterVersion)
	fmt.Fprintf(&b, "backend_binary_path=%s\n", id.BackendBinaryPath)
	fmt.Fprintf(&b, "backend_binary_sha256=%s\n", id.BackendBinarySHA256)
	fmt.Fprintf(&b, "model_id=%s\n", id.ModelID)
	fmt.Fprintf(&b, "backend_provider=%s\n", id.BackendProvider)
	fmt.Fprintf(&b, "backend_account_id=%s\n", id.BackendAccountID)
	fmt.Fprintf(&b, "backend_org_id=%s\n", id.BackendOrgID)
	fmt.Fprintf(&b, "backend_model_revision=%s\n", id.BackendModelRevision)
	fmt.Fprintf(&b, "backend_endpoint=%s\n", id.BackendEndpoint)
	fmt.Fprintf(&b, "backend_reasoning_mode=%s\n", id.BackendReasoningMode)
	fmt.Fprintf(&b, "backend_approval_mode=%s\n", id.BackendApprovalMode)
	fmt.Fprintf(&b, "backend_sandbox_mode=%s\n", id.BackendSandboxMode)
	fmt.Fprintf(&b, "backend_identity_hash=%s\n", id.BackendIdentityHash)
	fmt.Fprintf(&b, "backend_identity_known=%t\n", id.BackendIdentityKnown)
	fmt.Fprintf(&b, "capability_attest_id=%s\n", id.CapabilityAttestID)
	fmt.Fprintf(&b, "runner_config_hash=%s\n", id.RunnerConfigHash)
	fmt.Fprintf(&b, "governator_version=%s\n", id.GovernatorVersion)
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

// computeExecutionIdentity builds the identity from the inputs available once
// all pre-launch gates have passed. The caller guarantees cfg/head/hash/prompt
// reflect the current environment; this function only hashes them, never loads
// or re-checks them. bundle is the SAME PolicyBundle the caller already passed
// to evaluatePolicyGate for this run (Sol P1-3) — never a fresh, independent
// load — so OrgPolicyHash/ProjectDoctrineHash always describe exactly the
// rule sets the policy gate evaluated against, not whatever happened to be on
// disk when this function later ran (project doctrine and contract rules used
// to be re-read here, minutes of pre-launch work after the gate's own read,
// which is the exact window a doctrine edit could slip through unnoticed).
//
// resolution is the single canonical backend resolution computed once for
// this run (Sol Finding 5 / Session 2) — computeExecutionIdentity must never
// independently re-resolve the configured binary. Its CanonicalPath/SHA256
// feed BackendBinaryPath/BackendBinarySHA256 in place of the old
// hashFileContent(config.BackendBin(...)) call, which hashed a bare name like
// "pi" literally (via os.ReadFile, never through PATH) and always produced
// the same "unreadable:pi" sentinel regardless of which binary that name
// actually resolved to — a swapped executable never changed the identity.
func computeExecutionIdentity(cfg config.Config, c contracts.Contract, agent agents.Agent, resolution agents.PathResolution, identity agents.BackendIdentity, dockerImage *runner.ImageIdentity, envPolicyHash, head, hash string, promptVer prompts.Version, capabilityAttestID string, bundle PolicyBundle) ExecutionIdentity {
	return ExecutionIdentity{
		ContractHash:          hash,
		ApprovedHead:          head,
		ConfigHash:            cfg.Hash(),
		ProtectedManifestHash: hashFileContent(cfg.ProtectedManifest),
		OrgPolicyHash:         hashJSON(bundle.OrgRules),
		ProjectDoctrineHash:   hashJSON(bundle.ProjectRules),
		PromptVersion:         promptVer.ID,
		PromptChecksum:        promptVer.Checksum,
		ValidatorSetHash:      hashJSON(contractValidatorSet(c)),
		AssayerProfileHash:    hashJSON(assayerInputs(cfg, c)),
		BackendAdapter:        agent.Name(),
		BackendAdapterVersion: adapterVersion(agent),
		BackendBinaryPath:     resolution.CanonicalPath,
		BackendBinarySHA256:   resolution.SHA256,
		ModelID:               agent.Name(),
		BackendProvider:       identity.Provider,
		BackendAccountID:      identity.AccountID,
		BackendOrgID:          identity.OrgID,
		BackendModelRevision:  identity.ModelRevision,
		BackendEndpoint:       identity.Endpoint,
		BackendReasoningMode:  identity.ReasoningMode,
		BackendApprovalMode:   identity.ApprovalMode,
		BackendSandboxMode:    identity.SandboxMode,
		BackendIdentityHash:   identity.ConfigHash,
		BackendIdentityKnown:  identity.Known(),
		CapabilityAttestID:    capabilityAttestID,
		RunnerConfigHash:      hashJSON(runnerConfig(c, dockerImage, envPolicyHash)),
		GovernatorVersion:     governatorBuildID(),
	}
}

// replayMatch looks up the most recent APPROVED run whose stored identity hash
// matches. Returns ("", nil) when no replay exists, distinct from a scan
// error. Replacing the historical contract_hash+approved_head probe, this is
// the single replay entry point and keys only on the full identity.
func replayMatch(db *sql.DB, identityHash string) (string, error) {
	if identityHash == "" {
		return "", nil
	}
	var prior string
	err := db.QueryRow(`SELECT id FROM runs WHERE identity_hash=? AND status='APPROVED' ORDER BY created DESC LIMIT 1`, identityHash).Scan(&prior)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return prior, err
}

// hashFileContent returns the hex SHA-256 of the file at path, or a sentinel
// distinguishing "no path configured" from "path missing/unreadable" so a
// manifest or backend binary that disappears between runs changes the identity
// (the read error path) rather than silently collapsing to the same digest.
func hashFileContent(path string) string {
	if path == "" {
		return "none"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "unreadable:" + path
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// hashJSON marshals v to JSON (canonical: sorted map keys) and returns the hex
// SHA-256. A marshal failure — impossible for the plain data types hashed here
// — falls back to a fixed sentinel so it never silently matches.
func hashJSON(v any) string {
	data, err := json.Marshal(v)
	if err != nil {
		return "unhashable"
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// contractValidatorSet gathers every success and cleanup validator the
// contract declares, so a changed validator command (a tightened lint, a new
// gate) invalidates replay even when the contract hash itself is unchanged.
func contractValidatorSet(c contracts.Contract) map[string][]string {
	out := map[string][]string{
		"success": c.Success.Validators,
	}
	if c.Cleanup != nil {
		out["cleanup"] = c.Cleanup.Validators
	}
	return out
}

// assayerInputs gathers the bridge config and the contract's assay declaration
// so a changed Assayer profile or enforcement mode invalidates replay.
func assayerInputs(cfg config.Config, c contracts.Contract) map[string]any {
	out := map[string]any{"bridge": cfg.Assay}
	if c.Assay != nil {
		out["contract"] = *c.Assay
	} else {
		out["contract"] = nil
	}
	return out
}

// adapterVersion fingerprints the static adapter declaration (the Capability
// struct: native sandbox/read-only/approval/network flags + transcript format)
// as the adapter-version proxy until a real versioned adapter protocol lands
// (Sol §9 item 1). Two adapters with different transcript formats or native
// capabilities therefore mint different identities.
func adapterVersion(agent agents.Agent) string {
	if agent == nil {
		return "nil-agent"
	}
	return hashJSON(agent.Capabilities())
}

// runnerConfig captures the effective runner kind plus the full Docker or
// Local configuration so a switch from local to Docker, a tightened Docker
// security setting, or a changed local output-cap/require_complete_transcript
// setting (Sol High 11) invalidates replay.
// dockerImage is the resolved runner.ImageIdentity for a docker-runner
// contract (nil for local), computed once by the caller (runOnce) via
// runner.ResolveImageIdentity before this function runs. Sol P1-1: c.Docker
// alone carries only the operator's configured image reference, commonly a
// mutable tag -- hashing that string lets the tag be repointed at a
// different image between an attested run and a later replay without the
// identity changing. Folding in the resolved content-addressed image ID
// (and immutable repo digests, entrypoint/cmd/user) closes that gap: replay
// binds to the image that will actually run, not the name that requested it.
// envPolicyHash is agents.EnvPolicyHash(handle.AllowedEnv) for this run's
// resolved backend (Sol P1-14) -- folding it in means a backend whose
// declared allowed-environment variable set changes mints a new identity,
// the same "changed trust-bearing input never silently replays" treatment
// every other input here gets.
func runnerConfig(c contracts.Contract, dockerImage *runner.ImageIdentity, envPolicyHash string) map[string]any {
	out := map[string]any{"runner": c.EffectiveRunner()}
	if c.Docker != nil {
		out["docker"] = *c.Docker
	} else {
		out["docker"] = nil
	}
	out["docker_image_identity"] = dockerImage
	out["env_policy_hash"] = envPolicyHash
	if c.Local != nil {
		out["local"] = *c.Local
	} else {
		out["local"] = nil
	}
	return out
}

// governatorBuildID reports the running binary's module version + VCS revision
// from debug.BuildInfo, so a Governator upgrade (new commit) mints a fresh
// identity and prior approvals never replay across a version boundary. Falls
// back to "unknown" when BuildInfo is unavailable (e.g. a bare go run).
func governatorBuildID() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	rev := "unknown"
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" {
			rev = s.Value
		}
	}
	mod := info.Main.Version
	if mod == "" {
		mod = "devel"
	}
	return mod + "+" + rev
}
