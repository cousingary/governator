package runtime

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/cousingary/governator/internal/agents"
	"github.com/cousingary/governator/internal/assay"
	"github.com/cousingary/governator/internal/config"
	"github.com/cousingary/governator/internal/containment"
	"github.com/cousingary/governator/internal/contracts"
	"github.com/cousingary/governator/internal/enforce"
	"github.com/cousingary/governator/internal/prompts"
	"github.com/cousingary/governator/internal/runner"
	"github.com/cousingary/governator/internal/toolregistry"
)

// containmentEnvironmentHash binds the exact identity of every
// descendant-containment primitive a run's frozen ContainmentEnvironment
// resolved into ExecutionIdentity (rc4 Session 2, Sol10 P0-2) -- see
// ExecutionIdentity.ContainmentEnvironmentHash's doc comment. A primitive
// that failed to resolve (nil handle) hashes as "enrolled: false" rather
// than being omitted, so "not enrolled" and "enrolled to something" are
// always distinguishable identities.
func containmentEnvironmentHash(env containment.ContainmentEnvironment) string {
	describe := func(h *toolregistry.Handle) map[string]any {
		if h == nil {
			return map[string]any{"enrolled": false}
		}
		return map[string]any{
			"enrolled":       true,
			"canonical_path": h.Identity.CanonicalPath,
			"sha256":         h.Identity.SHA256,
			"device":         h.Identity.Device,
			"inode":          h.Identity.Inode,
		}
	}
	return hashJSON(map[string]any{
		"systemd_run": describe(env.SystemdRun),
		"unshare":     describe(env.Unshare),
		"cgroup":      env.Cgroup,
	})
}

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
	ContractHash              string
	ApprovedHead              string
	ConfigHash                string
	ProtectedManifestHash     string
	OrgPolicyHash             string
	ProjectDoctrineHash       string
	PromptVersion             string
	PromptChecksum            string
	CompiledPromptHash        string
	ValidatorSetHash          string
	ValidatorToolsetHash      string
	ControllerToolsetHash     string
	ControllerEnvironmentHash string
	// ContainmentEnvironmentHash (rc4 Session 2, Sol10 P0-2) binds the exact
	// identity (SHA256/canonical path/device/inode) of every
	// descendant-containment primitive (systemd-run, unshare) this run's
	// frozen ContainmentEnvironment resolved, plus its cgroup v2 capability
	// probe -- see containmentEnvironmentHash. Computed once, from the same
	// RunEnvironment.Containment every containment.NewScope call for this
	// run is handed, before any stage launches; a same-uid replacement of an
	// enrolled primitive after this hash was computed has no effect on
	// execution (Scope.Command launches through the held descriptor, never a
	// re-resolved pathname), but a genuinely DIFFERENT enrolled primitive
	// between runs still mints a different identity, exactly like every
	// other trust-bearing input here.
	ContainmentEnvironmentHash string
	AssayerEnvironmentHash     string
	ConsumedArtifactsHash      string
	GraphProviderHash          string
	GraphSnapshotHash          string
	GovernatorSelfSHA256       string
	AssayerProfileHash         string
	BackendAdapter             string
	BackendAdapterVersion      string
	BackendBinaryPath          string
	BackendBinarySHA256        string
	ModelID                    string
	CapabilityAttestID         string
	RunnerConfigHash           string
	GovernatorVersion          string
	// V2 binds the exact transaction participants and final model-visible prompt.
	Participants               map[string]ExecutableIdentity
	ExactPromptHash            string
	CredentialIdentityHash     string
	StrictReplayEligible       bool
	StrictReplayDisabledReason string

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
	BackendProvider      string
	BackendAccountID     string
	BackendOrgID         string
	BackendModelRevision string
	BackendEndpoint      string
	BackendReasoningMode string
	BackendApprovalMode  string
	BackendSandboxMode   string
	BackendIdentityHash  string
	BackendIdentityKnown bool
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
	fmt.Fprintf(&b, "compiled_prompt_hash=%s\n", id.CompiledPromptHash)
	fmt.Fprintf(&b, "validator_set_hash=%s\n", id.ValidatorSetHash)
	fmt.Fprintf(&b, "validator_toolset_hash=%s\n", id.ValidatorToolsetHash)
	fmt.Fprintf(&b, "controller_toolset_hash=%s\n", id.ControllerToolsetHash)
	fmt.Fprintf(&b, "controller_environment_hash=%s\n", id.ControllerEnvironmentHash)
	fmt.Fprintf(&b, "containment_environment_hash=%s\n", id.ContainmentEnvironmentHash)
	fmt.Fprintf(&b, "assayer_environment_hash=%s\n", id.AssayerEnvironmentHash)
	fmt.Fprintf(&b, "consumed_artifacts_hash=%s\n", id.ConsumedArtifactsHash)
	fmt.Fprintf(&b, "graph_provider_hash=%s\n", id.GraphProviderHash)
	fmt.Fprintf(&b, "graph_snapshot_hash=%s\n", id.GraphSnapshotHash)
	fmt.Fprintf(&b, "governator_self_sha256=%s\n", id.GovernatorSelfSHA256)
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
	fmt.Fprintf(&b, "participants=%s\n", hashJSON(id.Participants))
	fmt.Fprintf(&b, "exact_prompt_hash=%s\n", id.ExactPromptHash)
	fmt.Fprintf(&b, "credential_identity_hash=%s\n", id.CredentialIdentityHash)
	fmt.Fprintf(&b, "strict_replay_eligible=%t\n", id.StrictReplayEligible)
	fmt.Fprintf(&b, "strict_replay_disabled_reason=%s\n", id.StrictReplayDisabledReason)
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
func computeExecutionIdentity(cfg config.Config, c contracts.Contract, agent agents.Agent, resolution agents.PathResolution, identity agents.BackendIdentity, dockerImage *runner.ImageIdentity, envPolicyHash, head, hash string, promptVer prompts.Version, capabilityAttestID string, bundle PolicyBundle, containmentEnv containment.ContainmentEnvironment, dynamicHashes ...string) ExecutionIdentity {
	compiledPromptHash, consumedArtifactsHash, graphProviderHash, graphSnapshotHash, controllerEnvironmentHash, validatorToolsetHash := dynamicIdentityHashes(dynamicHashes...)
	if validatorToolsetHash == "unknown" {
		validatorToolsetHash = hashJSON(contractValidatorToolset(c))
	}
	return ExecutionIdentity{
		ContractHash:               hash,
		ApprovedHead:               head,
		ConfigHash:                 cfg.Hash(),
		ProtectedManifestHash:      hashFileContent(cfg.ProtectedManifest),
		OrgPolicyHash:              hashJSON(bundle.OrgRules),
		ProjectDoctrineHash:        hashJSON(bundle.ProjectRules),
		PromptVersion:              promptVer.ID,
		PromptChecksum:             promptVer.Checksum,
		CompiledPromptHash:         compiledPromptHash,
		ValidatorSetHash:           hashJSON(contractValidatorSet(c)),
		ValidatorToolsetHash:       validatorToolsetHash,
		ControllerToolsetHash:      hashJSON(map[string]string{"backend_path": resolution.CanonicalPath, "backend_sha256": resolution.SHA256}),
		ControllerEnvironmentHash:  controllerEnvironmentHash,
		ContainmentEnvironmentHash: containmentEnvironmentHash(containmentEnv),
		AssayerEnvironmentHash:     hashJSON(assayerInputs(cfg, c)),
		ConsumedArtifactsHash:      consumedArtifactsHash,
		GraphProviderHash:          graphProviderHash,
		GraphSnapshotHash:          graphSnapshotHash,
		GovernatorSelfSHA256:       governatorSelfSHA256(),
		AssayerProfileHash:         hashJSON(assayerInputs(cfg, c)),
		BackendAdapter:             agent.Name(),
		BackendAdapterVersion:      adapterVersion(agent),
		BackendBinaryPath:          resolution.CanonicalPath,
		BackendBinarySHA256:        resolution.SHA256,
		ModelID:                    agent.Name(),
		BackendProvider:            identity.Provider,
		BackendAccountID:           identity.AccountID,
		BackendOrgID:               identity.OrgID,
		BackendModelRevision:       identity.ModelRevision,
		BackendEndpoint:            identity.Endpoint,
		BackendReasoningMode:       identity.ReasoningMode,
		BackendApprovalMode:        identity.ApprovalMode,
		BackendSandboxMode:         identity.SandboxMode,
		BackendIdentityHash:        identity.ConfigHash,
		BackendIdentityKnown:       identity.Known(),
		CapabilityAttestID:         capabilityAttestID,
		RunnerConfigHash:           hashJSON(runnerConfig(c, dockerImage, envPolicyHash)),
		GovernatorVersion:          governatorBuildID(),
	}
}

func dynamicIdentityHashes(values ...string) (compiledPromptHash, consumedArtifactsHash, graphProviderHash, graphSnapshotHash, controllerEnvironmentHash, validatorToolsetHash string) {
	defaults := []string{"unknown", "none", "unknown", "unknown", "unknown", "unknown"}
	for i, v := range values {
		if i >= len(defaults) {
			break
		}
		if v != "" {
			defaults[i] = v
		}
	}
	return defaults[0], defaults[1], defaults[2], defaults[3], defaults[4], defaults[5]
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

type validatorStageSpec struct {
	Stage      string
	Validators []string
	Specs      []contracts.ValidatorSpec
}

func validatorStages(c contracts.Contract) []validatorStageSpec {
	stages := []validatorStageSpec{{Stage: "success", Validators: c.Success.Validators, Specs: c.Success.ValidatorSpecs}}
	if c.Cleanup != nil {
		stages = append(stages, validatorStageSpec{Stage: "cleanup", Validators: c.Cleanup.Validators, Specs: c.Cleanup.ValidatorSpecs})
	}
	return stages
}

type resolvedValidatorTool struct {
	Name          string `json:"name"`
	CanonicalPath string `json:"canonical_path"`
	SHA256        string `json:"sha256"`
	Device        uint64 `json:"device"`
	Inode         uint64 `json:"inode"`
}

type resolvedValidatorFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type resolvedValidatorSpec struct {
	Command string                  `json:"command"`
	Tools   []resolvedValidatorTool `json:"tools"`
	Files   []resolvedValidatorFile `json:"files"`
}

func resolveValidatorToolset(c contracts.Contract, root string, registries ...*toolregistry.Registry) (string, error) {
	var registry *toolregistry.Registry
	structured := false
	for _, stage := range validatorStages(c) {
		if len(stage.Specs) > 0 {
			structured = true
			break
		}
	}
	if !structured {
		return hashJSON(contractValidatorToolset(c)), nil
	}
	if len(registries) > 0 {
		registry = registries[0]
	} else {
		var err error
		registry, err = toolregistry.Load()
		if err != nil {
			return "", fmt.Errorf("load validator tool registry: %w", err)
		}
	}
	if registry == nil {
		return "", fmt.Errorf("validator tool registry is not frozen")
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	resolved := map[string][]resolvedValidatorSpec{}
	for _, stage := range validatorStages(c) {
		if len(stage.Specs) == 0 {
			continue
		}
		if len(stage.Specs) != len(stage.Validators) {
			return "", fmt.Errorf("structured and legacy validators cannot be mixed in %s validators", stage.Stage)
		}
		items := make([]resolvedValidatorSpec, 0, len(stage.Specs))
		for _, spec := range stage.Specs {
			item := resolvedValidatorSpec{Command: spec.Command}
			for _, name := range spec.Tools {
				identity, err := registry.Resolve(name, name)
				if err != nil {
					return "", fmt.Errorf("resolve %s validator tool %q: %w", stage.Stage, name, err)
				}
				item.Tools = append(item.Tools, resolvedValidatorTool{Name: name, CanonicalPath: identity.CanonicalPath, SHA256: identity.SHA256, Device: identity.Device, Inode: identity.Inode})
			}
			for _, declared := range spec.Files {
				abs := filepath.Join(rootAbs, filepath.FromSlash(declared))
				rel, err := filepath.Rel(rootAbs, abs)
				if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
					return "", fmt.Errorf("validator file %q escapes workspace root", declared)
				}
				hash := hashFileContent(abs)
				if strings.HasPrefix(hash, "unreadable:") {
					return "", fmt.Errorf("validator file %q is unreadable", declared)
				}
				item.Files = append(item.Files, resolvedValidatorFile{Path: filepath.ToSlash(rel), SHA256: hash})
			}
			items = append(items, item)
		}
		resolved[stage.Stage] = items
	}
	return hashJSON(resolved), nil
}

// sealedValidatorTools is a per-validator private executable directory
// populated with sealed (verified-bytes) copies of exactly the tools the
// spec declares -- nothing else. That directory becomes the validator's
// sole PATH entry (no ambient base PATH), so declaring "go" can no longer
// expose python3/perl/curl/ssh/git/sh through PATH the way
// filepath.Dir(canonical) + ambient PATH let it before (Sol9 P0-5).
//
// ReadRoots carries each sealed tool's ELF runtime closure (dynamic
// loader + shared libraries) so the Landlock read policy the structured
// validator runs under can actually permit the kernel exec of a declared
// dynamically-linked tool -- without it, the sealed binary's first
// mmap of /lib64/ld-linux-x86-64.so.2 would be denied and the validator
// would fail before its declared tool ever ran.
//
// Identities mirrors what resolveValidatorToolset already folded into
// the replay identity hash; sealedValidatorToolsets returns it here so
// the call site has a single source of truth for the validator's
// declared-tool set, never a re-resolve inside validator execution.
type sealedValidatorTools struct {
	Path       string
	ReadRoots  []string
	Identities []resolvedValidatorTool
	// Copies is every per-tool SealedCopy this directory was populated
	// with (Sol9 P1-4). The caller MUST call Verify on each immediately
	// before the validator process that will find them through PATH=Path
	// starts, and Close once that process has finished.
	Copies []*toolregistry.SealedCopy
}

// sealedToolsForSpec materializes one private executable directory for a
// single validator spec, sealing each declared tool into it and gathering
// the closure read roots each sealed tool needs to actually exec under
// Landlock. Returns nil (no error) for a spec declaring no tools -- the
// caller keeps the legacy ambient-PATH behavior in that case (already
// marked validator_tools=Known:false in the identity, so strict replay
// never depends on it). A spec whose declared tool cannot be resolved,
// sealed, or whose ELF closure cannot be computed is a hard error: the
// pre-fix behavior silently widened PATH to whatever dir held the tool,
// which is exactly what P0-5 closes, so fail closed here rather than
// fall back to ambient.
func sealedToolsForSpec(spec contracts.ValidatorSpec, stage string, idx int, registry *toolregistry.Registry) (*sealedValidatorTools, error) {
	if len(spec.Tools) == 0 {
		return nil, nil
	}
	if registry == nil {
		return nil, fmt.Errorf("validator tool registry is not frozen")
	}
	dir, err := os.MkdirTemp("", fmt.Sprintf("gov-validator-%s-%d-", stage, idx))
	if err != nil {
		return nil, fmt.Errorf("create sealed validator tool dir: %w", err)
	}
	constructed := false
	var copies []*toolregistry.SealedCopy
	defer func() {
		if !constructed {
			for _, cp := range copies {
				_ = cp.Close()
			}
			_ = os.RemoveAll(dir)
		}
	}()
	var identities []resolvedValidatorTool
	var readRoots []string
	seen := map[string]bool{}
	for _, name := range spec.Tools {
		handle, err := registry.ResolveHandle(name, name, toolregistry.KindTrustedController)
		if err != nil {
			return nil, fmt.Errorf("resolve %s validator tool %q: %w", stage, name, err)
		}
		// SealedExecutablePathIn copies the verified-bytes fd's contents
		// into the shared dir; once it returns, the handle's own fd is
		// no longer needed and we can close it. The private copy stands
		// alone -- bash finds the tool by name through PATH=dir, never
		// via /proc/self/fd/<n>, so the handle's fd is not part of the
		// validator's launch chain. The returned SealedCopy (Sol9 P1-4)
		// is kept so its Verify can be called immediately before the
		// validator process starts, catching a same-UID tamper of the
		// published copy between now and then.
		sealedCopy, err := handle.SealedExecutablePathIn(dir)
		if err != nil {
			_ = handle.Close()
			return nil, fmt.Errorf("seal %s validator tool %q: %w", stage, name, err)
		}
		copies = append(copies, sealedCopy)
		base := filepath.Base(handle.Identity.CanonicalPath)
		if seen[base] {
			_ = handle.Close()
			return nil, fmt.Errorf("%s validator tool %q collides on basename %q with an earlier declared tool in the sealed directory", stage, name, base)
		}
		seen[base] = true
		identities = append(identities, resolvedValidatorTool{
			Name:          name,
			CanonicalPath: handle.Identity.CanonicalPath,
			SHA256:        handle.Identity.SHA256,
			Device:        handle.Identity.Device,
			Inode:         handle.Identity.Inode,
		})
		closure, cerr := enforce.ExecutableReadClosure(handle.Identity.CanonicalPath)
		if cerr != nil {
			_ = handle.Close()
			return nil, fmt.Errorf("resolve %s validator tool %q runtime closure: %w", stage, name, cerr)
		}
		readRoots = append(readRoots, closure...)
		if err := handle.Close(); err != nil {
			return nil, fmt.Errorf("close sealed %s validator tool %q handle: %w", stage, name, err)
		}
	}
	if err := os.Chmod(dir, 0500); err != nil {
		return nil, fmt.Errorf("chmod sealed validator tool dir: %w", err)
	}
	constructed = true
	return &sealedValidatorTools{Path: dir, ReadRoots: readRoots, Identities: identities, Copies: copies}, nil
}

// sealedValidatorToolsets materializes one private executable directory
// per validator spec across the success and cleanup stages. The returned
// remove function deletes every directory it created and the caller MUST
// defer it once the transaction's validators have finished running --
// the sealed dirs are private to the run, never part of replay identity
// (which is over the verified tool identities, not the sealed copies).
//
// A spec with no declared Tools contributes a nil entry, preserving the
// legacy ambient-PATH behavior for that one validator (already marked
// validator_tools=Known:false in the identity). Structured validators
// snap to enforcement: PATH is exactly their sealed dir, no ambient base
// PATH, no auto-added git directory -- declaring git explicitly when
// needed, exactly as P0-5 requires.
func sealedValidatorToolsets(c contracts.Contract, registry *toolregistry.Registry) (success, cleanup []*sealedValidatorTools, remove func(), err error) {
	var dirs []string
	var copies []*toolregistry.SealedCopy
	remove = func() {
		for _, cp := range copies {
			_ = cp.Close()
		}
		for _, d := range dirs {
			_ = os.RemoveAll(d)
		}
	}
	defer func() {
		if err != nil {
			remove()
		}
	}()
	if len(c.Success.ValidatorSpecs) > 0 {
		success = make([]*sealedValidatorTools, len(c.Success.ValidatorSpecs))
		for i, spec := range c.Success.ValidatorSpecs {
			st, serr := sealedToolsForSpec(spec, "success", i, registry)
			if serr != nil {
				err = serr
				return
			}
			success[i] = st
			if st != nil {
				dirs = append(dirs, st.Path)
				copies = append(copies, st.Copies...)
			}
		}
	}
	if c.Cleanup != nil && len(c.Cleanup.ValidatorSpecs) > 0 {
		cleanup = make([]*sealedValidatorTools, len(c.Cleanup.ValidatorSpecs))
		for i, spec := range c.Cleanup.ValidatorSpecs {
			st, serr := sealedToolsForSpec(spec, "cleanup", i, registry)
			if serr != nil {
				err = serr
				return
			}
			cleanup[i] = st
			if st != nil {
				dirs = append(dirs, st.Path)
				copies = append(copies, st.Copies...)
			}
		}
	}
	return success, cleanup, remove, nil
}

func contractValidatorToolset(c contracts.Contract) map[string][]string {
	return contractValidatorSet(c)
}

// resolvedAssayerParticipants reports the "assayer"/"assayer_profile"/
// "assayer_checks" participant identities from snap alone (Sol10 P0-6):
// before this fix these three roles were built by re-resolving python3 and
// re-walking/re-hashing the live Assayer checkout on every call, so a
// concurrent edit or a python3 registry rotation occurring AFTER snap was
// already built silently changed the identity ledgered for a transaction
// whose execution had already been pinned to that frozen Snapshot. snap is
// the same *assay.Snapshot BuildSnapshot already produced for this
// transaction (nil when assay isn't configured, or when this specific
// contract doesn't declare an assay block); once built, nothing here
// rereads cfg.Repo, reloads the trusted-tool registry, or re-resolves
// python.
func resolvedAssayerParticipants(cfg config.Assay, envHash string, snap *assay.Snapshot) map[string]ExecutableIdentity {
	parts := map[string]ExecutableIdentity{}
	if strings.TrimSpace(cfg.Repo) == "" {
		return parts
	}
	if snap == nil {
		// Bridge is configured but no snapshot was built for this
		// transaction (this contract doesn't use assay this run) -- there
		// is no executed snapshot to bind identity to, so these roles
		// report NotApplicable rather than falling back to a live
		// re-resolve.
		for _, role := range []string{"assayer", "assayer_profile", "assayer_checks"} {
			parts[role] = ExecutableIdentity{Role: role, EnvironmentHash: envHash, Known: true, NotApplicable: true}
		}
		return parts
	}
	pythonID := snap.Identity.PythonIdentity
	parts["assayer"] = ExecutableIdentity{
		Role: "assayer", CanonicalPath: pythonID.CanonicalPath, SHA256: snap.Identity.PackageHash,
		Device: pythonID.Device, Inode: pythonID.Inode, EnvironmentHash: envHash,
		Known: pythonID.SHA256 != "" && snap.Identity.PackageHash != "",
	}
	parts["assayer_profile"] = ExecutableIdentity{Role: "assayer_profile", SHA256: snap.Identity.ProfileHash, EnvironmentHash: envHash, Known: snap.Identity.ProfileHash != ""}
	// assayer_checks: checks.py's bytes are part of the same copied tree
	// PackageHash already covers (BuildSnapshot copies every .py file under
	// assayer/), so this role shares that hash rather than needing its own
	// separately-retained field.
	parts["assayer_checks"] = ExecutableIdentity{Role: "assayer_checks", SHA256: snap.Identity.PackageHash, EnvironmentHash: envHash, Known: snap.Identity.PackageHash != ""}
	return parts
}

func governatorSelfSHA256() string {
	// Hash the object this process is actually executing, not a pathname that
	// a same-user process can replace between os.Executable and open.
	if runtime.GOOS == "linux" {
		return hashFileContent("/proc/self/exe")
	}
	exe, err := os.Executable()
	if err != nil {
		return "unknown:" + err.Error()
	}
	return hashFileContent(exe)
}

// resolvedAssayerEnvironmentHash is Sol10 P0-6's fix: the sole source of
// Assayer transaction identity. Everything it hashes comes either from snap
// (the frozen *assay.Snapshot BuildSnapshot already produced for this
// transaction, before replay identity was calculated) or from cfg/c (this
// transaction's own declared bridge/contract configuration -- values
// already fixed as function arguments, never re-read from disk here).
//
// Before this fix this function ALSO re-walked the live Assayer repo tree
// (assayerRepoTreeHash), re-resolved python3 (resolvedAssayerPython), and
// called assay.DescribeEnvironment/hashed a hand-picked file list -- all
// live state read AFTER snap was built -- so the ledgered identity
// described a hybrid of the frozen snapshot actually executed plus
// whatever the live checkout/registry happened to be at the moment this
// function ran, not the identity of any single executable transaction
// (Sol10 P0-6). snap is nil when assay isn't configured, or when this
// specific contract doesn't declare an assay block; there is then no
// snapshot to bind to and the hash reduces to the declared
// (non-)configuration alone.
func resolvedAssayerEnvironmentHash(cfg config.Config, c contracts.Contract, snap *assay.Snapshot) string {
	var snapshotIdentity any = "no-snapshot-this-transaction"
	if snap != nil {
		snapshotIdentity = snap.Identity
	}
	return hashJSON(map[string]any{
		"snapshot_identity": snapshotIdentity,
		"bridge":            cfg.Assay,
		"contract":          c.Assay,
	})
}

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
