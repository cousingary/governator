package contracts

import (
	"fmt"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type Mode string

const (
	ModeScout       Mode = "scout"
	ModeSurgeon     Mode = "surgeon"
	ModeBatchWorker Mode = "batch_worker"
	ModeVerifier    Mode = "verifier"
	ModeRepair      Mode = "repair"
	ModeArchitect   Mode = "architect"
	// ModePlanner decomposes an intent into an ordered PLAN.yaml manifest of
	// governed sub-contracts. It writes (unlike scout/verifier/architect) but
	// only within the plan's own output directory — see `gov plan`.
	ModePlanner Mode = "planner"
)

var validModes = map[Mode]bool{
	ModeScout: true, ModeSurgeon: true, ModeBatchWorker: true,
	ModeVerifier: true, ModeRepair: true, ModeArchitect: true, ModePlanner: true,
}

// ReadOnly reports whether m never writes to the workspace. Scout, verifier,
// and architect jobs inspect and report only; every other mode may write.
func (m Mode) ReadOnly() bool {
	return m == ModeScout || m == ModeVerifier || m == ModeArchitect
}

var jobIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

var riskClasses = map[string]bool{"low": true, "medium": true, "high": true}

// validAgents mirrors internal/agents.New's switch (kept in sync by the
// router_test cross-check against agents.Registered). Duplicated here so the
// contracts package can validate an explicit agent without importing agents
// (which would create a cycle: agents imports contracts for SpecFromContract).
var validAgents = map[string]bool{
	"claude-code": true, "claude": true, "codex": true,
	"glm": true, "opencode": true, "pi": true,
}

// AgentAuto is the contract sentinel that defers backend selection to the
// route broker (internal/router). An explicit agent name keeps today's
// behavior: the broker still validates health but never overrides an
// operator's explicit choice (it may warn).
const AgentAuto = "auto"

var routingObjectives = map[string]bool{
	"balanced": true, "cheapest": true, "most_reliable": true,
}

var routingFallbacks = map[string]bool{
	// v1.2 reserves the enum but only this value is meaningful; S3 defines
	// the fallback behavior. An empty fallback (omitted) is also valid.
	"infrastructure_only": true,
}

// Routing is the optional block a contract pairs with agent: auto to shape
// route-broker selection. It is meaningless (and rejected) with an explicit
// agent, since an explicit agent is the operator overriding the broker.
// Hard capability filters live under Requirements and fail closed: if no
// healthy candidate satisfies them the job refuses to run rather than
// silently widening the pool.
type Routing struct {
	Objective    string              `yaml:"objective,omitempty" json:"objective,omitempty"`
	Candidates   []string            `yaml:"candidates,omitempty" json:"candidates,omitempty"`
	MaxAttempts  int                 `yaml:"max_attempts,omitempty" json:"max_attempts,omitempty"`
	Fallback     string              `yaml:"fallback,omitempty" json:"fallback,omitempty"`
	Requirements RoutingRequirements `yaml:"requirements,omitempty" json:"requirements,omitempty"`
}

// EffectiveObjective returns the routing objective defaulted to balanced. The
// broker shifts weights by objective but never uses it to bypass a hard
// exclusion (rule: fail closed).
func (r *Routing) EffectiveObjective() string {
	if r == nil || r.Objective == "" {
		return "balanced"
	}
	return r.Objective
}

// EffectiveMaxAttempts returns the fallback-chain cap defaulted to 2. Session 3
// wires the chain; validation already rejected >3, so this only applies the
// default for an unset (zero) value.
func (r *Routing) EffectiveMaxAttempts() int {
	if r == nil || r.MaxAttempts == 0 {
		return 2
	}
	return r.MaxAttempts
}

// RoutingRequirements are hard capability filters. Every set field must be
// satisfied by a candidate's agents.Capability or the candidate is excluded;
// if none remain the broker fails closed.
//
// NativeSandbox, NetworkControl, and ReadOnlyMode check fixed properties of
// the backend's CLI wrapper (agents.Capability's static fields). Vision,
// ToolCalling, LocalOnly, MinContextTokens, and MinOutputTokens check the
// underlying *model* the operator has pointed the backend at — Governator
// never guesses those from a binary name, since the same CLI wrapper can run
// different models over time. They are satisfied only by an explicit
// backends.<name> declaration in config.yaml (see docs/routing.md); absent a
// declaration every candidate reports unsupported/zero, so an unmet
// requirement fails closed rather than silently passing.
type RoutingRequirements struct {
	NativeSandbox  bool `yaml:"native_sandbox,omitempty" json:"native_sandbox,omitempty"`
	NetworkControl bool `yaml:"network_control,omitempty" json:"network_control,omitempty"`
	ReadOnlyMode   bool `yaml:"read_only_mode,omitempty" json:"read_only_mode,omitempty"`
	Vision         bool `yaml:"vision,omitempty" json:"vision,omitempty"`
	ToolCalling    bool `yaml:"tool_calling,omitempty" json:"tool_calling,omitempty"`
	LocalOnly      bool `yaml:"local_only,omitempty" json:"local_only,omitempty"`

	// MinContextTokens and MinOutputTokens are minimum thresholds, not flags:
	// zero means "no minimum," so a contract with neither set behaves exactly
	// as before this field existed.
	MinContextTokens int `yaml:"min_context_tokens,omitempty" json:"min_context_tokens,omitempty"`
	MinOutputTokens  int `yaml:"min_output_tokens,omitempty" json:"min_output_tokens,omitempty"`
}

// ArtifactSpec declares a typed handoff artifact a job produces. Artifacts
// are controller-owned handoff files, not source files: they must live under
// .governator/artifacts/ in the run worktree, are size-bounded, optionally
// schema-validated, copied to the ledger-adjacent artifact store, and never
// merged back into the source root.
type ArtifactSpec struct {
	Name     string `yaml:"name" json:"name"`
	Path     string `yaml:"path" json:"path"`
	Schema   string `yaml:"schema,omitempty" json:"schema,omitempty"`
	MaxBytes int64  `yaml:"max_bytes" json:"max_bytes"`
}

// Assay is the optional block a contract uses to opt into the
// Governator<->Assayer synchronous bridge (Phase 3A). Profile names a check
// profile the local Assayer subprocess understands. Enforcement controls
// what a FAIL/ERROR verdict does to the run: "blocking" routes a FAIL/ERROR
// into the existing quarantine path exactly like a failed validator;
// "advisory"/"telemetry" record the verdict in the assay_evaluations ledger
// table but never block the merge.
type Assay struct {
	Profile     string `yaml:"profile" json:"profile"`
	Enforcement string `yaml:"enforcement" json:"enforcement"`
}

// AssayEnforcements are the valid Assay.Enforcement values (fail-closed:
// anything else is a validation error, same pattern as OnViolation/RiskClass).
var AssayEnforcements = map[string]bool{"blocking": true, "advisory": true, "telemetry": true}

// DockerRunnerConfig configures the Phase 5 DockerRunner: host-level
// containment for the agent process itself (worktrees, created the same way
// regardless of runner, only ever isolated the repo, not the OS). Only
// meaningful when Contract.Runner == "docker".
//
// The Session 3 (Phase 2) hardening fields below (User through
// RequireCompleteTranscript) are individually optional: a non-hardened config
// is still valid for ordinary jobs. IsHardened reports when enough of them are
// set to satisfy a risk_class: high contract (see internal/containment).
type DockerRunnerConfig struct {
	Image            string   `yaml:"image" json:"image"`
	CPULimit         string   `yaml:"cpu_limit,omitempty" json:"cpu_limit,omitempty"`
	MemoryLimit      string   `yaml:"memory_limit,omitempty" json:"memory_limit,omitempty"`
	PIDsLimit        int      `yaml:"pids_limit,omitempty" json:"pids_limit,omitempty"`
	Network          string   `yaml:"network,omitempty" json:"network,omitempty"`
	CredentialMounts []string `yaml:"credential_mounts,omitempty" json:"credential_mounts,omitempty"`
	OutputCapBytes   int64    `yaml:"output_cap_bytes,omitempty" json:"output_cap_bytes,omitempty"`

	// User runs the container process as a non-root user (docker --user),
	// e.g. "65532:65532". Required for IsHardened — root inside the container
	// defeats the capability/read-only controls below.
	User string `yaml:"user,omitempty" json:"user,omitempty"`
	// ReadOnlyRootfs mounts the root filesystem read-only (--read-only).
	// Required for IsHardened; pair with Tmpfs for the dirs an agent must write.
	ReadOnlyRootfs bool `yaml:"read_only_rootfs,omitempty" json:"read_only_rootfs,omitempty"`
	// CapDropAll drops every Linux capability (--cap-drop=ALL). Required for
	// IsHardened; the agent gets no kernel surface to escalate through.
	CapDropAll bool `yaml:"cap_drop_all,omitempty" json:"cap_drop_all,omitempty"`
	// NoNewPrivileges sets --security-opt no-new-privileges. Required for
	// IsHardened; blocks setuid/file-capability escalation paths.
	NoNewPrivileges bool `yaml:"no_new_privileges,omitempty" json:"no_new_privileges,omitempty"`
	// SeccompProfile applies a seccomp profile (--security-opt seccomp=<path>).
	// Must be an absolute host path when set.
	SeccompProfile string `yaml:"seccomp_profile,omitempty" json:"seccomp_profile,omitempty"`
	// AppArmorProfile applies an AppArmor profile (--security-opt
	// apparmor=<profile>).
	AppArmorProfile string `yaml:"apparmor_profile,omitempty" json:"apparmor_profile,omitempty"`
	// Tmpfs mounts controlled temporary filesystems (--tmpfs). Needed under
	// ReadOnlyRootfs for /tmp, /run, and any dir the backend CLI writes to.
	Tmpfs []string `yaml:"tmpfs,omitempty" json:"tmpfs,omitempty"`
	// AllowMutableTag is the documented operator exception to the digest
	// requirement: a mutable tag (image:latest) is accepted only when this is
	// set, and the choice is recorded in provenance. Without it, IsHardened
	// requires Image to be pinned by digest (image@sha256:...).
	AllowMutableTag bool `yaml:"allow_mutable_tag,omitempty" json:"allow_mutable_tag,omitempty"`
	// EgressAllowlist is reserved for a future runner that can actually
	// enforce host:port egress filtering. Validation currently REJECTS a
	// non-empty list (fail-closed): the docker runner has no mechanism to
	// enforce it, and an unenforced allowlist reading as a restriction is
	// worse than no field at all. Use network: deny (default), or network:
	// allow with deny_metadata_and_local_net: true.
	EgressAllowlist []string `yaml:"egress_allowlist,omitempty" json:"egress_allowlist,omitempty"`
	// DenyMetadataAndLocalNet sinkholes cloud-metadata endpoints when network
	// is allowed (--add-host redirection to loopback). The safe default remains
	// network: deny; this narrows the allow opt-in.
	DenyMetadataAndLocalNet bool `yaml:"deny_metadata_and_local_net,omitempty" json:"deny_metadata_and_local_net,omitempty"`
	// RequireCompleteTranscript makes output truncation a blocking violation:
	// a run whose transcript was capped is quarantined rather than approved on
	// an incomplete evidence trail. Defaults false (truncation is recorded but
	// non-blocking); high-risk hardened contracts should set it true.
	RequireCompleteTranscript bool `yaml:"require_complete_transcript,omitempty" json:"require_complete_transcript,omitempty"`
}

// dockerNetworkModes are the valid DockerRunnerConfig.Network values ("" defers
// to EffectiveNetwork's default-deny).
var dockerNetworkModes = map[string]bool{"": true, "deny": true, "allow": true}

// EffectiveNetwork defaults an unset Network to "deny" (plan rule: network
// policy is default deny, contract opt-in). A nil receiver (docker runner not
// configured) also reports "deny".
func (d *DockerRunnerConfig) EffectiveNetwork() string {
	if d == nil || d.Network == "" {
		return "deny"
	}
	return d.Network
}

// EffectiveOutputCapBytes defaults an unset/invalid cap to 20MiB so a
// runaway backend can never grow the transcript file without bound.
func (d *DockerRunnerConfig) EffectiveOutputCapBytes() int64 {
	if d == nil || d.OutputCapBytes <= 0 {
		return 20 * 1024 * 1024
	}
	return d.OutputCapBytes
}

// imagePinned reports whether Image references an immutable digest, the
// hardening requirement — a mutable tag (image:latest) can be silently
// retagged underneath a "hardened" config. AllowMutableTag is the documented
// operator exception (recorded, not enforced, at the registry).
func (d *DockerRunnerConfig) imagePinned() bool {
	if d == nil {
		return false
	}
	if d.AllowMutableTag {
		return true
	}
	return strings.Contains(d.Image, "@sha256:")
}

// IsHardened reports whether every Session 3 (Phase 2) containment control is
// in place: non-root user, read-only root filesystem, cap-drop=ALL,
// no-new-privileges, a pinned (digest) image, and network deny. A risk_class:
// high contract requires an IsHardened docker config — or a verified native
// sandbox / signed override (see internal/containment) — and must never
// silently resolve to local execution. Network deny is part of hardened
// because unrestricted egress is a data-exfiltration path no filesystem or
// capability control compensates for; a high-risk job that genuinely needs
// the network goes through the signed operator override instead. A nil
// receiver (no docker config) is never hardened.
func (d *DockerRunnerConfig) IsHardened() bool {
	if d == nil {
		return false
	}
	return d.User != "" && d.ReadOnlyRootfs && d.CapDropAll && d.NoNewPrivileges &&
		d.imagePinned() && d.EffectiveNetwork() == "deny"
}

// validRunners are the valid Contract.Runner values; "" defers to
// EffectiveRunner's "local" default.
var validRunners = map[string]bool{"": true, "local": true, "docker": true}

type Contract struct {
	Task          string         `yaml:"task,omitempty" json:"task,omitempty"`
	JobID         string         `yaml:"job_id" json:"job_id"`
	JobType       string         `yaml:"job_type" json:"job_type"`
	Agent         string         `yaml:"agent" json:"agent"`
	Mode          Mode           `yaml:"mode" json:"mode"`
	Workspace     Workspace      `yaml:"workspace" json:"workspace"`
	Allowed       Permissions    `yaml:"allowed" json:"allowed"`
	Forbidden     Forbidden      `yaml:"forbidden" json:"forbidden"`
	Budget        Budget         `yaml:"budget" json:"budget"`
	TelemetryMode string         `yaml:"telemetry_mode,omitempty" json:"telemetry_mode,omitempty"`
	Preflight     Preflight      `yaml:"preflight" json:"preflight"`
	Success       Success        `yaml:"success" json:"success"`
	Output        *OutputPolicy  `yaml:"output,omitempty" json:"output,omitempty"`
	Repair        *Repair        `yaml:"repair,omitempty" json:"repair,omitempty"`
	Cleanup       *Cleanup       `yaml:"cleanup,omitempty" json:"cleanup,omitempty"`
	Produces      []ArtifactSpec `yaml:"produces,omitempty" json:"produces,omitempty"`
	Consumes      []string       `yaml:"consumes,omitempty" json:"consumes,omitempty"`
	OnViolation   string         `yaml:"on_violation" json:"on_violation"`

	// Routing shapes route-broker selection and is only meaningful with
	// agent: auto. Validate rejects a routing block paired with an explicit
	// agent (the operator already chose). The pointer (not a value) keeps
	// the block absent on every prior job YAML, so existing contracts keep
	// validating unchanged.
	Routing *Routing `yaml:"routing,omitempty" json:"routing,omitempty"`

	// RepairLineage tags a contract compiled by the auto-repair loop with the
	// id of the original run that started its failure lineage. It is set
	// only by internal/runtime, never by job YAML: `yaml:"-"` keeps it out of
	// the strict decoder (KnownFields would otherwise let an operator forge
	// it), and `json:"-"` keeps it out of ContractHash and the compiled
	// prompt.
	RepairLineage string `yaml:"-" json:"-"`

	// ArtifactSources maps each consumed artifact name to the producing job_id.
	// ValidatePlan populates it for ordered plan execution; it is intentionally
	// not part of job YAML, prompts, or ContractHash.
	ArtifactSources map[string]string `yaml:"-" json:"-"`

	// DependsOn is plan-authoring metadata: a `gov plan` manifest's
	// sub-contracts use it to declare execution order (`gov batch run
	// --ordered`). Optional and additive — absent on every job YAML predating
	// `gov plan`, so existing contracts keep validating unchanged. Entries
	// name other job_ids within the same plan; cross-referencing and cycle
	// detection happen at the plan level (ValidatePlan), not here, since a
	// single contract can't see its siblings.
	//
	// RiskClass is a coarse operator-declared tier (low, medium, high),
	// optional on every contract. `gov plan --show` renders it per job, and
	// (Phase 1) the route broker reads it too: paired with agent: auto it
	// nudges scoring toward reliability over cost the way `most_reliable`
	// does for objective, without requiring the operator to give up their
	// chosen objective to say "but this one is risky." An unset RiskClass is
	// scoring-neutral, so no prior agent: auto contract routes differently.
	DependsOn []string `yaml:"depends_on,omitempty" json:"depends_on,omitempty"`
	RiskClass string   `yaml:"risk_class,omitempty" json:"risk_class,omitempty"`

	// Assay opts a job's produced artifacts into the Governator<->Assayer
	// synchronous bridge (Phase 3A): Profile names a check profile the
	// Assayer subprocess understands (e.g. "coding-output-v1"), and
	// Enforcement controls what a FAIL/ERROR verdict does. The pointer
	// (not a value) keeps the block absent on every prior job YAML, so
	// existing contracts keep validating and running unchanged — assay is
	// opt-in per job, not a global gate.
	Assay *Assay `yaml:"assay,omitempty" json:"assay,omitempty"`

	// Runner selects host-level containment (Phase 5): "local" (default, the
	// pre-Phase-5 behavior — a git worktree or plain copy, agent run as a
	// host subprocess) or "docker" (agent process run inside a container
	// bind-mounting the same worktree). Docker settings live in Docker,
	// required when Runner == "docker". An empty value validates and behaves
	// identically to "local", so every prior job YAML keeps working unchanged.
	Runner string              `yaml:"runner,omitempty" json:"runner,omitempty"`
	Docker *DockerRunnerConfig `yaml:"docker,omitempty" json:"docker,omitempty"`

	// Containment is the Session 3 (Phase 2) risk-class containment override
	// surface — optional on every contract, and absent on every prior job YAML
	// so existing contracts keep validating unchanged. See the Containment type.
	Containment *Containment `yaml:"containment,omitempty" json:"containment,omitempty"`

	// Policy is the Session 5 (Sol Phase 4) job-contract layer of the
	// layered policy engine: declarative rules this specific job wants
	// evaluated in addition to organization policy and project doctrine
	// (e.g. tightening an otherwise-ASK default to a hard DENY for this job
	// only). A plain data mirror lives here rather than the real
	// internal/policy.ConditionRule type to avoid an import cycle —
	// internal/policy already depends on internal/contracts for
	// Contract/Mode, so this type can't depend back on internal/policy.
	// internal/policy.ContractRules converts it at evaluation time. Optional
	// and additive — absent on every prior job YAML, so existing contracts
	// keep validating unchanged.
	Policy *Policy `yaml:"policy,omitempty" json:"policy,omitempty"`

	// PostRunValidate, when set, runs in-process after Success.Validators
	// pass but before the run merges to the live root — an extra pre-merge
	// gate for checks too structured for a shell one-liner (e.g. `gov plan`'s
	// PLAN.yaml post-gate). A non-nil error is added as a violation exactly
	// like a failed validator, quarantining the run and skipping the merge.
	// Set only by internal callers, never by job YAML: `yaml:"-"`/`json:"-"`
	// keep it out of the strict decoder and ContractHash (a func value can't
	// serialize, and letting YAML forge it would be a governance hole).
	PostRunValidate func(worktree string) error `yaml:"-" json:"-"`
}

// EffectiveRunner defaults an unset Runner to "local".
func (c Contract) EffectiveRunner() string {
	if c.Runner == "" {
		return "local"
	}
	return c.Runner
}

// Containment carries Session 3 (Phase 2) risk-class containment declarations.
// It is optional on every contract. A risk_class: high contract that cannot
// satisfy hardened Docker or a verified native sandbox may set an override: an
// explicit, cryptographically signed operator assertion that the run may
// proceed under lesser containment. The signature is ed25519 over
// "<job_id>:<override_reason>", verified at run time against the operator
// public key in config (containment.override_public_key). With no key
// configured, no override is ever accepted (fail-closed): high-risk local
// execution without qualifying containment simply fails before launch.
type Containment struct {
	OverrideReason    string `yaml:"override_reason,omitempty" json:"override_reason,omitempty"`
	OverrideSignature string `yaml:"override_signature,omitempty" json:"override_signature,omitempty"`
}

// policyRuleVerdicts and policyRuleOps mirror internal/policy's Verdict
// constants and validConditionOps map (duplicated, not imported, for the
// same reason Policy itself is a plain data mirror — see Contract.Policy).
// Session 5's ContractRules converter is the single place a drift between
// these two lists would surface, since it round-trips every value through
// policy.ConditionRule.Validate.
var policyRuleVerdicts = map[string]bool{"DENY": true, "ASK": true, "FLAG": true}
var policyRuleOps = map[string]bool{
	"eq": true, "ne": true, "gt": true, "gte": true, "lt": true, "lte": true,
	"contains": true, "matches_any": true,
}

var telemetryModes = map[string]bool{"": true, "strict": true, "estimated": true, "advisory": true}

var policyFactTypes = map[string]string{
	"risk_class": "string", "mode": "string", "backend": "string",
	"network_enabled": "bool", "write_out_of_scope": "bool",
	"estimated_cost_usd": "number", "daily_cap_usd": "number",
	"unusual_infra_retry": "bool", "infra_failure_kind": "string",
}

// policyRuleFields mirrors internal/policy's validConditionFields (facts.go's
// Fact* constants) the same way policyRuleVerdicts/policyRuleOps mirror their
// lists — ContractRules' round-trip through policy.ConditionRule.Validate is
// where any drift surfaces.
var policyRuleFields = map[string]bool{
	"risk_class": true, "mode": true, "backend": true,
	"network_enabled": true, "write_out_of_scope": true,
	"estimated_cost_usd": true, "daily_cap_usd": true,
	"unusual_infra_retry": true, "infra_failure_kind": true,
}

// PolicyConditionSpec is one condition in a PolicyRuleSpec's When list: Field
// is a well-known fact name (internal/policy.Fact* constants — see
// docs/contracts.md), Op one of eq/ne/gt/gte/lt/lte/contains/matches_any, Value
// the literal to compare against.
type PolicyConditionSpec struct {
	Field string `yaml:"field" json:"field"`
	Op    string `yaml:"op" json:"op"`
	Value string `yaml:"value" json:"value"`
}

// PolicyRuleSpec is the job-contract layer's declarative policy rule shape
// (Session 5 / Sol Phase 4): every When condition must match (AND) for the
// rule to fire and contribute Verdict/Reason to the layered evaluation.
type PolicyRuleSpec struct {
	ID      string                `yaml:"id" json:"id"`
	When    []PolicyConditionSpec `yaml:"when" json:"when"`
	Verdict string                `yaml:"verdict" json:"verdict"`
	Reason  string                `yaml:"reason" json:"reason"`
}

// Policy carries the job-contract layer of the Session 5 declarative policy
// engine (see Contract.Policy).
type Policy struct {
	Rules []PolicyRuleSpec `yaml:"rules,omitempty" json:"rules,omitempty"`
}

type Workspace struct {
	Root     string `yaml:"root" json:"root"`
	Worktree string `yaml:"worktree" json:"worktree"`
}

type Permissions struct {
	Read    []string `yaml:"read" json:"read"`
	Write   []string `yaml:"write" json:"write"`
	Execute []string `yaml:"execute" json:"execute"`
}

type Forbidden struct {
	Paths     []string `yaml:"paths" json:"paths"`
	Commands  []string `yaml:"commands" json:"commands"`
	Behaviors []string `yaml:"behaviors" json:"behaviors"`
}

type Budget struct {
	MaxMinutes      int `yaml:"max_minutes" json:"max_minutes"`
	MaxCommands     int `yaml:"max_commands" json:"max_commands"`
	MaxFilesChanged int `yaml:"max_files_changed" json:"max_files_changed"`
	MaxLinesChanged int `yaml:"max_lines_changed" json:"max_lines_changed"`
	MaxNewFiles     int `yaml:"max_new_files" json:"max_new_files"`
	MaxDeleted      int `yaml:"max_deleted" json:"max_deleted"`
	MaxTokens       int `yaml:"max_tokens,omitempty" json:"max_tokens,omitempty"`
}

type Preflight struct {
	IntendedWrites  []string `yaml:"intended_writes" json:"intended_writes"`
	ScoutCompleted  bool     `yaml:"scout_completed,omitempty" json:"scout_completed,omitempty"`
	ApproveHighRisk bool     `yaml:"approve_high_risk,omitempty" json:"approve_high_risk,omitempty"`
}

type Success struct {
	RequiredFiles []string `yaml:"required_files" json:"required_files"`
	Validators    []string `yaml:"validators" json:"validators"`
}

type OutputPolicy struct {
	Style         string `yaml:"style" json:"style"`
	MaxFinalWords int    `yaml:"max_final_words,omitempty" json:"max_final_words,omitempty"`
}

func (p OutputPolicy) EffectiveMaxFinalWords() int {
	if p.MaxFinalWords > 0 {
		return p.MaxFinalWords
	}
	return 120
}

// Repair opts a contract into the auto-triggered repair loop: when a run
// quarantines, the runtime compiles a follow-up job from the quarantine's
// repair packet and runs it, bounded by EffectiveMaxAttempts. Absent (the
// zero value via a nil pointer) leaves existing behavior unchanged.
type Repair struct {
	Auto        bool   `yaml:"auto,omitempty" json:"auto,omitempty"`
	MaxAttempts int    `yaml:"max_attempts,omitempty" json:"max_attempts,omitempty"`
	Backend     string `yaml:"backend,omitempty" json:"backend,omitempty"`
}

// EffectiveMaxAttempts returns r.MaxAttempts defaulted to 1 and hard-clamped
// to 2 regardless of what YAML requested — the two-attempts rule encoded so
// a misconfigured job cannot loop repair attempts indefinitely. A nil
// receiver (repair block absent) reports 0: no attempts are ever permitted.
func (r *Repair) EffectiveMaxAttempts() int {
	if r == nil {
		return 0
	}
	n := r.MaxAttempts
	if n <= 0 {
		n = 1
	}
	if n > 2 {
		n = 2
	}
	return n
}

// Cleanup opts a contract into a distinct pre-merge tidy stage that runs
// after Success.Validators pass: a lint/format/temp-file pass recorded with
// its own ledger rows (validators.stage = "cleanup") instead of being folded
// into success.validators. Absent (nil) leaves existing behavior unchanged —
// no cleanup stage runs. Required governs whether a failing cleanup
// validator blocks the merge like a success validator (true) or is recorded
// for visibility only (false, the default) — useful for a lint pass an
// operator wants observed before it's enforced.
type Cleanup struct {
	Required   bool     `yaml:"required,omitempty" json:"required,omitempty"`
	Validators []string `yaml:"validators" json:"validators"`
}

type ValidationError struct {
	Field   string
	Message string
}

func (e ValidationError) Error() string { return fmt.Sprintf("%s: %s", e.Field, e.Message) }

type ValidationErrors []ValidationError

func (e ValidationErrors) Error() string {
	parts := make([]string, 0, len(e))
	for _, item := range e {
		parts = append(parts, item.Error())
	}
	return strings.Join(parts, "; ")
}

func (e ValidationErrors) Sorted() ValidationErrors {
	out := append(ValidationErrors(nil), e...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Field < out[j].Field })
	return out
}

func (c Contract) Validate() error {
	var errs ValidationErrors
	add := func(field, message string) { errs = append(errs, ValidationError{Field: field, Message: message}) }

	if strings.TrimSpace(c.JobID) == "" {
		add("job_id", "is required")
	} else if !jobIDPattern.MatchString(c.JobID) {
		add("job_id", "must start with an alphanumeric character and contain only alphanumerics, '.', '_' or '-'")
	}
	if strings.TrimSpace(c.JobType) == "" {
		add("job_type", "is required")
	}
	if strings.TrimSpace(c.Agent) == "" {
		add("agent", "is required")
	}
	// auto defers to the route broker; any other value is an explicit
	// operator choice that the broker validates but never overrides.
	if c.Agent != AgentAuto && !validAgents[c.Agent] {
		add("agent", "must be 'auto' or a known backend (claude-code, claude, codex, glm, opencode, pi)")
	}
	if !validModes[c.Mode] {
		add("mode", "must be one of scout, surgeon, batch_worker, verifier, repair, architect, planner")
	}
	if strings.TrimSpace(c.Workspace.Root) == "" {
		add("workspace.root", "is required")
	} else if !filepath.IsAbs(c.Workspace.Root) {
		add("workspace.root", "must be an absolute path")
	}
	// Every backend runs in a disposable workspace. Accepting "none" would
	// promise direct-root execution that the runtime intentionally never does.
	if c.Workspace.Worktree != "auto" {
		add("workspace.worktree", "must be 'auto'; direct-root execution is unsupported")
	}

	readOnly := c.Mode == ModeScout || c.Mode == ModeVerifier || c.Mode == ModeArchitect
	if len(c.Allowed.Read) == 0 {
		add("allowed.read", "must contain at least one path pattern")
	}
	if readOnly && len(c.Allowed.Write) != 0 {
		add("allowed.write", "must be empty in a read-only mode")
	}
	if !readOnly && len(c.Allowed.Write) == 0 {
		add("allowed.write", "must contain at least one path pattern for a write-capable mode")
	}

	validatePathPatterns("allowed.read", c.Allowed.Read, add)
	validatePathPatterns("allowed.write", c.Allowed.Write, add)
	if readOnly && len(c.Preflight.IntendedWrites) != 0 {
		add("preflight.intended_writes", "must be empty in a read-only mode")
	}
	if !readOnly && len(c.Preflight.IntendedWrites) == 0 {
		add("preflight.intended_writes", "must declare at least one planned write for a write-capable mode")
	}
	validatePathPatterns("preflight.intended_writes", c.Preflight.IntendedWrites, add)
	validatePathPatterns("forbidden.paths", c.Forbidden.Paths, add)
	validateNonBlank("allowed.execute", c.Allowed.Execute, add)
	validateNonBlank("forbidden.commands", c.Forbidden.Commands, add)
	validateNonBlank("forbidden.behaviors", c.Forbidden.Behaviors, add)

	if c.Budget.MaxMinutes <= 0 {
		add("budget.max_minutes", "must be greater than zero")
	}
	if c.Budget.MaxCommands <= 0 {
		add("budget.max_commands", "must be greater than zero")
	}
	if c.Budget.MaxFilesChanged <= 0 {
		add("budget.max_files_changed", "must be greater than zero")
	}
	if c.Budget.MaxLinesChanged <= 0 {
		add("budget.max_lines_changed", "must be greater than zero")
	}
	if c.Budget.MaxNewFiles < 0 {
		add("budget.max_new_files", "must be zero or greater")
	} else if c.Budget.MaxNewFiles > c.Budget.MaxFilesChanged {
		add("budget.max_new_files", "must not exceed budget.max_files_changed")
	}
	if c.Budget.MaxDeleted < 0 {
		add("budget.max_deleted", "must be zero or greater")
	}
	if c.Budget.MaxTokens < 0 {
		add("budget.max_tokens", "must be zero or greater")
	}
	if !telemetryModes[c.TelemetryMode] {
		add("telemetry_mode", "must be one of strict, estimated, advisory when set")
	}

	if !readOnly && len(c.Success.RequiredFiles) == 0 {
		add("success.required_files", "must contain at least one path pattern for a write-capable mode")
	}
	validatePathPatterns("success.required_files", c.Success.RequiredFiles, add)
	if len(c.Success.Validators) == 0 {
		add("success.validators", "must contain at least one deterministic validator command")
	}
	validateNonBlank("success.validators", c.Success.Validators, add)

	if c.Output != nil {
		switch c.Output.Style {
		case "terse":
			if c.Output.MaxFinalWords != 0 && (c.Output.MaxFinalWords < 20 || c.Output.MaxFinalWords > 1000) {
				add("output.max_final_words", "must be between 20 and 1000 when set")
			}
		case "normal":
			if c.Output.MaxFinalWords != 0 {
				add("output.max_final_words", "is only valid when output.style is 'terse'")
			}
		default:
			add("output.style", "must be 'terse' or 'normal'")
		}
	}

	if c.Repair != nil && c.Repair.MaxAttempts < 0 {
		add("repair.max_attempts", "must be zero or greater (0 defaults to 1, values above 2 clamp to 2)")
	}

	if c.Cleanup != nil {
		if len(c.Cleanup.Validators) == 0 {
			add("cleanup.validators", "must contain at least one command when the cleanup block is present")
		}
		validateNonBlank("cleanup.validators", c.Cleanup.Validators, add)
	}

	if strings.TrimSpace(c.RiskClass) != "" && !riskClasses[c.RiskClass] {
		add("risk_class", "must be one of low, medium, high when set")
	}
	validateNonBlank("depends_on", c.DependsOn, add)
	for i, dep := range c.DependsOn {
		if strings.TrimSpace(dep) != "" && !jobIDPattern.MatchString(dep) {
			add(fmt.Sprintf("depends_on[%d]", i), "must look like a job_id (alphanumeric, '.', '_', '-')")
		}
	}

	validateRouting(c, add)
	validateArtifacts(c, add)
	validateAssay(c, add)
	validateRunner(c, add)
	validateContainment(c, add)
	validatePolicy(c, add)

	// Quarantine is the implemented fail-closed action. Halt and rollback were
	// previously accepted but ignored; rollback also cannot restore arbitrary
	// live-root mutations from fingerprints alone.
	if c.OnViolation != "quarantine" {
		add("on_violation", "must be 'quarantine'; halt and rollback are unsupported")
	}

	if len(errs) > 0 {
		return errs.Sorted()
	}
	return nil
}

func validatePathPatterns(field string, patterns []string, add func(string, string)) {
	for i, raw := range patterns {
		itemField := fmt.Sprintf("%s[%d]", field, i)
		value := strings.TrimSpace(raw)
		if value == "" {
			add(itemField, "must not be blank")
			continue
		}
		if strings.ContainsAny(value, "\x00\r\n") {
			add(itemField, "must not contain control characters")
		}
		if filepath.IsAbs(value) {
			add(itemField, "must be relative to workspace.root")
			continue
		}
		cleaned := path.Clean(strings.ReplaceAll(value, `\`, "/"))
		if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
			add(itemField, "must not escape workspace.root")
		}
	}
}

func validateNonBlank(field string, values []string, add func(string, string)) {
	for i, value := range values {
		if strings.TrimSpace(value) == "" {
			add(fmt.Sprintf("%s[%d]", field, i), "must not be blank")
		}
	}
}

// validateRouting enforces the contract between agent and routing. A routing
// block is meaningful only with agent: auto — an explicit agent is the
// operator overriding the broker, so pairing the two is an ambiguity error,
// not a warning (rule: fail closed on ambiguity). candidate/enum/range
// checks keep the broker's input well-formed before it ever reads the ledger.
func validateRouting(c Contract, add func(string, string)) {
	if c.Routing == nil {
		return
	}
	if c.Agent != AgentAuto {
		add("routing", "is only valid with agent: auto; an explicit agent overrides the broker")
		return
	}
	r := c.Routing
	if r.Objective != "" && !routingObjectives[r.Objective] {
		add("routing.objective", "must be one of balanced, cheapest, most_reliable")
	}
	if r.Fallback != "" && !routingFallbacks[r.Fallback] {
		add("routing.fallback", "must be infrastructure_only in v1.2")
	}
	// max_attempts becomes operational in Session 3; validate the range now
	// so a misconfigured job never reaches a fallback chain. 0 defaults to 2;
	// >3 is rejected (the two-attempts rule caps effective attempts at 2 once
	// S3 wires the chain).
	if r.MaxAttempts < 0 {
		add("routing.max_attempts", "must be zero or greater (0 defaults to 2)")
	} else if r.MaxAttempts > 3 {
		add("routing.max_attempts", "must not exceed 3")
	}
	for i, name := range r.Candidates {
		field := fmt.Sprintf("routing.candidates[%d]", i)
		trimmed := strings.TrimSpace(name)
		if trimmed == "" {
			add(field, "must not be blank")
			continue
		}
		if !validAgents[trimmed] {
			add(field, "must name a known backend (claude-code, claude, codex, glm, opencode, pi)")
		}
	}
	if r.Requirements.MinContextTokens < 0 {
		add("routing.requirements.min_context_tokens", "must be zero or greater")
	}
	if r.Requirements.MinOutputTokens < 0 {
		add("routing.requirements.min_output_tokens", "must be zero or greater")
	}
}

func validateArtifacts(c Contract, add func(string, string)) {
	seenProduces := map[string]bool{}
	for i, artifact := range c.Produces {
		field := fmt.Sprintf("produces[%d]", i)
		name := strings.TrimSpace(artifact.Name)
		if name == "" {
			add(field+".name", "is required")
		} else if !jobIDPattern.MatchString(name) {
			add(field+".name", "must start with an alphanumeric character and contain only alphanumerics, '.', '_' or '-'")
		} else if seenProduces[name] {
			add(field+".name", "duplicates another produced artifact name")
		}
		seenProduces[name] = true
		pathValue := strings.TrimSpace(artifact.Path)
		if pathValue == "" {
			add(field+".path", "is required")
		} else if !validArtifactPath(pathValue) {
			add(field+".path", "must be a relative path under .governator/artifacts/")
		}
		if artifact.MaxBytes <= 0 {
			add(field+".max_bytes", "must be greater than zero")
		}
		if artifact.Schema != "" {
			validateArtifactSchemaPath(field+".schema", artifact.Schema, add)
		}
	}
	for i, name := range c.Consumes {
		field := fmt.Sprintf("consumes[%d]", i)
		trimmed := strings.TrimSpace(name)
		if trimmed == "" {
			add(field, "must not be blank")
		} else if !jobIDPattern.MatchString(trimmed) {
			add(field, "must look like an artifact name (alphanumeric, '.', '_' or '-')")
		}
	}
}

// validateAssay enforces the same fail-closed pattern as OnViolation/RiskClass:
// an unset Assay block is fine (assay is opt-in), but a present one must
// name a profile and a known enforcement mode — an unrecognized enforcement
// value must never be silently treated as "off" or "advisory".
func validateAssay(c Contract, add func(string, string)) {
	if c.Assay == nil {
		return
	}
	if strings.TrimSpace(c.Assay.Profile) == "" {
		add("assay.profile", "is required when the assay block is present")
	}
	if !AssayEnforcements[c.Assay.Enforcement] {
		add("assay.enforcement", "must be one of blocking, advisory, telemetry")
	}
}

// validatePolicy enforces the same fail-closed pattern as validateAssay: an
// absent Policy block is fine (every prior job YAML), but a present rule
// must be structurally complete and name a recognized verdict/op — a typo
// must never be silently treated as "this rule never fires."
func validatePolicy(c Contract, add func(string, string)) {
	if c.Policy == nil {
		return
	}
	seen := map[string]bool{}
	for i, r := range c.Policy.Rules {
		field := fmt.Sprintf("policy.rules[%d]", i)
		id := strings.TrimSpace(r.ID)
		if id == "" {
			add(field+".id", "is required")
		} else if seen[id] {
			add(field+".id", "duplicates another policy rule id in this source namespace")
		}
		seen[id] = true
		if strings.TrimSpace(r.Reason) == "" {
			add(field+".reason", "is required")
		}
		if !policyRuleVerdicts[r.Verdict] {
			add(field+".verdict", "must be one of DENY, ASK, FLAG")
		}
		if len(r.When) == 0 {
			add(field+".when", "must contain at least one condition")
		}
		for j, cond := range r.When {
			condField := fmt.Sprintf("%s.when[%d]", field, j)
			if strings.TrimSpace(cond.Field) == "" {
				add(condField+".field", "is required")
			} else if !policyRuleFields[cond.Field] {
				add(condField+".field", "is not a known policy fact (an unknown field would silently never match); see docs/contracts.md for the fact vocabulary")
			} else if msg := validatePolicyConditionValue(cond.Field, cond.Op, cond.Value); msg != "" {
				add(condField+".value", msg)
			}
			if !policyRuleOps[cond.Op] {
				add(condField+".op", "must be one of eq, ne, gt, gte, lt, lte, contains, matches_any")
			}
		}
	}
}

func validatePolicyConditionValue(field, op, value string) string {
	typ := policyFactTypes[field]
	switch op {
	case "gt", "gte", "lt", "lte":
		if typ != "number" {
			return "numeric operators require a numeric policy fact"
		}
		if _, err := strconv.ParseFloat(strings.TrimSpace(value), 64); err != nil {
			return "numeric operators require a numeric literal"
		}
	case "contains":
		if typ != "string" {
			return "contains requires a string policy fact"
		}
		if value == "" {
			return "contains requires a non-empty literal"
		}
	case "matches_any":
		if typ != "list" {
			return "matches_any requires a list policy fact"
		}
		if strings.TrimSpace(value) == "" {
			return "matches_any requires at least one pattern"
		}
	case "eq", "ne":
		if typ == "bool" {
			if _, err := strconv.ParseBool(strings.TrimSpace(value)); err != nil {
				return "boolean policy facts require true or false"
			}
		}
		if typ == "number" {
			if _, err := strconv.ParseFloat(strings.TrimSpace(value), 64); err != nil {
				return "numeric policy facts require a numeric literal"
			}
		}
	}
	return ""
}

// validateRunner enforces the same fail-closed pattern as validateAssay: an
// unset/"local" Runner (every prior job YAML) is fine, but a "docker" runner
// must carry a valid Docker block — misconfiguration must never be silently
// treated as "run locally instead" (that decision belongs to New's docker
// availability check at run time, not to validation being lenient).
func validateRunner(c Contract, add func(string, string)) {
	if !validRunners[c.Runner] {
		add("runner", "must be 'local' or 'docker' when set")
		return
	}
	if c.Runner != "docker" {
		if c.Docker != nil {
			add("docker", "must be absent unless runner: docker")
		}
		return
	}
	if c.Docker == nil {
		add("docker", "is required when runner: docker")
		return
	}
	if strings.TrimSpace(c.Docker.Image) == "" {
		add("docker.image", "is required when runner: docker")
	}
	if c.Docker.Network != "" && !dockerNetworkModes[c.Docker.Network] {
		add("docker.network", "must be 'deny' or 'allow' when set")
	}
	if c.Docker.PIDsLimit < 0 {
		add("docker.pids_limit", "must be zero or greater")
	}
	if c.Docker.OutputCapBytes < 0 {
		add("docker.output_cap_bytes", "must be zero or greater")
	}
	for i, mount := range c.Docker.CredentialMounts {
		field := fmt.Sprintf("docker.credential_mounts[%d]", i)
		trimmed := strings.TrimSpace(mount)
		if trimmed == "" {
			add(field, "must not be blank")
		} else if !filepath.IsAbs(trimmed) {
			add(field, "must be an absolute host path")
		}
	}
	// Session 3 (Phase 2) hardening field validation is structural, not a
	// hardening gate: a non-hardened docker config is valid for ordinary jobs;
	// IsHardened (a runtime policy check in internal/containment) decides
	// whether it qualifies for risk_class: high. Seccomp paths must be real
	// filesystem locations; tmpfs/egress entries must be non-empty.
	if c.Docker.SeccompProfile != "" && !filepath.IsAbs(c.Docker.SeccompProfile) {
		add("docker.seccomp_profile", "must be an absolute host path when set")
	}
	for i, t := range c.Docker.Tmpfs {
		field := fmt.Sprintf("docker.tmpfs[%d]", i)
		if strings.TrimSpace(t) == "" {
			add(field, "must not be blank")
		}
	}
	// Fail-closed on egress_allowlist: DockerRunner has no mechanism that
	// actually restricts egress to a host:port list (docker alone cannot do
	// domain/port filtering without extra network infrastructure), so
	// accepting the field would ship a silently-unenforced security control —
	// the contract READS as restricted while the container has full egress.
	// Until a real enforcement mechanism exists, declaring it is an error:
	// use network: deny (the default), or an explicit network: allow with
	// deny_metadata_and_local_net: true for the enforceable narrowing.
	if len(c.Docker.EgressAllowlist) > 0 {
		add("docker.egress_allowlist", "declared but not enforceable by the docker runner in this build; remove it and use network: deny, or network: allow with deny_metadata_and_local_net: true (fail-closed: an unenforced allowlist must not read as a restriction)")
	}
}

// validateContainment enforces that an override is complete or absent — a
// reason without a signature (or vice versa) is a half-declared escape hatch
// and must never silently behave as either "no override" or "override
// granted." Cryptographic verification happens at run time
// (internal/containment), not here, since it depends on the operator key in
// config.
func validateContainment(c Contract, add func(string, string)) {
	if c.Containment == nil {
		return
	}
	reason := strings.TrimSpace(c.Containment.OverrideReason)
	sig := strings.TrimSpace(c.Containment.OverrideSignature)
	if sig != "" && reason == "" {
		add("containment.override_reason", "is required when override_signature is set")
	}
	if reason != "" && sig == "" {
		add("containment.override_signature", "is required when override_reason is set")
	}
}

func validArtifactPath(value string) bool {
	if strings.ContainsAny(value, "\x00\r\n") || filepath.IsAbs(value) {
		return false
	}
	cleaned := path.Clean(strings.ReplaceAll(value, `\`, "/"))
	return strings.HasPrefix(cleaned, ".governator/artifacts/") && cleaned != ".governator/artifacts" && !strings.HasSuffix(cleaned, "/")
}

func validateArtifactSchemaPath(field, value string, add func(string, string)) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		add(field, "must not be blank when set")
		return
	}
	if strings.ContainsAny(trimmed, "\x00\r\n") || filepath.IsAbs(trimmed) {
		add(field, "must be relative to workspace.root")
		return
	}
	cleaned := path.Clean(strings.ReplaceAll(trimmed, `\`, "/"))
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		add(field, "must not escape workspace.root")
	}
}
