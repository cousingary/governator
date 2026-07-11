package contracts

import (
	"fmt"
	"path"
	"path/filepath"
	"regexp"
	"sort"
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

type Contract struct {
	Task        string         `yaml:"task,omitempty" json:"task,omitempty"`
	JobID       string         `yaml:"job_id" json:"job_id"`
	JobType     string         `yaml:"job_type" json:"job_type"`
	Agent       string         `yaml:"agent" json:"agent"`
	Mode        Mode           `yaml:"mode" json:"mode"`
	Workspace   Workspace      `yaml:"workspace" json:"workspace"`
	Allowed     Permissions    `yaml:"allowed" json:"allowed"`
	Forbidden   Forbidden      `yaml:"forbidden" json:"forbidden"`
	Budget      Budget         `yaml:"budget" json:"budget"`
	Preflight   Preflight      `yaml:"preflight" json:"preflight"`
	Success     Success        `yaml:"success" json:"success"`
	Output      *OutputPolicy  `yaml:"output,omitempty" json:"output,omitempty"`
	Repair      *Repair        `yaml:"repair,omitempty" json:"repair,omitempty"`
	Cleanup     *Cleanup       `yaml:"cleanup,omitempty" json:"cleanup,omitempty"`
	Produces    []ArtifactSpec `yaml:"produces,omitempty" json:"produces,omitempty"`
	Consumes    []string       `yaml:"consumes,omitempty" json:"consumes,omitempty"`
	OnViolation string         `yaml:"on_violation" json:"on_violation"`

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
