package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cousingary/governator/internal/policy"
	"gopkg.in/yaml.v3"
)

// Backend configures one routing candidate. Bin overrides the binary path.
// The remaining fields are operator-declared facts about whichever model the
// operator has pointed this backend at (vision, tool calling, locality,
// context/output limits) — Governator never infers them from the backend
// name, since the same CLI wrapper can run different models over time. They
// back the router's optional RoutingRequirements hard filters (see
// internal/contracts.RoutingRequirements and docs/routing.md) and default to
// unsupported/zero (fail closed) until declared here.
type Backend struct {
	Bin           string `yaml:"bin"`
	Vision        bool   `yaml:"vision,omitempty"`
	ToolCalling   bool   `yaml:"tool_calling,omitempty"`
	LocalOnly     bool   `yaml:"local_only,omitempty"`
	ContextTokens int    `yaml:"context_tokens,omitempty"`
	OutputTokens  int    `yaml:"output_tokens,omitempty"`

	// Sol P1-2: model/provider identity. A CLI wrapper name is not identity —
	// "model = backend name, account = default" lets a swapped account or
	// model behind the same wrapper pass as unchanged. These are the
	// operator's declared facts about what actually sits behind Bin;
	// agents.Identity leaves any undeclared field empty, which
	// computeExecutionIdentity/attest.VerifyHighRiskNative (Session 3) then
	// treat as unknown — blocking strict replay and high-risk native-sandbox
	// capability reuse rather than silently trusting the backend name.
	Provider      string `yaml:"provider,omitempty"`
	AccountID     string `yaml:"account_id,omitempty"`
	OrgID         string `yaml:"org_id,omitempty"`
	ModelRevision string `yaml:"model_revision,omitempty"`
	Endpoint      string `yaml:"endpoint,omitempty"`
	ReasoningMode string `yaml:"reasoning_mode,omitempty"`
	ApprovalMode  string `yaml:"approval_mode,omitempty"`
	SandboxMode   string `yaml:"sandbox_mode,omitempty"`

	// Sol P1-14: the backend launch inherited the FULL parent environment
	// unconditionally — cloud credentials, unrelated provider keys, SSH
	// agent sockets, everything — with no allowlist at all. AllowedEnv is
	// this adapter's declared list of additional variable NAMES (beyond
	// agents.BuildAllowedEnv's small fixed baseline: PATH/HOME/LANG/etc.)
	// it actually needs; every other inherited variable is stripped by
	// default rather than passed opaquely to a governed backend process.
	AllowedEnv []string `yaml:"allowed_env,omitempty"`
}

type RTK struct {
	Mode string `yaml:"mode"`
	Bin  string `yaml:"bin"`
}

type Graph struct {
	Mode     string `yaml:"mode"`
	Provider string `yaml:"provider"`
	Bin      string `yaml:"bin"`
}

type Minimalism struct {
	Mode string `yaml:"mode"`
}

type Spend struct {
	DailyCapUSD float64 `yaml:"daily_cap_usd"`
	HaltFile    string  `yaml:"halt_file"`
}

// QuotaWindow seeds a subscription/reset window for a backend. Usage units are
// tokens by convention; runtime reservations use budget.max_tokens and
// completion replaces the reservation with measured total_tokens when the
// backend reports them.
type QuotaWindow struct {
	Backend         string  `yaml:"backend"`
	Account         string  `yaml:"account"`
	WindowType      string  `yaml:"window_type"` // 5h, daily, weekly, monthly
	WindowStartedAt string  `yaml:"window_started_at"`
	ResetAt         string  `yaml:"reset_at"`
	EstimatedLimit  float64 `yaml:"estimated_limit"`
	Confidence      float64 `yaml:"confidence"`
}

// Doctrine holds config-gated policy toggles enforced by `gov validate`
// rather than the always-on schema checks in internal/contracts. Default
// false on every field so every existing config file and job YAML keeps
// validating unchanged.
type Doctrine struct {
	// RequireCleanup upgrades the cleanup-doctrine check (a write-capable
	// contract with neither a cleanup block nor a lint/format validator in
	// success.validators) from a warning to a validation error.
	RequireCleanup bool `yaml:"require_cleanup"`
	// UnenforceableRuleAction controls what happens when a starter temporal
	// rule (internal/policy's RuleSecretPrecedesNetwork etc.) cannot possibly
	// fire for a run's transcript format because that backend's parser
	// doesn't supply an event kind the rule needs (Session 6, Sol High 12:
	// internal/policy.UnenforceableRules). "flag" (the default, including
	// "") records an advisory RuleViolation — visible to operators, never
	// blocks the run, so no prior run's outcome changes just because this
	// field now exists. "block" makes it a hard denial, for operators who
	// want a coverage gap on a security-relevant backend to fail closed
	// instead. Never silent either way — that was the actual bug.
	UnenforceableRuleAction string `yaml:"unenforceable_rule_action,omitempty"`
	// TranscriptConformanceAction controls what happens when a run's
	// transcript fails the Sol3 P1.8 (finding #15) sequence-conformance
	// checks — session-start event, completion event, tool-start/result
	// pairing, session identity consistency, turn-count reconciliation —
	// beyond the pre-existing "at least one recognized event" bar. Same
	// posture as UnenforceableRuleAction above and for the same reason: this
	// finding is not release-blocking (P0), and for local untrusted
	// high-risk backends the real backstop is already containment tiering
	// (P0.4) and behavioral attestation (P0.1), not transcript trust. "flag"
	// (the default, including "") records an advisory RuleViolation;
	// "block" makes it a hard denial for operators who want a malformed or
	// suspiciously minimal transcript to fail closed instead of merely
	// being reported.
	TranscriptConformanceAction string `yaml:"transcript_conformance_action,omitempty"`
	// ExactRestoreUnattended is the Sol3 P2.1 (finding #18) unattended policy
	// for `gov snap restore --exact`, which (unlike the pre-existing overlay
	// restore) deletes live files added after the snapshot was taken. Exact
	// restore always requires either the CLI's interactive --yes confirmation
	// or this field set to "allow" before it deletes anything — empty (the
	// default) means every unattended/scripted caller that doesn't pass --yes
	// gets the deletion plan printed back and nothing removed, so no existing
	// automation can be surprised into losing files just because this mode now
	// exists. Protected paths are never deleted by exact restore regardless of
	// this setting.
	ExactRestoreUnattended string `yaml:"exact_restore_unattended,omitempty"`
}

// Containment configures the Session 3 (Phase 2) risk-class containment
// policy. OverridePublicKey is the ed25519 public key (hex) an operator uses
// to sign high-risk containment overrides. Empty (the default) means overrides
// are refused — a high-risk job without qualifying containment simply fails
// before launch. Configure it only when you genuinely need the escape hatch.
type Containment struct {
	OverridePublicKey string `yaml:"override_public_key"`
	// LocalEffectfulTiering controls Session 6's medium/high effectful local-run
	// containment gate. "enforce" (the built-in default) requires hardened
	// Docker, a behaviorally attested native OS sandbox, or a signed override.
	// "off" is the explicit compatibility escape hatch for operators who choose
	// to keep medium-risk effectful jobs on local worktrees temporarily.
	LocalEffectfulTiering string `yaml:"local_effectful_tiering"`
}

// Credentials configures the Session 6 (Sol High 9) credential-mount
// containment: Roots is the operator-declared allowlist of host directories
// a docker.credential_mounts entry may resolve under, after symlink
// resolution. Empty (the default) refuses every credential mount — an
// operator must explicitly declare at least one root before any job can
// mount host credentials into a container, so no prior config.yaml grants
// broader access than it did before this field existed.
type Credentials struct {
	Roots []string `yaml:"roots"`
}

type Defaults struct {
	Agent      string `yaml:"agent"`
	MaxMinutes int    `yaml:"max_minutes"`
}

// Assay configures the Governator<->Assayer synchronous bridge (Phase 3A):
// Repo is the assayer checkout containing cli.py, Python is the interpreter
// to invoke it with, TimeoutSeconds bounds the subprocess call. Repo empty
// (the default — BuiltIn leaves it unset) means assay steps are SKIPPED and
// RECORDED AS SKIPPED by internal/assay: every existing config and every
// existing run that doesn't set this keeps behaving exactly as it did
// before this field existed.
type Assay struct {
	Repo           string `yaml:"repo"`
	Python         string `yaml:"python"`
	TimeoutSeconds int    `yaml:"timeout_seconds"`
}

// Attest bounds the S4 behavioral capability probes. ProbeTimeoutSeconds is a
// per-probe wall-clock budget: each probe drives a REAL backend agent through a
// multi-step task (write in-workspace, attempt a sibling write, attempt a
// protected-host read, attempt four network egress targets, emit a completion
// marker), so the budget must cover a genuine agent turn, not a subprocess
// call. A budget too small to complete an honest probe is not a safe default:
// every probe times out, every capability is recorded unattested — but
// (Session 5, Sol P0-3) that no longer blocks any local work on its own, since
// containment tiering now authorizes on Governator's own externally enforced
// sandbox, never on probe-observed evidence alone. The probe still fails
// CLOSED on timeout (a timed-out capability is never assumed present); the
// timeout is recorded distinctly in ProbeNotes so an operator can tell "we
// could not observe this" from "the backend failed the check."
//
// TotalDeadlineSeconds (Sol P1-17) is the whole probe suite's wall-clock
// ceiling: previously each of the 3 probes (sandbox, read-only, approval) got
// its own independent ProbeTimeoutSeconds budget with nothing bounding their
// sum, so a slow-but-honest backend (or one probe stalling near its own
// budget) could let a single Generate call run for up to 3x ProbeTimeoutSeconds
// with no overall ceiling. Each probe's effective budget is
// min(ProbeTimeoutSeconds, time remaining in TotalDeadlineSeconds) — the
// per-probe budget above still applies unchanged when the total has headroom,
// preserving "a budget too small for a genuine agent turn is not a safe
// default"; TotalDeadlineSeconds only starts trimming once the suite has
// already spent that much wall-clock. Zero means the default, 3x
// ProbeTimeoutSeconds's default (i.e. today's actual worst case, now enforced
// rather than merely possible).
type Attest struct {
	ProbeTimeoutSeconds  int `yaml:"probe_timeout_seconds"`
	TotalDeadlineSeconds int `yaml:"total_deadline_seconds"`
}

type Config struct {
	ProtectedManifest string             `yaml:"protected_manifest"`
	SnapshotDir       string             `yaml:"snapshot_dir"`
	SnapshotRoots     []string           `yaml:"snapshot_roots"`
	LedgerDir         string             `yaml:"ledger_dir"`
	Backends          map[string]Backend `yaml:"backends"`
	RTK               RTK                `yaml:"rtk"`
	Graph             Graph              `yaml:"graph"`
	Minimalism        Minimalism         `yaml:"minimalism"`
	Spend             Spend              `yaml:"spend"`
	Quotas            []QuotaWindow      `yaml:"quotas"`
	Doctrine          Doctrine           `yaml:"doctrine"`
	Defaults          Defaults           `yaml:"defaults"`
	Assay             Assay              `yaml:"assay"`
	Attest            Attest             `yaml:"attest"`
	Containment       Containment        `yaml:"containment"`
	Credentials       Credentials        `yaml:"credentials"`
	// PolicyRules is the Session 5 (Sol Phase 4) organization layer of the
	// layered policy engine: declarative rules evaluated first and with the
	// most authority — no lower layer (project doctrine, job contract,
	// session override) can loosen a DENY an org rule produces. Empty by
	// default (BuiltIn leaves it nil) so every existing config.yaml keeps
	// behaving exactly as it did before this field existed; see
	// docs/contracts.md for the condition language and example rules.
	PolicyRules []policy.ConditionRule `yaml:"policy_rules"`
}

// Env is the single environment lookup seam used by Governator packages.
func Env(name string) string { return strings.TrimSpace(os.Getenv(name)) }

func HomeDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "."
	}
	return home
}

func Path() string {
	if path := Env("GOV_CONFIG"); path != "" {
		return filepath.Clean(path)
	}
	return filepath.Join(HomeDir(), ".governator", "config.yaml")
}

func BuiltIn() Config {
	base := filepath.Join(HomeDir(), ".governator")
	return Config{
		ProtectedManifest: filepath.Join(base, "protected-paths.txt"),
		SnapshotDir:       filepath.Join(base, "snapshots"),
		LedgerDir:         base,
		Backends: map[string]Backend{
			"claude": {Bin: "claude"}, "claude-code": {Bin: "claude"},
			"codex": {Bin: "codex"}, "glm": {Bin: "glm"},
			"opencode": {Bin: "opencode"}, "pi": {Bin: "pi"},
		},
		RTK:        RTK{Mode: "auto", Bin: "rtk"},
		Graph:      Graph{Mode: "auto", Provider: "codegraph", Bin: "codegraph"},
		Minimalism: Minimalism{Mode: "full"},
		Spend:      Spend{DailyCapUSD: 0, HaltFile: filepath.Join(base, "HALT")},
		Quotas:     nil,
		Doctrine:   Doctrine{RequireCleanup: false},
		Defaults:   Defaults{Agent: "claude-code", MaxMinutes: 30},
		// Repo intentionally left unset: assay steps are skipped by default
		// (see Assay's doc comment). Python/TimeoutSeconds default sensibly
		// so a config that only sets `assay.repo` gets a working invocation.
		Assay: Assay{Python: "python3", TimeoutSeconds: 60},
		// 300s: a real agent turn. Measured 2026-07-13, claude-code needs ~19s
		// for a ONE-step probe task; the sandbox probe is five steps including
		// four network egress attempts. The original 30s constant timed out
		// every multi-step probe on every real backend, which recorded sandbox,
		// network and transcript as unattested across the board.
		// TotalDeadlineSeconds: 900s (3x the per-probe default) preserves
		// today's actual worst case for the 3-probe suite (sandbox,
		// read-only, approval) as a hard ceiling rather than an unenforced
		// possibility -- see Attest's doc comment (Sol P1-17).
		Attest: Attest{ProbeTimeoutSeconds: 300, TotalDeadlineSeconds: 900},
		// No override key means risky jobs must qualify for containment on their
		// own (fail-closed). Session 6's medium/high effectful local-run gate is
		// enforced by default and can only be relaxed explicitly.
		Containment: Containment{LocalEffectfulTiering: "enforce"},
	}
}

// LoadStrict reads, strictly-decodes and validates the configuration file. It
// is the canonical configuration API for Sol Critical 2 (malformed
// configuration must fail closed):
//   - absent config → built-in defaults (no error);
//   - present-but-unreadable → a specific error;
//   - malformed YAML → a specific error;
//   - unknown fields (yaml.KnownFields strict decoding) → a specific error;
//   - invalid policy rule values → a specific error.
//
// Security-sensitive callers and the CLI startup guard use this, never the
// error-hiding Current() convenience. Load() remains as a backward-compatible
// alias.
func LoadStrict() (Config, error) {
	cfg := BuiltIn()
	path := Path()
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return Config{}, fmt.Errorf("read config %s: %w", path, err)
	}
	if err == nil {
		var file Config
		decoder := yaml.NewDecoder(bytes.NewReader(data))
		decoder.KnownFields(true)
		if err := decoder.Decode(&file); err != nil {
			return Config{}, fmt.Errorf("decode config %s: %w", path, err)
		}
		// Sol P1.2 (finding #9): LoadStrict used to decode only the first
		// YAML document in the file — a second `---`-separated document was
		// silently ignored rather than rejected. Requiring the next decode
		// to hit io.EOF closes that: any further document (even an empty
		// one, which decodes successfully with err == nil) is an error.
		var extra any
		if derr := decoder.Decode(&extra); derr != io.EOF {
			if derr == nil {
				return Config{}, fmt.Errorf("decode config %s: multiple YAML documents are not supported", path)
			}
			return Config{}, fmt.Errorf("decode config %s: %w", path, derr)
		}
		// Sol P1.2: merge() only overwrites a built-in default when a
		// supplied int field is > 0 (see merge's comments below) — a
		// negative value therefore doesn't get validated at all, it just
		// silently loses to the default before any check ever sees it. The
		// strict Config decode above cannot tell "the operator wrote -5"
		// from "the operator wrote nothing" (both are the Go zero-adjacent
		// case for these fields), so this raw pass re-reads the same bytes
		// generically and validates exactly what was actually supplied,
		// before merge has a chance to hide it.
		if err := validateRawSuppliedValues(data, path); err != nil {
			return Config{}, err
		}
		merge(&cfg, file)
	}
	applyEnv(&cfg)
	clean(&cfg)
	if cfg.RTK.Mode != "auto" && cfg.RTK.Mode != "off" && cfg.RTK.Mode != "required" {
		return Config{}, fmt.Errorf("invalid rtk.mode %q (want auto, off, or required)", cfg.RTK.Mode)
	}
	if cfg.Graph.Mode != "auto" && cfg.Graph.Mode != "off" && cfg.Graph.Mode != "required" {
		return Config{}, fmt.Errorf("invalid graph.mode %q (want auto, off, or required)", cfg.Graph.Mode)
	}
	if cfg.Graph.Provider != "codegraph" {
		return Config{}, fmt.Errorf("invalid graph.provider %q (want codegraph)", cfg.Graph.Provider)
	}
	if cfg.Minimalism.Mode != "off" && cfg.Minimalism.Mode != "lite" && cfg.Minimalism.Mode != "full" && cfg.Minimalism.Mode != "ultra" {
		return Config{}, fmt.Errorf("invalid minimalism.mode %q (want off, lite, full, or ultra)", cfg.Minimalism.Mode)
	}
	// Sol P1.2 (finding #9): NaN/±Inf pass a bare `< 0` check (NaN compares
	// false to everything; Inf compares >= 0 fine) and can otherwise reach
	// Hash()'s JSON marshal, where a non-finite float either round-trips as
	// a broken value or, in pathological cases, makes the whole document
	// unmarshalable — silently degrading every run's identity to the
	// "config-unhashable" sentinel. Reject non-finite values explicitly,
	// everywhere a float can reach this struct from YAML.
	if !finite(cfg.Spend.DailyCapUSD) {
		return Config{}, fmt.Errorf("invalid spend.daily_cap_usd %v (want a finite number >= 0)", cfg.Spend.DailyCapUSD)
	}
	if cfg.Spend.DailyCapUSD < 0 {
		return Config{}, fmt.Errorf("invalid spend.daily_cap_usd %v (want >= 0, 0 = unlimited)", cfg.Spend.DailyCapUSD)
	}
	for _, q := range cfg.Quotas {
		if !finite(q.EstimatedLimit) {
			return Config{}, fmt.Errorf("invalid quota estimated_limit %v for backend %q (want a finite number)", q.EstimatedLimit, q.Backend)
		}
		if q.EstimatedLimit < 0 {
			return Config{}, fmt.Errorf("invalid quota estimated_limit %v for backend %q (want >= 0)", q.EstimatedLimit, q.Backend)
		}
		if !finite(q.Confidence) {
			return Config{}, fmt.Errorf("invalid quota confidence %v for backend %q (want a finite number)", q.Confidence, q.Backend)
		}
		if q.Confidence < 0 || q.Confidence > 1 {
			return Config{}, fmt.Errorf("invalid quota confidence %v for backend %q (want 0..1)", q.Confidence, q.Backend)
		}
		if q.WindowType != "" && q.WindowType != "5h" && q.WindowType != "daily" && q.WindowType != "weekly" && q.WindowType != "monthly" {
			return Config{}, fmt.Errorf("invalid quota window_type %q (want 5h, daily, weekly, or monthly)", q.WindowType)
		}
		// Sol P1.2: a malformed window_started_at/reset_at previously fell
		// through to quota.parseTimeOrZero, which silently substitutes the
		// zero time for anything it can't parse — a typo'd timestamp would
		// quietly reset the window's clock instead of failing to load.
		if s := strings.TrimSpace(q.WindowStartedAt); s != "" && !parsableTimestamp(s) {
			return Config{}, fmt.Errorf("invalid quota window_started_at %q for backend %q (want RFC3339 or YYYY-MM-DD)", q.WindowStartedAt, q.Backend)
		}
		if s := strings.TrimSpace(q.ResetAt); s != "" && !parsableTimestamp(s) {
			return Config{}, fmt.Errorf("invalid quota reset_at %q for backend %q (want RFC3339 or YYYY-MM-DD)", q.ResetAt, q.Backend)
		}
	}
	for _, root := range cfg.Credentials.Roots {
		if !filepath.IsAbs(root) {
			return Config{}, fmt.Errorf("invalid credentials.roots entry %q (want an absolute path)", root)
		}
	}
	if a := cfg.Doctrine.UnenforceableRuleAction; a != "" && a != "flag" && a != "block" {
		return Config{}, fmt.Errorf("invalid doctrine.unenforceable_rule_action %q (want flag or block)", a)
	}
	if a := cfg.Doctrine.TranscriptConformanceAction; a != "" && a != "flag" && a != "block" {
		return Config{}, fmt.Errorf("invalid doctrine.transcript_conformance_action %q (want flag or block)", a)
	}
	if a := cfg.Doctrine.ExactRestoreUnattended; a != "" && a != "allow" {
		return Config{}, fmt.Errorf("invalid doctrine.exact_restore_unattended %q (want allow)", a)
	}
	if t := cfg.Containment.LocalEffectfulTiering; t != "" && t != "enforce" && t != "off" {
		return Config{}, fmt.Errorf("invalid containment.local_effectful_tiering %q (want enforce or off)", t)
	}
	seenPolicyRuleIDs := map[string]bool{}
	for _, rule := range cfg.PolicyRules {
		if seenPolicyRuleIDs[rule.ID] {
			return Config{}, fmt.Errorf("invalid policy_rules: duplicate rule id %q in org_policy namespace", rule.ID)
		}
		seenPolicyRuleIDs[rule.ID] = true
		if err := rule.Validate(); err != nil {
			return Config{}, fmt.Errorf("invalid policy_rules: %w", err)
		}
	}
	return cfg, nil
}

// Load remains as a backward-compatible alias for LoadStrict. New callers
// should call LoadStrict directly to make the strict-decoding contract
// explicit at the call site.
func Load() (Config, error) { return LoadStrict() }

// Current returns the effective configuration. It is a convenience for callers
// that cannot propagate an error (e.g. package-level helpers); prefer
// LoadStrict wherever the error can be observed.
//
// Sol Critical 2: Current() no longer SILENTLY hides a malformed config. When
// LoadStrict reports an error it writes a visible warning to stderr and returns
// built-in defaults rather than crashing a host process (panic-free). The real
// protection is the CLI startup guard (cmd/gov guardConfig), which exits the
// process before any command body runs when the configuration is invalid — so
// in the normal CLI path Current() is never reached with a bad file. Library
// callers that bypass that guard should call LoadStrict directly.
func Current() Config {
	cfg, err := LoadStrict()
	if err != nil {
		fmt.Fprintln(os.Stderr, "governator: malformed configuration ignored, using built-in defaults:", err)
		cfg = BuiltIn()
		applyEnv(&cfg)
		clean(&cfg)
	}
	return cfg
}

// Hash returns a stable SHA-256 digest of the effective configuration. It is
// the "effective config hash" trust-bearing input of the ExecutionIdentity
// (Sol §11 Phase A): two runs whose loaded configuration differs in any
// operator-declared field — backend paths, spend cap, org policy rules,
// containment key, quota windows, assay settings — produce different hashes,
// so a prior APPROVED run can never be replayed against a configuration it was
// never actually evaluated against (Critical 1). encoding/json marshals map
// keys in sorted order, so the digest is canonical regardless of map
// iteration order.
func (c Config) Hash() string {
	data, err := json.Marshal(c)
	if err != nil {
		// Config is a plain struct of comparable/slice/map values whose only
		// non-builtin field (policy.ConditionRule) is itself JSON-serializable,
		// so Marshal cannot fail in practice. Falling back to a fixed sentinel
		// keeps a failure loud (every run mints a fresh identity, so replay
		// never matches) rather than panicking on a governance-critical path.
		return "config-unhashable"
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func merge(dst *Config, src Config) {
	if src.ProtectedManifest != "" {
		dst.ProtectedManifest = src.ProtectedManifest
	}
	if src.SnapshotDir != "" {
		dst.SnapshotDir = src.SnapshotDir
	}
	if src.SnapshotRoots != nil {
		dst.SnapshotRoots = append([]string(nil), src.SnapshotRoots...)
	}
	if src.LedgerDir != "" {
		dst.LedgerDir = src.LedgerDir
	}
	for name, backend := range src.Backends {
		// Field-by-field, not a wholesale replace: an operator declaring only
		// `backends.codex.vision: true` (no bin override) must not silently
		// lose that declaration just because Bin is blank.
		existing := dst.Backends[name]
		if backend.Bin != "" {
			existing.Bin = backend.Bin
		}
		if backend.Vision {
			existing.Vision = backend.Vision
		}
		if backend.ToolCalling {
			existing.ToolCalling = backend.ToolCalling
		}
		if backend.LocalOnly {
			existing.LocalOnly = backend.LocalOnly
		}
		if backend.ContextTokens > 0 {
			existing.ContextTokens = backend.ContextTokens
		}
		if backend.OutputTokens > 0 {
			existing.OutputTokens = backend.OutputTokens
		}
		if backend.Provider != "" {
			existing.Provider = backend.Provider
		}
		if backend.AccountID != "" {
			existing.AccountID = backend.AccountID
		}
		if backend.OrgID != "" {
			existing.OrgID = backend.OrgID
		}
		if backend.ModelRevision != "" {
			existing.ModelRevision = backend.ModelRevision
		}
		if backend.Endpoint != "" {
			existing.Endpoint = backend.Endpoint
		}
		if backend.ReasoningMode != "" {
			existing.ReasoningMode = backend.ReasoningMode
		}
		if backend.ApprovalMode != "" {
			existing.ApprovalMode = backend.ApprovalMode
		}
		if backend.SandboxMode != "" {
			existing.SandboxMode = backend.SandboxMode
		}
		if backend.AllowedEnv != nil {
			existing.AllowedEnv = append([]string(nil), backend.AllowedEnv...)
		}
		dst.Backends[name] = existing
	}
	if src.RTK.Mode != "" {
		dst.RTK.Mode = src.RTK.Mode
	}
	if src.RTK.Bin != "" {
		dst.RTK.Bin = src.RTK.Bin
	}
	if src.Graph.Mode != "" {
		dst.Graph.Mode = src.Graph.Mode
	}
	if src.Graph.Provider != "" {
		dst.Graph.Provider = src.Graph.Provider
	}
	if src.Graph.Bin != "" {
		dst.Graph.Bin = src.Graph.Bin
	}
	if src.Minimalism.Mode != "" {
		dst.Minimalism.Mode = src.Minimalism.Mode
	}
	if src.Spend.DailyCapUSD != 0 {
		dst.Spend.DailyCapUSD = src.Spend.DailyCapUSD
	}
	if src.Spend.HaltFile != "" {
		dst.Spend.HaltFile = src.Spend.HaltFile
	}
	if src.Quotas != nil {
		dst.Quotas = append([]QuotaWindow(nil), src.Quotas...)
	}
	if src.PolicyRules != nil {
		dst.PolicyRules = append([]policy.ConditionRule(nil), src.PolicyRules...)
	}
	if src.Doctrine.RequireCleanup {
		dst.Doctrine.RequireCleanup = true
	}
	if src.Doctrine.UnenforceableRuleAction != "" {
		dst.Doctrine.UnenforceableRuleAction = src.Doctrine.UnenforceableRuleAction
	}
	if src.Doctrine.TranscriptConformanceAction != "" {
		dst.Doctrine.TranscriptConformanceAction = src.Doctrine.TranscriptConformanceAction
	}
	if src.Doctrine.ExactRestoreUnattended != "" {
		dst.Doctrine.ExactRestoreUnattended = src.Doctrine.ExactRestoreUnattended
	}
	if src.Defaults.Agent != "" {
		dst.Defaults.Agent = src.Defaults.Agent
	}
	if src.Defaults.MaxMinutes > 0 {
		dst.Defaults.MaxMinutes = src.Defaults.MaxMinutes
	}
	if src.Assay.Repo != "" {
		dst.Assay.Repo = src.Assay.Repo
	}
	if src.Assay.Python != "" {
		dst.Assay.Python = src.Assay.Python
	}
	if src.Attest.ProbeTimeoutSeconds > 0 {
		dst.Attest.ProbeTimeoutSeconds = src.Attest.ProbeTimeoutSeconds
	}
	if src.Attest.TotalDeadlineSeconds > 0 {
		dst.Attest.TotalDeadlineSeconds = src.Attest.TotalDeadlineSeconds
	}
	if src.Assay.TimeoutSeconds > 0 {
		dst.Assay.TimeoutSeconds = src.Assay.TimeoutSeconds
	}
	if src.Containment.OverridePublicKey != "" {
		dst.Containment.OverridePublicKey = src.Containment.OverridePublicKey
	}
	if src.Containment.LocalEffectfulTiering != "" {
		dst.Containment.LocalEffectfulTiering = src.Containment.LocalEffectfulTiering
	}
	if src.Credentials.Roots != nil {
		dst.Credentials.Roots = append([]string(nil), src.Credentials.Roots...)
	}
}

func applyEnv(cfg *Config) {
	if value := firstEnv("GOV_PROTECTED_PATHS", "GOV_PROTECTED_MANIFEST"); value != "" {
		cfg.ProtectedManifest = value
	} else if state := Env("CLAUDE_HARNESS_STATE"); state != "" {
		cfg.ProtectedManifest = filepath.Join(state, "protected_paths.txt")
	}
	if value := firstEnv("GOV_SNAPSHOT_DIR", "HARNESS_SNAPSHOT_DIR"); value != "" {
		cfg.SnapshotDir = value
	}
	if value := Env("GOV_SNAPSHOT_ROOTS"); value != "" {
		cfg.SnapshotRoots = splitPathList(value)
	}
	if value := Env("GOV_CREDENTIAL_ROOTS"); value != "" {
		cfg.Credentials.Roots = splitPathList(value)
	}
	if value := firstEnv("GOV_LEDGER_DIR", "GOV_HOME", "GOVERNATOR_HOME"); value != "" {
		cfg.LedgerDir = value
		// Keep the still-default halt file next to the ledger it guards when
		// the home is overridden: the spend cap reads the ledger under this
		// home, so consulting ~/.governator/HALT from a GOV_HOME-isolated run
		// (tests especially) would let a real operator halt bleed into every
		// isolated environment. An explicit spend.halt_file in the config
		// file, or GOV_SPEND_HALT_FILE (applied below), still wins.
		if cfg.Spend.HaltFile == filepath.Join(HomeDir(), ".governator", "HALT") {
			cfg.Spend.HaltFile = filepath.Join(value, "HALT")
		}
	}
	for name, backend := range cfg.Backends {
		envName := "GOV_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_")) + "_BIN"
		if name == "claude-code" {
			envName = "GOV_CLAUDE_BIN"
		}
		if value := Env(envName); value != "" {
			backend.Bin = value
			cfg.Backends[name] = backend
		}
	}
	if value := Env("GOV_RTK_MODE"); value != "" {
		cfg.RTK.Mode = value
	}
	if value := Env("GOV_RTK_BIN"); value != "" {
		cfg.RTK.Bin = value
	}
	if value := Env("GOV_GRAPH_MODE"); value != "" {
		cfg.Graph.Mode = value
	}
	if value := Env("GOV_GRAPH_PROVIDER"); value != "" {
		cfg.Graph.Provider = value
	}
	if value := Env("GOV_GRAPH_BIN"); value != "" {
		cfg.Graph.Bin = value
	}
	if value := Env("GOV_MINIMALISM_MODE"); value != "" {
		cfg.Minimalism.Mode = value
	}
	if value := Env("GOV_SPEND_DAILY_CAP_USD"); value != "" {
		if cap, err := strconv.ParseFloat(value, 64); err == nil && cap >= 0 {
			cfg.Spend.DailyCapUSD = cap
		}
	}
	if value := Env("GOV_SPEND_HALT_FILE"); value != "" {
		cfg.Spend.HaltFile = value
	}
	if value := Env("GOV_DOCTRINE_REQUIRE_CLEANUP"); value != "" {
		if b, err := strconv.ParseBool(value); err == nil {
			cfg.Doctrine.RequireCleanup = b
		}
	}
	if value := Env("GOV_UNENFORCEABLE_RULE_ACTION"); value != "" {
		cfg.Doctrine.UnenforceableRuleAction = value
	}
	if value := Env("GOV_TRANSCRIPT_CONFORMANCE_ACTION"); value != "" {
		cfg.Doctrine.TranscriptConformanceAction = value
	}
	if value := Env("GOV_EXACT_RESTORE_UNATTENDED"); value != "" {
		cfg.Doctrine.ExactRestoreUnattended = value
	}
	if value := Env("GOV_DEFAULT_AGENT"); value != "" {
		cfg.Defaults.Agent = value
	}
	if value := Env("GOV_DEFAULT_MAX_MINUTES"); value != "" {
		if minutes, err := strconv.Atoi(value); err == nil && minutes > 0 {
			cfg.Defaults.MaxMinutes = minutes
		}
	}
	if value := Env("GOV_ASSAY_REPO"); value != "" {
		cfg.Assay.Repo = value
	}
	if value := Env("GOV_ASSAY_PYTHON"); value != "" {
		cfg.Assay.Python = value
	}
	if value := Env("GOV_ASSAY_TIMEOUT_SECONDS"); value != "" {
		if seconds, err := strconv.Atoi(value); err == nil && seconds > 0 {
			cfg.Assay.TimeoutSeconds = seconds
		}
	}
	if value := Env("GOV_CONTAINMENT_OVERRIDE_PUBLIC_KEY"); value != "" {
		cfg.Containment.OverridePublicKey = value
	}
	if value := Env("GOV_CONTAINMENT_LOCAL_EFFECTFUL_TIERING"); value != "" {
		cfg.Containment.LocalEffectfulTiering = value
	}
}

func firstEnv(names ...string) string {
	for _, name := range names {
		if value := Env(name); value != "" {
			return value
		}
	}
	return ""
}

func splitPathList(value string) []string {
	var out []string
	for _, item := range strings.Split(value, string(os.PathListSeparator)) {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

func clean(cfg *Config) {
	cfg.RTK.Mode = strings.ToLower(strings.TrimSpace(cfg.RTK.Mode))
	cfg.RTK.Bin = strings.TrimSpace(cfg.RTK.Bin)
	cfg.Graph.Mode = strings.ToLower(strings.TrimSpace(cfg.Graph.Mode))
	cfg.Graph.Provider = strings.ToLower(strings.TrimSpace(cfg.Graph.Provider))
	cfg.Graph.Bin = strings.TrimSpace(cfg.Graph.Bin)
	cfg.Minimalism.Mode = strings.ToLower(strings.TrimSpace(cfg.Minimalism.Mode))
	cfg.Spend.HaltFile = expand(cfg.Spend.HaltFile)
	for i := range cfg.Quotas {
		cfg.Quotas[i].Backend = strings.ToLower(strings.TrimSpace(cfg.Quotas[i].Backend))
		cfg.Quotas[i].Account = strings.ToLower(strings.TrimSpace(cfg.Quotas[i].Account))
		cfg.Quotas[i].WindowType = strings.ToLower(strings.TrimSpace(cfg.Quotas[i].WindowType))
	}
	cfg.ProtectedManifest = expand(cfg.ProtectedManifest)
	cfg.SnapshotDir = expand(cfg.SnapshotDir)
	cfg.LedgerDir = expand(cfg.LedgerDir)
	cfg.Assay.Python = strings.TrimSpace(cfg.Assay.Python)
	if strings.TrimSpace(cfg.Assay.Repo) != "" {
		cfg.Assay.Repo = expand(cfg.Assay.Repo)
	}
	for i := range cfg.SnapshotRoots {
		cfg.SnapshotRoots[i] = expand(cfg.SnapshotRoots[i])
	}
	for i := range cfg.Credentials.Roots {
		cfg.Credentials.Roots[i] = expand(cfg.Credentials.Roots[i])
	}
}

func expand(path string) string {
	if path == "~" {
		return HomeDir()
	}
	if strings.HasPrefix(path, "~/") {
		path = filepath.Join(HomeDir(), path[2:])
	}
	return filepath.Clean(os.ExpandEnv(path))
}

func BackendBin(name string) string {
	cfg := Current()
	if backend, ok := cfg.Backends[name]; ok && backend.Bin != "" {
		return backend.Bin
	}
	return name
}

// finite reports whether f is a real, representable number — neither NaN
// nor +/-Inf.
func finite(f float64) bool {
	return !math.IsNaN(f) && !math.IsInf(f, 0)
}

// quotaTimestampLayouts mirrors internal/quota's parseTimeOrZero accepted
// formats exactly, so a timestamp LoadStrict accepts is guaranteed to be one
// quota.SeedFromConfig can actually parse (rather than silently zeroing).
var quotaTimestampLayouts = []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05", "2006-01-02"}

func parsableTimestamp(s string) bool {
	for _, layout := range quotaTimestampLayouts {
		if _, err := time.Parse(layout, s); err == nil {
			return true
		}
	}
	return false
}

// validateRawSuppliedValues re-decodes data generically (no struct, no
// merge) to see exactly what the operator wrote for the handful of int
// fields whose merge() gate ("only overwrite the default when > 0" — see
// merge's own comments) makes a negative supplied value indistinguishable
// from an omitted one by the time anything downstream could validate it.
// Sol P1.2 (finding #9) names these four explicitly: defaults.max_minutes,
// assay.timeout_seconds, and every backend's context_tokens/output_tokens.
// A zero max_minutes/timeout_seconds is rejected too (a job or assay call
// cannot run in zero time); zero context/output tokens is left alone — it
// is this codebase's existing, intentional "not declared" state for those
// two fields (see Backend's doc comment and the BuiltIn zero default), not
// a value anyone would ever mean literally.
func validateRawSuppliedValues(data []byte, path string) error {
	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("decode config %s: %w", path, err)
	}
	if raw == nil {
		return nil
	}
	if v, ok := rawNumber(raw, "defaults", "max_minutes"); ok {
		if v <= 0 {
			return fmt.Errorf("invalid defaults.max_minutes %v (want > 0)", v)
		}
	}
	if v, ok := rawNumber(raw, "assay", "timeout_seconds"); ok {
		if v <= 0 {
			return fmt.Errorf("invalid assay.timeout_seconds %v (want > 0)", v)
		}
	}
	if v, ok := rawNumber(raw, "attest", "probe_timeout_seconds"); ok {
		if v <= 0 {
			return fmt.Errorf("invalid attest.probe_timeout_seconds %v (want > 0)", v)
		}
	}
	if v, ok := rawNumber(raw, "attest", "total_deadline_seconds"); ok {
		if v <= 0 {
			return fmt.Errorf("invalid attest.total_deadline_seconds %v (want > 0)", v)
		}
	}
	if backends, ok := raw["backends"].(map[string]any); ok {
		for name, b := range backends {
			bm, ok := b.(map[string]any)
			if !ok {
				continue
			}
			if v, ok := rawNumber(bm, "context_tokens"); ok && v < 0 {
				return fmt.Errorf("invalid backends.%s.context_tokens %v (want >= 0)", name, v)
			}
			if v, ok := rawNumber(bm, "output_tokens"); ok && v < 0 {
				return fmt.Errorf("invalid backends.%s.output_tokens %v (want >= 0)", name, v)
			}
		}
	}
	return nil
}

// rawNumber walks path through nested map[string]any values (as produced by
// yaml.Unmarshal into `any`) and, if the final key is present and holds a
// YAML scalar number, returns it as a float64. Ok is false if any
// intermediate key is absent/not a map, or the final value isn't numeric —
// callers only act when ok is true, so an absent field is silently treated
// as "not supplied" exactly like the struct decode already does.
func rawNumber(m map[string]any, path ...string) (float64, bool) {
	cur := any(m)
	for _, key := range path {
		asMap, ok := cur.(map[string]any)
		if !ok {
			return 0, false
		}
		cur, ok = asMap[key]
		if !ok {
			return 0, false
		}
	}
	switch t := cur.(type) {
	case int:
		return float64(t), true
	case int64:
		return float64(t), true
	case uint64:
		return float64(t), true
	case float64:
		return t, true
	default:
		return 0, false
	}
}
