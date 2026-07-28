// Package router is the Governator route broker: it resolves an agent: auto
// contract to a concrete backend using structured signals only. It sits
// between contract validation and backend launch, closing the loop the
// evidence substrate (ledger stats, capability matrix, spend estimates)
// always supported but nothing wired together.
//
// Standing rules enforced here:
//   - Fail closed. An unsatisfiable hard requirement refuses to run rather
//     than silently widening the pool.
//   - Structured signals only. Route on job_type, risk_class, budgets,
//     capability requirements, and ledger evidence — never task text. Mode is
//     carried on Request for downstream context (e.g. `gov route --explain`
//     display) but is deliberately score-neutral: risk_class is the intended
//     lever for "route this one more conservatively," and doubling that up
//     with an implicit mode-based nudge would make decisions harder to
//     explain from the ledger (rule 4).
//   - Infrastructure and quality failures are separate metrics. The breaker
//     (Session 2) carries infra signals only; quality scores never touch it.
//   - Determinism. No LLM calls. Plain Go + the ledger.
package router

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os/exec"
	"sort"
	"strings"

	"github.com/cousingary/governator/internal/agents"
	"github.com/cousingary/governator/internal/config"
	"github.com/cousingary/governator/internal/contracts"
	"github.com/cousingary/governator/internal/observability"
	"github.com/cousingary/governator/internal/spend"
)

// RegisteredAgents is the canonical, sorted candidate pool the broker draws
// from when a contract names no allowlist. It mirrors internal/agents.New;
// contracts.validAgents and router_test cross-check keep them in sync.
func RegisteredAgents() []string {
	return []string{"claude-code", "codex", "glm", "opencode", "pi"}
}

// RequestFromContract builds a broker Request from an agent: auto contract.
// It is nil-safe on the routing block: agent: auto with no routing: block
// routes over every registered backend under the balanced default. Objective
// defaults are applied inside Resolve, so callers need not normalize.
func RequestFromContract(c contracts.Contract) Request {
	req := Request{
		JobID:         c.JobID,
		JobType:       c.JobType,
		Mode:          c.Mode,
		RiskClass:     c.RiskClass,
		MaxTokens:     c.Budget.MaxTokens,
		RepairLineage: c.RepairLineage,
	}
	if c.Routing != nil {
		req.Objective = c.Routing.Objective
		req.Candidates = c.Routing.Candidates
		req.Requirements = c.Routing.Requirements
	}
	return req
}

// BreakerState is the circuit-breaker state for a backend (Session 2). The
// broker hard-excludes OPEN backends and penalizes DEGRADED ones; quality
// failures never reach the breaker (rule 3).
type BreakerState string

const (
	BreakerClosed   BreakerState = "CLOSED"
	BreakerDegraded BreakerState = "DEGRADED"
	BreakerOpen     BreakerState = "OPEN"
)

// BreakerSnapshot is the breaker view of one backend at decision time.
type BreakerSnapshot struct {
	State  BreakerState
	Reason string
}

// QuotaSnapshot is the subscription-headroom view of one backend (Session 4).
// Available=false means no telemetry: the broker does not penalize a backend
// for quota data it cannot see.
type QuotaSnapshot struct {
	HeadroomPct float64 // 0..1 remaining headroom; 1.0 = full
	Available   bool    // false = no quota telemetry (do not penalize)
}

// HealthSource reports infrastructure health (breaker + quota) for a backend.
// It carries infrastructure signals only — never quality — so a provider
// outage can never lower a quality score and bad output can never open a
// breaker (rule 3). A nil HealthSource means every backend reports healthy:
// the safe default for offline tests. Production callers inject breaker.Store
// (breaker added in Session 2, quota in Session 4; both live).
type HealthSource interface {
	Breaker(agent string) BreakerSnapshot
	Quota(agent string) QuotaSnapshot
}

// Request is the input to a routing decision. Every field is structured —
// job_type, mode, budgets, capability requirements, ledger evidence — so the
// broker never sniffs task text (rule 2).
type Request struct {
	JobID         string
	JobType       string
	Mode          contracts.Mode
	RiskClass     string                        // low|medium|high; empty = scoring-neutral
	Objective     string                        // balanced|cheapest|most_reliable; empty = balanced
	Candidates    []string                      // allowlist; empty = all registered
	Requirements  contracts.RoutingRequirements // hard capability filters (fail closed)
	MaxTokens     int                           // sizes spend.EstimateCostUSD
	RepairLineage string                        // root run id; non-empty = repair job (affinity)

	// ExcludeAgents hard-excludes named candidates from this decision. It is
	// never set from a contract (RequestFromContract leaves it empty) — it is
	// runtime orchestration state a caller builds per call, the same tier as
	// a capability requirement miss. internal/runtime.resolvePanelBackends is
	// the first caller: it grows this set across a panel's members so a
	// backend already assigned to an earlier member is excluded from later
	// ones (Phase 2 diversity).
	ExcludeAgents []string
}

// ScoredCandidate is one evaluated backend in a decision. Every component is
// recorded separately so the decision is fully explainable from the ledger
// alone (rule 4).
//
// AssayQualityScore (plan v1.4 Session 2 item 4, closing the gap Phase 7
// deliberately left open — see observability/phase7.go's package doc:
// "Nothing here feeds back into routing... that boundary is Phase 3C's job")
// is the one component this evidence feeds into Total. It blends four
// evidence-backed rate signals — assay pass rate, validator pass rate,
// repair success rate, and panel agreement rate — each neutral (0.5) when
// there is no evidence yet, same idiom as ValidRateScore. AssayPassRate,
// ValidatorPassRate, RepairSuccessRate, PanelAgreementRate, and
// CostPerAcceptedUSD are the underlying raw evidence, recorded separately
// and unweighted (rule 4) so `gov route --explain` shows exactly what fed
// the blended score instead of only the blend itself. CostPerAcceptedUSD is
// informational only (0 = no evidence) — cost preference is already fully
// handled by CostScore's own estimate-based mechanism below; this field
// exists for visibility, not to double-count cost in Total.
type ScoredCandidate struct {
	Agent                string
	ValidRateScore       float64
	FailureSeverityScore float64
	CostScore            float64
	BreakerScore         float64
	QuotaScore           float64
	RepairAffinityScore  float64
	AssayQualityScore    float64
	AssayPassRate        float64
	ValidatorPassRate    float64
	RepairSuccessRate    float64
	PanelAgreementRate   float64
	CostPerAcceptedUSD   float64
	Total                float64
	Excluded             bool
	ExclusionReason      string
	Selected             bool
}

// Decision is the broker's output: the objective, the full scored candidate
// table (excluded candidates included, with reasons), and the selected
// backend (empty when fail-closed). Selected is the highest-total
// non-excluded candidate; ties break by name for reproducibility (rule 5).
// PolicyHash identifies the exact scoring weights + requirement set that
// produced this decision (see policyHash) — two decisions with the same hash
// used the identical policy even if the ledger evidence they scored differed.
type Decision struct {
	Objective  string
	JobID      string
	JobType    string
	RiskClass  string
	PolicyHash string
	Selected   string
	Candidates []ScoredCandidate
}

// Router resolves agent: auto to a concrete backend. It is deterministic (no
// LLM calls), reads only the ledger, and fails closed when no healthy
// candidate satisfies a hard requirement. Health and Binary are optional
// injection points: nil Health = every backend healthy; nil Binary = the
// default LookPath probe (S1 binary presence; full flag-drift comes via the
// doctor-gated breaker in Session 2).
type Router struct {
	Health HealthSource
	Binary func(name string) bool
	// ModelCapability overlays operator-declared model facts (vision, tool
	// calling, locality, context/output limits) onto a candidate's static
	// capability profile. nil = defaultModelCapability, which reads
	// config.Current().Backends[name] once per Resolve call. Tests inject a
	// stub so requirement checks never depend on the host's real config.yaml
	// (the same reason Binary is injectable).
	ModelCapability func(name string, base agents.Capability) agents.Capability
}

// Resolve evaluates every candidate and returns a Decision. It never returns
// an error for "no candidate qualifies" — that is the normal fail-closed
// outcome, expressed as Decision.Selected == "" with every candidate excluded.
// An error means the broker could not read its evidence (a broken ledger).
func (r Router) Resolve(db *sql.DB, req Request, cfg config.Config) (Decision, error) {
	objective := req.Objective
	if objective == "" {
		objective = "balanced"
	}
	weights := riskAdjustedWeights(objectiveWeights(objective), req.RiskClass)
	// cfg is the caller's frozen RunEnvironment.Config (Sol Finding 2 /
	// Session 3) — Resolve used to call config.Current() here itself,
	// re-reading config.yaml from disk independently of whatever the rest of
	// the run had already frozen. A decision only has a handful of
	// candidates, so threading one already-loaded value through costs
	// nothing.
	candidates := r.candidatePool(req.Candidates)
	lineageAgent, err := lineageAgentFor(db, req.RepairLineage)
	if err != nil {
		return Decision{}, err
	}
	scored := make([]ScoredCandidate, 0, len(candidates))
	for _, name := range candidates {
		scored = append(scored, r.evaluate(db, name, req, weights, lineageAgent, cfg))
	}
	// cost is normalized across the non-excluded pool, so a second pass fills
	// CostScore and recomputes Total for the survivors once every raw cost is
	// known.
	finalizeCosts(scored, req.MaxTokens, weights)
	recomputeTotals(scored, weights)
	selectWinner(scored)
	return Decision{
		Objective:  objective,
		JobID:      req.JobID,
		JobType:    req.JobType,
		RiskClass:  req.RiskClass,
		PolicyHash: policyHash(weights, req),
		Selected:   selectedAgent(scored),
		Candidates: orderForDisplay(scored),
	}, nil
}

// candidatePool returns the de-duplicated, canonical-named, sorted candidate
// list. Empty input yields every registered backend. Each name is normalized
// through agents.New so the "claude" alias collapses to "claude-code" — the
// same name recorded in agent_profiles — keeping profile queries aligned.
func (r Router) candidatePool(allowlist []string) []string {
	raw := allowlist
	if len(raw) == 0 {
		raw = RegisteredAgents()
	}
	seen := make(map[string]bool, len(raw))
	out := make([]string, 0, len(raw))
	for _, name := range raw {
		agent, err := agents.New(name)
		if err != nil {
			// Validation already rejected unknown candidates; if one reaches
			// here anyway, skip it rather than panic mid-decision.
			continue
		}
		canonical := agent.Name()
		if !seen[canonical] {
			seen[canonical] = true
			out = append(out, canonical)
		}
	}
	sort.Strings(out)
	return out
}

func (r Router) health() HealthSource {
	if r.Health == nil {
		return closedHealth{}
	}
	return r.Health
}

func (r Router) binaryProbe() func(string) bool {
	if r.Binary != nil {
		return r.Binary
	}
	return defaultBinaryPresent
}

// modelCapability overlays operator-declared model facts onto base. The
// default path reads cfg.Backends[name] (a zero-value config.Backend when
// the operator declared nothing, leaving every model field at its
// fail-closed default — see agents.WithConfiguredModel); r.ModelCapability
// overrides it so tests never depend on the host's real config.yaml.
func (r Router) modelCapability(cfg config.Config, name string, base agents.Capability) agents.Capability {
	if r.ModelCapability != nil {
		return r.ModelCapability(name, base)
	}
	return agents.WithConfiguredModel(base, cfg.Backends[name])
}

// defaultBinaryPresent is the S1 binary-health floor: the backend's configured
// binary resolves in PATH. It runs no --help/--version probe (that flag-drift
// check is the doctor's job, surfaced through the Session 2 breaker), so it is
// cheap and offline-safe in tests via Binary injection.
func defaultBinaryPresent(name string) bool {
	bin := config.BackendBin(name)
	if bin == "" {
		bin = name
	}
	if _, err := exec.LookPath(bin); err != nil {
		return false
	}
	return true
}

// closedHealth is the nil-HealthSource stand-in: every backend CLOSED and
// every quota unmeasured, so neither infra signal differentiates candidates.
// Production callers inject breaker.Store; this fallback only fires for
// offline tests and other callers that construct a Router without Health.
type closedHealth struct{}

func (closedHealth) Breaker(string) BreakerSnapshot { return BreakerSnapshot{State: BreakerClosed} }
func (closedHealth) Quota(string) QuotaSnapshot     { return QuotaSnapshot{Available: false} }

// evaluate scores one candidate. Hard exclusions (capability, binary, OPEN
// breaker) mark the candidate Excluded and short-circuit the soft scores.
func (r Router) evaluate(db *sql.DB, name string, req Request, w weightSet, lineageAgent string, cfg config.Config) ScoredCandidate {
	candidate := ScoredCandidate{Agent: name}
	if containsAgent(req.ExcludeAgents, name) {
		return excluded(candidate, "diversity_exclusion")
	}
	cap, err := agents.New(name)
	if err != nil {
		return excluded(candidate, "unknown backend")
	}
	capability := r.modelCapability(cfg, name, cap.Capabilities())
	if req.Requirements.NativeSandbox && !capability.NativeSandbox {
		return excluded(candidate, "native_sandbox required")
	}
	if req.Requirements.NetworkControl && !capability.NetworkControl {
		return excluded(candidate, "network_control required")
	}
	if req.Requirements.ReadOnlyMode && !capability.NativeReadOnly {
		return excluded(candidate, "read_only_mode required")
	}
	if req.Requirements.Vision && !capability.Vision {
		return excluded(candidate, "vision required")
	}
	if req.Requirements.ToolCalling && !capability.ToolCalling {
		return excluded(candidate, "tool_calling required")
	}
	if req.Requirements.LocalOnly && !capability.LocalOnly {
		return excluded(candidate, "local_only required")
	}
	if req.Requirements.MinContextTokens > 0 && capability.ContextTokens < req.Requirements.MinContextTokens {
		return excluded(candidate, fmt.Sprintf("min_context_tokens required (need >= %d, have %d)", req.Requirements.MinContextTokens, capability.ContextTokens))
	}
	if req.Requirements.MinOutputTokens > 0 && capability.OutputTokens < req.Requirements.MinOutputTokens {
		return excluded(candidate, fmt.Sprintf("min_output_tokens required (need >= %d, have %d)", req.Requirements.MinOutputTokens, capability.OutputTokens))
	}
	if !r.binaryProbe()(name) {
		return excluded(candidate, "binary_missing")
	}
	h := r.health()
	breaker := h.Breaker(name)
	if breaker.State == BreakerOpen {
		return excluded(candidate, "breaker_open"+reasonSuffix(breaker.Reason))
	}

	// Soft scores.
	runs, valid, severityRate := evidenceFor(db, name, req.JobType)
	candidate.ValidRateScore = validRateComponent(runs, valid)
	candidate.FailureSeverityScore = severityComponent(severityRate)
	candidate.BreakerScore = breakerScore(breaker.State)
	quota := h.Quota(name)
	candidate.QuotaScore = quotaScore(quota)
	candidate.RepairAffinityScore = affinityScore(req.RepairLineage, lineageAgent, name)
	candidate.CostScore = 0 // finalizeCosts fills this in the pool pass.
	assayEvidence := assayEvidenceFor(db, name, req.JobType)
	candidate.AssayPassRate = assayEvidence.assayPassRate
	candidate.ValidatorPassRate = assayEvidence.validatorPassRate
	candidate.RepairSuccessRate = assayEvidence.repairSuccessRate
	candidate.PanelAgreementRate = assayEvidence.panelAgreementRate
	candidate.CostPerAcceptedUSD = assayEvidence.costPerAcceptedUSD
	candidate.AssayQualityScore = assayQualityComponent(assayEvidence)
	candidate.Total = totalScore(candidate, w)
	return candidate
}

func excluded(c ScoredCandidate, reason string) ScoredCandidate {
	c.Excluded = true
	c.ExclusionReason = reason
	return c
}

// containsAgent reports whether name (already canonical — evaluate is called
// per candidatePool entry, which is always agents.New-normalized) appears in
// values. A plain loop, not a set: ExcludeAgents is at most a handful of
// entries per panel member.
func containsAgent(values []string, name string) bool {
	for _, v := range values {
		if v == name {
			return true
		}
	}
	return false
}

func reasonSuffix(reason string) string {
	if reason == "" {
		return ""
	}
	return ": " + reason
}

// weightSet holds the per-objective component weights. The objective shifts
// weights but never bypasses a hard exclusion. Weights sum to 1.0; the
// breaker and quota weights are live and discriminating whenever
// breaker.Store has telemetry (production callers always inject it).
type weightSet struct {
	validRate    float64
	severity     float64
	cost         float64
	breaker      float64
	quota        float64
	affinity     float64
	assayQuality float64
}

// objectiveWeights' three presets each gained a modest assayQuality slice
// (plan Session 2 item 4), taken mainly from cost/validRate so every preset
// still sums to exactly 1.0. assayQuality is neutral (0.5, see
// assayQualityComponent) for any candidate with no assay/validator/repair/
// panel evidence yet, so a ledger with none of that evidence recorded routes
// identically to how it did before this field existed.
func objectiveWeights(objective string) weightSet {
	switch objective {
	case "cheapest":
		return weightSet{validRate: 0.18, severity: 0.10, cost: 0.50, breaker: 0.05, quota: 0.05, affinity: 0.05, assayQuality: 0.07}
	case "most_reliable":
		return weightSet{validRate: 0.30, severity: 0.28, cost: 0.05, breaker: 0.18, quota: 0.05, affinity: 0.05, assayQuality: 0.09}
	default: // "balanced" and any unrecognized value (validation rejects those)
		return weightSet{validRate: 0.27, severity: 0.15, cost: 0.22, breaker: 0.10, quota: 0.05, affinity: 0.15, assayQuality: 0.06}
	}
}

// riskAdjustedWeights nudges the objective's weights toward reliability for a
// risky job by moving a bounded slice of the cost weight onto valid-rate,
// severity, breaker, and assay quality — the four reliability components —
// split proportionally (40/25/20/15) so the total stays exactly 1.0.
// assayQuality joined this split in Session 2: an evidence-backed quality
// signal is exactly as much a "reliability component" as valid rate or
// breaker state, and gets a smaller slice than valid rate/severity because it
// is a blend of several second-order rates rather than the run's own direct
// outcome. It never touches quota or affinity (rule 3: infra/quality signals
// stay separate from anything risk-flavored) and never bypasses a hard
// exclusion — only soft scores among survivors move. "low" and an unset
// RiskClass are a deliberate no-op: unset keeps every prior agent: auto
// contract routing exactly as it did before RiskClass existed, and "low"
// means "score this the way the chosen objective already would."
func riskAdjustedWeights(w weightSet, risk string) weightSet {
	var shift float64
	switch risk {
	case "high":
		shift = 0.15
	case "medium":
		shift = 0.05
	default: // "low", "", and any unrecognized value (validation rejects those)
		return w
	}
	if shift > w.cost {
		shift = w.cost
	}
	w.cost -= shift
	w.validRate += shift * 0.40
	w.severity += shift * 0.25
	w.breaker += shift * 0.20
	w.assayQuality += shift * 0.15
	return w
}

// policyHash fingerprints the exact scoring weights and requirement set
// behind a decision: a short hex digest an operator (or `gov route
// --explain`) can compare across two decisions to confirm they used the
// identical policy, without diffing source or trusting memory of which
// weights were live on a given day. w is the final, risk-adjusted weightSet
// actually used to score every candidate in this decision.
func policyHash(w weightSet, req Request) string {
	r := req.Requirements
	material := fmt.Sprintf(
		"weights:valid=%.4f,severity=%.4f,cost=%.4f,breaker=%.4f,quota=%.4f,affinity=%.4f,assay_quality=%.4f|"+
			"requirements:native_sandbox=%t,network_control=%t,read_only_mode=%t,vision=%t,tool_calling=%t,local_only=%t,min_context_tokens=%d,min_output_tokens=%d",
		w.validRate, w.severity, w.cost, w.breaker, w.quota, w.affinity, w.assayQuality,
		r.NativeSandbox, r.NetworkControl, r.ReadOnlyMode, r.Vision, r.ToolCalling, r.LocalOnly,
		r.MinContextTokens, r.MinOutputTokens,
	)
	sum := sha256.Sum256([]byte(material))
	return hex.EncodeToString(sum[:8]) // 16 hex chars (64 bits): enough to spot drift, short enough for a ledger row / CLI table
}

func totalScore(c ScoredCandidate, w weightSet) float64 {
	return c.ValidRateScore*w.validRate +
		c.FailureSeverityScore*w.severity +
		c.CostScore*w.cost +
		c.BreakerScore*w.breaker +
		c.QuotaScore*w.quota +
		c.RepairAffinityScore*w.affinity +
		c.AssayQualityScore*w.assayQuality
}

func recomputeTotals(scored []ScoredCandidate, w weightSet) {
	for i := range scored {
		if scored[i].Excluded {
			continue
		}
		scored[i].Total = totalScore(scored[i], w)
	}
}

// validRateComponent is the historical valid-output rate for (agent, job_type)
// from agent_profiles. No evidence (runs==0) is neutral 0.5: a brand-new
// backend is neither penalized for being unproven nor rewarded over a proven
// one — the cost and capability signals still differentiate it.
func validRateComponent(runs, valid int) float64 {
	if runs <= 0 {
		return 0.5
	}
	return clampUnit(float64(valid) / float64(runs))
}

// failureSeverity weights quality-failure taxonomies by severity and returns
// the severity-weighted failure RATE (severe failures count more). The score
// component (severityComponent) inverts it: milder-failure backends score
// higher. Infra taxonomies do not exist yet (Session 2) and SPEND_CAP is never
// booked to agent_profiles, so every taxonomy here is a quality kind — the
// rule that quality and infra are separate metrics holds.
var failureSeverity = map[string]float64{
	"SCOPE_DRIFT":           1.0,
	"OVERWRITE_RISK":        1.0,
	"DESTRUCTIVE_COMMAND":   1.0,
	"UNAUTHORIZED_REFACTOR": 1.0,
	"REPEATED_COMMAND_LOOP": 0.7,
	"POLICY_VIOLATION":      0.7,
	"AGENT_FAILURE":         0.7,
	"VALIDATION_FAILED":     0.4,
	"BUDGET_EXCEEDED":       0.4,
}

// severityWeight treats a taxonomy missing from the table as medium (0.7):
// ClassifyFailure defaults unknowns to POLICY_VIOLATION today, but a future
// taxonomy must still count as a failure rather than silently weigh zero.
func severityWeight(taxonomy string) float64 {
	if w, ok := failureSeverity[taxonomy]; ok {
		return w
	}
	return 0.7
}

func severityRateOf(counts map[string]int, runs int) float64 {
	if runs <= 0 {
		return 0
	}
	weighted := 0.0
	for taxonomy, n := range counts {
		weighted += severityWeight(taxonomy) * float64(n)
	}
	return clampUnit(weighted / float64(runs))
}

func severityComponent(severityRate float64) float64 {
	return clampUnit(1 - severityRate)
}

func breakerScore(state BreakerState) float64 {
	switch state {
	case BreakerDegraded:
		return 0.5
	default: // CLOSED (OPEN is excluded before scoring)
		return 1.0
	}
}

func quotaScore(q QuotaSnapshot) float64 {
	if !q.Available {
		return 1.0 // no telemetry — do not penalize
	}
	return clampUnit(q.HeadroomPct)
}

// affinityScore gives a repair job a clear (not absolute) preference for the
// backend that ran the run it is repairing. Non-repair jobs are neutral 1.0,
// so the affinity weight does not differentiate them.
func affinityScore(repairLineage, lineageAgent, candidate string) float64 {
	if repairLineage == "" {
		return 1.0
	}
	if candidate == lineageAgent && lineageAgent != "" {
		return 1.0
	}
	return 0.0
}

func clampUnit(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

// finalizeCosts assigns CostScore by min-max normalizing raw cost estimates
// across the non-excluded candidates: cheapest survivor scores 1.0, most
// expensive 0.0. A single survivor has no peer to compare against and scores
// 1.0 (cost cannot differentiate a one-candidate pool). Excluded candidates
// keep CostScore 0; their Total is irrelevant.
func finalizeCosts(scored []ScoredCandidate, maxTokens int, _ weightSet) {
	minCost, maxCost := -1.0, -1.0
	for i := range scored {
		if scored[i].Excluded {
			continue
		}
		c := spend.EstimateCostUSD(scored[i].Agent, maxTokens, nil)
		if minCost < 0 || c < minCost {
			minCost = c
		}
		if maxCost < 0 || c > maxCost {
			maxCost = c
		}
	}
	for i := range scored {
		if scored[i].Excluded {
			continue
		}
		c := spend.EstimateCostUSD(scored[i].Agent, maxTokens, nil)
		if maxCost > minCost {
			scored[i].CostScore = clampUnit((maxCost - c) / (maxCost - minCost))
		} else {
			scored[i].CostScore = 1.0
		}
	}
}

// selectWinner marks the highest-total non-excluded candidate Selected. Ties
// break by ascending name for reproducibility. All-excluded leaves none
// selected (fail closed).
func selectWinner(scored []ScoredCandidate) {
	bestIdx := -1
	for i := range scored {
		if scored[i].Excluded {
			continue
		}
		if bestIdx == -1 ||
			scored[i].Total > scored[bestIdx].Total ||
			(scored[i].Total == scored[bestIdx].Total && scored[i].Agent < scored[bestIdx].Agent) {
			bestIdx = i
		}
	}
	if bestIdx >= 0 {
		scored[bestIdx].Selected = true
	}
}

func selectedAgent(scored []ScoredCandidate) string {
	for _, c := range scored {
		if c.Selected {
			return c.Agent
		}
	}
	return ""
}

// orderForDisplay returns survivors (highest total first, ties by name) then
// excluded candidates (by name), so a printed decision table reads best-first
// while still showing every exclusion.
func orderForDisplay(scored []ScoredCandidate) []ScoredCandidate {
	out := append([]ScoredCandidate(nil), scored...)
	sort.SliceStable(out, func(i, j int) bool {
		ei, ej := out[i].Excluded, out[j].Excluded
		if ei != ej {
			return !ei // non-excluded first
		}
		if !ei {
			if out[i].Total != out[j].Total {
				return out[i].Total > out[j].Total
			}
		}
		return out[i].Agent < out[j].Agent
	})
	return out
}

// lineageAgentFor returns the backend that ran the run a repair job is
// repairing, so the broker can prefer it (repair-lineage affinity). An empty
// lineage (not a repair job) or a missing run yields "" — affinity then falls
// back to neutral for every candidate.
func lineageAgentFor(db *sql.DB, lineage string) (string, error) {
	if lineage == "" {
		return "", nil
	}
	var agent string
	err := db.QueryRow(`SELECT COALESCE(agent,'') FROM runs WHERE id=?`, lineage).Scan(&agent)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return agent, err
}

// evidenceFor reads one (agent, job_type) profile's run/valid counts and its
// quality-failure taxonomy breakdown from the ledger. The taxonomy breakdown
// comes from the runs table (agent_profiles only stores aggregates); SPEND_CAP
// is excluded since it was never booked as a real run. A read error is treated
// as no evidence rather than failing the whole decision — a partial ledger
// should not make routing impossible, and the profile is still the source of
// truth for run/valid totals.
func evidenceFor(db *sql.DB, agent, jobType string) (runs, valid int, severityRate float64) {
	_ = db.QueryRow(`SELECT runs,valid_outputs FROM agent_profiles WHERE agent=? AND job_type=?`, agent, jobType).Scan(&runs, &valid)
	if runs <= 0 {
		return runs, valid, 0
	}
	rows, err := db.Query(`SELECT failure_taxonomy,COUNT(*) FROM runs WHERE agent=? AND job_type=? AND failure_taxonomy<>'' AND failure_taxonomy<>'SPEND_CAP' GROUP BY failure_taxonomy`, agent, jobType)
	if err != nil {
		return runs, valid, 0
	}
	defer rows.Close()
	counts := make(map[string]int)
	for rows.Next() {
		var taxonomy string
		var n int
		if err := rows.Scan(&taxonomy, &n); err != nil {
			return runs, valid, 0
		}
		taxonomy = strings.ToUpper(strings.TrimSpace(taxonomy))
		// Infra failures (Session 2) are recorded in the runs table for
		// visibility but must not influence quality severity — rule 3. They
		// are already excluded from agent_profiles.runs (the denominator), so
		// a failure_kind with zero severity weight would otherwise dilute the
		// rate and marginally flatter a backend that had an outage. Skip them.
		if observability.IsInfraFailure(taxonomy) {
			continue
		}
		counts[taxonomy] = n
	}
	return runs, valid, severityRateOf(counts, runs)
}

// assayEvidence is the raw per-(agent, job_type) quality-feedback evidence
// plan v1.4 Session 2 item 4 asks the router to consult: assay pass rate,
// validator pass rate, repair success rate, panel agreement rate (the
// inverse of disagreement — observability.PanelDisagreementRate's global
// analog), and cost per accepted result. Every rate field already carries
// its own neutral default (0.5 = "no evidence yet," the same idiom
// evidenceFor uses for valid rate) so callers never need a separate
// has-evidence flag. costPerAcceptedUSD defaults to 0 (no evidence) since a
// real accepted run always costs more than $0.
type assayEvidence struct {
	assayPassRate      float64
	validatorPassRate  float64
	repairSuccessRate  float64
	panelAgreementRate float64
	costPerAcceptedUSD float64
}

// assayEvidenceFor reads four independent rate queries plus one cost query,
// every one scoped to (agent, job_type) via a join through runs — the same
// scoping evidenceFor uses for valid rate and severity. A read error on any
// one query degrades only that query to its neutral default rather than
// failing the whole decision (a partial ledger should not make routing
// impossible — same tolerance evidenceFor already has).
func assayEvidenceFor(db *sql.DB, agent, jobType string) assayEvidence {
	return assayEvidence{
		assayPassRate: rateQuery(db,
			`SELECT ae.verdict FROM assay_evaluations ae JOIN runs r ON r.id=ae.run_id WHERE r.agent=? AND r.job_type=? AND ae.verdict<>'skipped'`,
			agent, jobType, isAssayPass),
		validatorPassRate: rateQuery(db,
			`SELECT CASE WHEN v.exit_code=0 THEN 'pass' ELSE 'fail' END FROM validators v JOIN runs r ON r.id=v.run_id WHERE r.agent=? AND r.job_type=?`,
			agent, jobType, isPass),
		repairSuccessRate: rateQuery(db,
			`SELECT status FROM runs WHERE agent=? AND job_type=? AND repair_of<>''`,
			agent, jobType, isApproved),
		panelAgreementRate: panelAgreementRateFor(db, agent, jobType),
		costPerAcceptedUSD: costPerAcceptedFor(db, agent, jobType),
	}
}

func isAssayPass(verdict string) bool {
	return verdict == assayVerdictPass || verdict == assayVerdictAdvisory
}
func isPass(status string) bool     { return status == "pass" }
func isApproved(status string) bool { return status == "APPROVED" }

// assayVerdictPass/assayVerdictAdvisory mirror internal/assay's VerdictPass/
// VerdictAdvisory string constants. router intentionally does not import
// internal/assay for two literal strings — the same reasoning breaker.Config
// uses to avoid an internal/config dependency (avoids growing an import
// graph for a value that will never itself change independently: Assayer's
// four verdict strings are a stable wire contract both sides already commit
// to via internal/assay's own doc comments).
const (
	assayVerdictPass     = "pass"
	assayVerdictAdvisory = "advisory"
)

// rateQuery runs a single-string-column query and returns the fraction of
// rows for which isHit reports true, or the neutral 0.5 default when the
// query errors or returns zero rows (no evidence).
func rateQuery(db *sql.DB, query, agent, jobType string, isHit func(string) bool) float64 {
	rows, err := db.Query(query, agent, jobType)
	if err != nil {
		return 0.5
	}
	defer rows.Close()
	total, hits := 0, 0
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return 0.5
		}
		total++
		if isHit(v) {
			hits++
		}
	}
	if rows.Err() != nil || total == 0 {
		return 0.5
	}
	return clampUnit(float64(hits) / float64(total))
}

// panelAgreementRateFor is the per-(agent, job_type) analog of
// observability.PanelDisagreementRate: same query shape (join panel_members
// to the newest run per (panel_id, job_id), count panels with more than one
// distinct terminal status), scoped to panels this agent was a member of and
// returning agreement (1 - disagreement rate) rather than disagreement, so it
// composes directly into assayQualityComponent alongside the other rates
// (higher = better, like every other component here).
func panelAgreementRateFor(db *sql.DB, agent, jobType string) float64 {
	// govratchet:sql-time-allow(s4_semantics_review)
	rows, err := db.Query(`
SELECT pm.panel_id, pm.job_id, r.status
FROM panel_members pm
JOIN runs r ON r.job_id = pm.job_id
WHERE pm.agent = ? AND r.job_type = ?
ORDER BY pm.panel_id ASC, pm.job_id ASC, r.created DESC`, agent, jobType)
	if err != nil {
		return 0.5
	}
	defer rows.Close()
	seenJob := map[[2]string]bool{}
	statuses := map[string]map[string]bool{}
	for rows.Next() {
		var panelID, jobID, status string
		if err := rows.Scan(&panelID, &jobID, &status); err != nil {
			return 0.5
		}
		jobKey := [2]string{panelID, jobID}
		if seenJob[jobKey] {
			continue
		}
		seenJob[jobKey] = true
		if statuses[panelID] == nil {
			statuses[panelID] = map[string]bool{}
		}
		statuses[panelID][status] = true
	}
	if rows.Err() != nil {
		return 0.5
	}
	panels, disagreements := 0, 0
	for _, distinct := range statuses {
		panels++
		if len(distinct) > 1 {
			disagreements++
		}
	}
	if panels == 0 {
		return 0.5
	}
	return clampUnit(1 - float64(disagreements)/float64(panels))
}

// costPerAcceptedFor averages cost_usd across this agent's APPROVED runs for
// job_type. 0 means no evidence (no approved run recorded yet), same as
// every other "no evidence" default in this file being the value that can
// never occur naturally (a real approved run always costs > $0).
func costPerAcceptedFor(db *sql.DB, agent, jobType string) float64 {
	var cost sql.NullFloat64
	if err := db.QueryRow(`SELECT AVG(cost_usd) FROM runs WHERE agent=? AND job_type=? AND status='APPROVED'`, agent, jobType).Scan(&cost); err != nil {
		return 0
	}
	if !cost.Valid {
		return 0
	}
	return cost.Float64
}

// assayQualityComponent blends the four evidence-backed rate signals into
// one [0,1] score for Total. Each input already carries its own neutral
// default (assayEvidenceFor), so a candidate with zero quality evidence
// anywhere scores exactly 0.5 — identical to how ValidRateScore treats an
// unproven backend: neither penalized nor rewarded. costPerAcceptedUSD is
// deliberately excluded from the blend (see ScoredCandidate's doc comment):
// cost preference already has its own weighted component (CostScore).
func assayQualityComponent(e assayEvidence) float64 {
	return clampUnit((e.assayPassRate + e.validatorPassRate + e.repairSuccessRate + e.panelAgreementRate) / 4)
}

// ErrNoCandidate is returned by the runtime layer (not Resolve) when a
// decision fail-closes — Resolve expresses the same outcome as Selected==""
// so the CLI can print the table without treating it as an error.
var ErrNoCandidate = fmt.Errorf("route broker: no candidate satisfies the contract requirements (fail closed)")

// Format renders a Decision as the table `gov route --explain` prints.
func (d Decision) Format() string {
	var b strings.Builder
	fmt.Fprintf(&b, "objective=%s risk_class=%s job_type=%s policy_hash=%s selected=%s\n",
		d.Objective, orDash(d.RiskClass), d.JobType, d.PolicyHash, orDash(d.Selected))
	b.WriteString("agent\ttotal\tvalid_rate\tseverity\tcost\tbreaker\tquota\taffinity\tassay_quality\tassay_pass\tvalidator_pass\trepair_success\tpanel_agreement\tcost_per_accepted\texcluded\treason\n")
	for _, c := range d.Candidates {
		selected := ""
		if c.Selected {
			selected = " *"
		}
		fmt.Fprintf(&b, "%s%s\t%.4f\t%.4f\t%.4f\t%.4f\t%.4f\t%.4f\t%.4f\t%.4f\t%.4f\t%.4f\t%.4f\t%.4f\t%.4f\t%t\t%s\n",
			c.Agent, selected, c.Total, c.ValidRateScore, c.FailureSeverityScore,
			c.CostScore, c.BreakerScore, c.QuotaScore, c.RepairAffinityScore,
			c.AssayQualityScore, c.AssayPassRate, c.ValidatorPassRate, c.RepairSuccessRate, c.PanelAgreementRate, c.CostPerAcceptedUSD,
			c.Excluded, orDash(c.ExclusionReason))
	}
	return b.String()
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
