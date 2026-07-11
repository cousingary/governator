package router

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/cousingary/governator/internal/agents"
	"github.com/cousingary/governator/internal/contracts"
	"github.com/cousingary/governator/internal/observability"
)

// allPresent is the offline binary probe: every backend is installed. Real
// runs use the default LookPath probe; tests inject this so they never depend
// on which CLIs the test host happens to have.
func allPresent(string) bool { return true }

func newLedger(t *testing.T) *sql.DB {
	t.Helper()
	db, err := observability.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func seedProfile(t *testing.T, db *sql.DB, agent, jobType string, runs, valid, failures int) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO agent_profiles(agent,job_type,runs,valid_outputs,failures,total_cost_usd) VALUES(?,?,?,?,?,0)`,
		agent, jobType, runs, valid, failures); err != nil {
		t.Fatal(err)
	}
}

func seedRun(t *testing.T, db *sql.DB, id, agent, jobType, taxonomy string) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO runs(id,job_id,job_type,agent,status,failure_taxonomy) VALUES(?,?,?,?,?,?)`,
		id, id, jobType, agent, "QUARANTINED", taxonomy); err != nil {
		t.Fatal(err)
	}
}

func mustResolve(t *testing.T, r Router, db *sql.DB, req Request) Decision {
	t.Helper()
	d, err := r.Resolve(db, req)
	if err != nil {
		t.Fatalf("Resolve error: %v", err)
	}
	return d
}

// stubHealth injects breaker/quota state for specific backends, defaulting the
// rest to healthy (CLOSED / no telemetry).
type stubHealth struct {
	breakers map[string]BreakerSnapshot
	quotas   map[string]QuotaSnapshot
}

func (s stubHealth) Breaker(a string) BreakerSnapshot {
	if b, ok := s.breakers[a]; ok {
		return b
	}
	return BreakerSnapshot{State: BreakerClosed}
}
func (s stubHealth) Quota(a string) QuotaSnapshot {
	if q, ok := s.quotas[a]; ok {
		return q
	}
	return QuotaSnapshot{Available: false}
}

func baseReq(jobType string) Request {
	return Request{JobID: "j", JobType: jobType, Objective: "balanced", MaxTokens: 0}
}

func TestRegisteredAgentsMatchesAgentsNew(t *testing.T) {
	// The candidate pool must stay in sync with agents.New; a backend added to
	// one without the other would silently drop from (or never enter) routing.
	for _, name := range RegisteredAgents() {
		if _, err := agents.New(name); err != nil {
			t.Errorf("RegisteredAgents lists %q but agents.New rejects it", name)
		}
	}
}

func TestResolveNoEvidenceTieBreaksByName(t *testing.T) {
	// No evidence and equal cost (MaxTokens=0 → flat estimate) leaves every
	// candidate tied; the deterministic tie-break is ascending name.
	db := newLedger(t)
	r := Router{Binary: allPresent}
	d := mustResolve(t, r, db, baseReq("code_change"))
	if d.Selected != "claude-code" {
		t.Fatalf("tie should break to claude-code, got %q\n%s", d.Selected, d.Format())
	}
	if len(d.Candidates) != len(RegisteredAgents()) {
		t.Fatalf("expected %d candidates, got %d", len(RegisteredAgents()), len(d.Candidates))
	}
}

func TestFailClosedWhenAllExcluded(t *testing.T) {
	// A binary probe reporting nobody present excludes everyone; the decision
	// fail-closes with Selected=="" rather than running anything.
	db := newLedger(t)
	r := Router{Binary: func(string) bool { return false }}
	d := mustResolve(t, r, db, baseReq("code_change"))
	if d.Selected != "" {
		t.Fatalf("expected fail-closed (empty selected), got %q", d.Selected)
	}
	for _, c := range d.Candidates {
		if !c.Excluded || c.ExclusionReason != "binary_missing" {
			t.Fatalf("expected binary_missing exclusion, got %+v", c)
		}
	}
}

func TestCapabilityRequirementExcludesUncapable(t *testing.T) {
	db := newLedger(t)
	r := Router{Binary: allPresent}
	req := baseReq("code_change")
	req.Requirements = contracts.RoutingRequirements{NativeSandbox: true}
	req.Candidates = []string{"glm"} // glm has no native sandbox
	d := mustResolve(t, r, db, req)
	if d.Selected != "" {
		t.Fatalf("glm lacks native_sandbox; expected fail-closed, got %q", d.Selected)
	}
	for _, c := range d.Candidates {
		if c.ExclusionReason != "native_sandbox required" {
			t.Fatalf("expected native_sandbox exclusion, got %+v", c)
		}
	}
}

func TestCapabilityRequirementAdmitsCapable(t *testing.T) {
	db := newLedger(t)
	r := Router{Binary: allPresent}
	req := baseReq("code_change")
	req.Requirements = contracts.RoutingRequirements{NativeSandbox: true}
	req.Candidates = []string{"claude-code", "codex"} // both have native sandbox
	d := mustResolve(t, r, db, req)
	if d.Selected == "" {
		t.Fatalf("expected a capable selection, fail-closed\n%s", d.Format())
	}
	if d.Selected != "claude-code" && d.Selected != "codex" {
		t.Fatalf("unexpected selection %q", d.Selected)
	}
}

func TestNetworkControlRequirementSelectsCodexOnly(t *testing.T) {
	db := newLedger(t)
	r := Router{Binary: allPresent}
	req := baseReq("code_change")
	req.Requirements = contracts.RoutingRequirements{NetworkControl: true}
	req.Candidates = []string{"glm", "opencode", "pi", "codex"}
	d := mustResolve(t, r, db, req)
	if d.Selected != "codex" {
		t.Fatalf("only codex has network_control, got %q\n%s", d.Selected, d.Format())
	}
}

// --- Phase 1: expanded RoutingRequirements (all fail closed) ---

func TestReadOnlyModeRequirementExcludesUncapable(t *testing.T) {
	db := newLedger(t)
	r := Router{Binary: allPresent}
	req := baseReq("code_change")
	req.Requirements = contracts.RoutingRequirements{ReadOnlyMode: true}
	req.Candidates = []string{"glm", "opencode"} // neither declares native_read_only
	d := mustResolve(t, r, db, req)
	if d.Selected != "" {
		t.Fatalf("expected fail-closed (no candidate has native_read_only), got %q", d.Selected)
	}
	for _, c := range d.Candidates {
		if c.ExclusionReason != "read_only_mode required" {
			t.Fatalf("expected read_only_mode exclusion, got %+v", c)
		}
	}
}

func TestReadOnlyModeRequirementAdmitsCapable(t *testing.T) {
	db := newLedger(t)
	r := Router{Binary: allPresent}
	req := baseReq("code_change")
	req.Requirements = contracts.RoutingRequirements{ReadOnlyMode: true}
	req.Candidates = []string{"pi"} // declares native_read_only
	d := mustResolve(t, r, db, req)
	if d.Selected != "pi" {
		t.Fatalf("pi has native_read_only; expected selection, got %q\n%s", d.Selected, d.Format())
	}
}

func TestVisionRequirementExcludesUnconfigured(t *testing.T) {
	// No ModelCapability override: every candidate's model fields default to
	// the fail-closed zero value, since none is declared in config.yaml.
	db := newLedger(t)
	r := Router{Binary: allPresent}
	req := baseReq("code_change")
	req.Requirements = contracts.RoutingRequirements{Vision: true}
	req.Candidates = []string{"claude-code"}
	d := mustResolve(t, r, db, req)
	if d.Selected != "" {
		t.Fatalf("no backend declares vision by default; expected fail-closed, got %q", d.Selected)
	}
	if reason := d.Candidates[0].ExclusionReason; reason != "vision required" {
		t.Fatalf("expected vision exclusion, got %q", reason)
	}
}

func TestVisionRequirementAdmitsConfigured(t *testing.T) {
	db := newLedger(t)
	r := Router{
		Binary: allPresent,
		ModelCapability: func(name string, base agents.Capability) agents.Capability {
			if name == "claude-code" {
				base.Vision = true
			}
			return base
		},
	}
	req := baseReq("code_change")
	req.Requirements = contracts.RoutingRequirements{Vision: true}
	req.Candidates = []string{"claude-code", "codex"}
	d := mustResolve(t, r, db, req)
	if d.Selected != "claude-code" {
		t.Fatalf("only claude-code is configured with vision, got %q\n%s", d.Selected, d.Format())
	}
}

func TestToolCallingRequirementExcludesUnconfigured(t *testing.T) {
	db := newLedger(t)
	r := Router{Binary: allPresent}
	req := baseReq("code_change")
	req.Requirements = contracts.RoutingRequirements{ToolCalling: true}
	req.Candidates = []string{"glm"}
	d := mustResolve(t, r, db, req)
	if reason := d.Candidates[0].ExclusionReason; reason != "tool_calling required" {
		t.Fatalf("expected tool_calling exclusion, got %q", reason)
	}
}

func TestLocalOnlyRequirementExcludesUnconfigured(t *testing.T) {
	db := newLedger(t)
	r := Router{Binary: allPresent}
	req := baseReq("code_change")
	req.Requirements = contracts.RoutingRequirements{LocalOnly: true}
	req.Candidates = []string{"pi"}
	d := mustResolve(t, r, db, req)
	if reason := d.Candidates[0].ExclusionReason; reason != "local_only required" {
		t.Fatalf("expected local_only exclusion, got %q", reason)
	}
}

func TestMinContextTokensRequirementExcludesInsufficient(t *testing.T) {
	db := newLedger(t)
	r := Router{
		Binary: allPresent,
		ModelCapability: func(name string, base agents.Capability) agents.Capability {
			base.ContextTokens = 1000
			return base
		},
	}
	req := baseReq("code_change")
	req.Requirements = contracts.RoutingRequirements{MinContextTokens: 5000}
	req.Candidates = []string{"claude-code"}
	d := mustResolve(t, r, db, req)
	if d.Selected != "" {
		t.Fatalf("1000 < 5000 required context tokens; expected fail-closed, got %q", d.Selected)
	}
	if reason := d.Candidates[0].ExclusionReason; reason != "min_context_tokens required (need >= 5000, have 1000)" {
		t.Fatalf("unexpected exclusion reason %q", reason)
	}
}

func TestMinContextTokensRequirementAdmitsSufficient(t *testing.T) {
	db := newLedger(t)
	r := Router{
		Binary: allPresent,
		ModelCapability: func(name string, base agents.Capability) agents.Capability {
			base.ContextTokens = 200000
			return base
		},
	}
	req := baseReq("code_change")
	req.Requirements = contracts.RoutingRequirements{MinContextTokens: 5000}
	req.Candidates = []string{"claude-code"}
	d := mustResolve(t, r, db, req)
	if d.Selected != "claude-code" {
		t.Fatalf("200000 >= 5000; expected selection, got %q\n%s", d.Selected, d.Format())
	}
}

func TestMinOutputTokensRequirementExcludesInsufficient(t *testing.T) {
	db := newLedger(t)
	r := Router{
		Binary: allPresent,
		ModelCapability: func(name string, base agents.Capability) agents.Capability {
			base.OutputTokens = 100
			return base
		},
	}
	req := baseReq("code_change")
	req.Requirements = contracts.RoutingRequirements{MinOutputTokens: 8192}
	req.Candidates = []string{"codex"}
	d := mustResolve(t, r, db, req)
	if d.Selected != "" {
		t.Fatalf("100 < 8192 required output tokens; expected fail-closed, got %q", d.Selected)
	}
	if reason := d.Candidates[0].ExclusionReason; reason != "min_output_tokens required (need >= 8192, have 100)" {
		t.Fatalf("unexpected exclusion reason %q", reason)
	}
}

func TestMinOutputTokensRequirementAdmitsSufficient(t *testing.T) {
	db := newLedger(t)
	r := Router{
		Binary: allPresent,
		ModelCapability: func(name string, base agents.Capability) agents.Capability {
			base.OutputTokens = 16384
			return base
		},
	}
	req := baseReq("code_change")
	req.Requirements = contracts.RoutingRequirements{MinOutputTokens: 8192}
	req.Candidates = []string{"codex"}
	d := mustResolve(t, r, db, req)
	if d.Selected != "codex" {
		t.Fatalf("16384 >= 8192; expected selection, got %q\n%s", d.Selected, d.Format())
	}
}

// defaultModelCapability's own default path (no ModelCapability override)
// reads real config.yaml through config.Current() — exercised once here via
// GOV_CONFIG pointed at a temp file, so the rest of the suite can safely
// stay isolated from the host's actual config.yaml via explicit injection.
func TestDefaultModelCapabilityReadsConfigFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("backends:\n  claude-code:\n    vision: true\n    context_tokens: 200000\n"), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_CONFIG", cfgPath)
	db := newLedger(t)
	r := Router{Binary: allPresent} // no ModelCapability override
	req := baseReq("code_change")
	req.Requirements = contracts.RoutingRequirements{Vision: true, MinContextTokens: 100000}
	req.Candidates = []string{"claude-code", "codex"}
	d := mustResolve(t, r, db, req)
	if d.Selected != "claude-code" {
		t.Fatalf("config.yaml declares claude-code vision+context_tokens; expected selection, got %q\n%s", d.Selected, d.Format())
	}
}

func TestBreakerOpenExcludes(t *testing.T) {
	db := newLedger(t)
	r := Router{
		Binary: allPresent,
		Health: stubHealth{breakers: map[string]BreakerSnapshot{
			"claude-code": {State: BreakerOpen, Reason: "rate_limit"},
		}},
	}
	req := baseReq("code_change")
	req.Candidates = []string{"claude-code"}
	d := mustResolve(t, r, db, req)
	if d.Selected != "" {
		t.Fatalf("OPEN breaker must exclude, got %q", d.Selected)
	}
	if reason := d.Candidates[0].ExclusionReason; reason != "breaker_open: rate_limit" {
		t.Fatalf("expected breaker_open reason, got %q", reason)
	}
}

func TestBreakerDegradedPenalizes(t *testing.T) {
	// Two otherwise-equal candidates: the DEGRADED one must lose to the CLOSED
	// one (breaker score 0.5 vs 1.0). claude-code and codex both have native
	// sandbox; pin the pool to them so capability/binary don't differentiate.
	db := newLedger(t)
	r := Router{
		Binary: allPresent,
		Health: stubHealth{breakers: map[string]BreakerSnapshot{
			"codex": {State: BreakerDegraded, Reason: "transient_upstream"},
		}},
	}
	req := baseReq("code_change")
	req.Candidates = []string{"claude-code", "codex"}
	d := mustResolve(t, r, db, req)
	if d.Selected != "claude-code" {
		t.Fatalf("DEGRADED codex should lose to CLOSED claude-code, got %q\n%s", d.Selected, d.Format())
	}
}

func TestCheapestObjectiveSelectsLowestCost(t *testing.T) {
	// With a real token ceiling, cost differs (glm is cheapest in the table).
	// The cheapest objective weights cost most heavily, so glm wins despite
	// every candidate being otherwise tied on (neutral) quality.
	db := newLedger(t)
	r := Router{Binary: allPresent}
	req := baseReq("code_change")
	req.Objective = "cheapest"
	req.MaxTokens = 1_000_000
	d := mustResolve(t, r, db, req)
	if d.Selected != "glm" {
		t.Fatalf("cheapest objective should select glm, got %q\n%s", d.Selected, d.Format())
	}
}

func TestQualityEvidencePrefersHigherValidRate(t *testing.T) {
	// Seed opposing evidence: claude-code is reliable, glm is not. Under
	// most_reliable (cost weight ~0) the higher valid-output rate must win.
	db := newLedger(t)
	seedProfile(t, db, "claude-code", "code_change", 10, 9, 1)
	seedProfile(t, db, "glm", "code_change", 10, 2, 8)
	r := Router{Binary: allPresent}
	req := baseReq("code_change")
	req.Objective = "most_reliable"
	req.Candidates = []string{"claude-code", "glm"}
	d := mustResolve(t, r, db, req)
	if d.Selected != "claude-code" {
		t.Fatalf("higher valid rate should win under most_reliable, got %q\n%s", d.Selected, d.Format())
	}
}

func TestRepairAffinityPrefersLineageAgent(t *testing.T) {
	// A repair job whose root lineage ran on codex should prefer codex. With
	// equal cost (MaxTokens=0) and no evidence, only affinity differentiates.
	db := newLedger(t)
	seedRun(t, db, "root-1", "codex", "code_change", "VALIDATION_FAILED")
	r := Router{Binary: allPresent}
	req := baseReq("code_change")
	req.RepairLineage = "root-1"
	d := mustResolve(t, r, db, req)
	if d.Selected != "codex" {
		t.Fatalf("repair job should prefer lineage agent codex, got %q\n%s", d.Selected, d.Format())
	}
}

func TestRepairAffinityNeutralForNonRepair(t *testing.T) {
	// A non-repair job has no lineage; affinity is neutral (1.0) for all, so
	// the name tie-break picks claude-code, not whatever ran last.
	db := newLedger(t)
	seedRun(t, db, "root-1", "glm", "code_change", "")
	r := Router{Binary: allPresent}
	d := mustResolve(t, r, db, baseReq("code_change"))
	if d.Selected != "claude-code" {
		t.Fatalf("non-repair job should tie-break to claude-code, got %q", d.Selected)
	}
}

func TestExplicitCandidateAllowlistRespected(t *testing.T) {
	db := newLedger(t)
	r := Router{Binary: allPresent}
	req := baseReq("code_change")
	req.Candidates = []string{"glm", "pi"}
	d := mustResolve(t, r, db, req)
	seen := map[string]bool{}
	for _, c := range d.Candidates {
		seen[c.Agent] = true
	}
	if len(seen) != 2 || !seen["glm"] || !seen["pi"] {
		t.Fatalf("allowlist {glm,pi} not respected: %+v", seen)
	}
}

func TestDecisionIsDeterministicAcrossRuns(t *testing.T) {
	// Same inputs → same selection, every time (rule 5).
	db := newLedger(t)
	seedProfile(t, db, "claude-code", "code_change", 10, 8, 2)
	seedProfile(t, db, "glm", "code_change", 10, 5, 5)
	r := Router{Binary: allPresent}
	req := baseReq("code_change")
	req.Candidates = []string{"claude-code", "glm"}
	first := mustResolve(t, r, db, req).Selected
	for i := 0; i < 5; i++ {
		if got := mustResolve(t, r, db, req).Selected; got != first {
			t.Fatalf("non-deterministic: first=%q then=%q", first, got)
		}
	}
}

func TestDecisionRecordsOneRowPerCandidate(t *testing.T) {
	db := newLedger(t)
	r := Router{Binary: allPresent}
	d := mustResolve(t, r, db, baseReq("code_change"))
	if err := observability.RecordRouteDecision(db, observability.RouteDecisionRecord{
		JobID: "j", JobType: "code_change", Objective: d.Objective, Created: "2026-07-10T00:00:00Z",
		Rows: toRows(d),
	}); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM route_decisions WHERE job_id='j'").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != len(RegisteredAgents()) {
		t.Fatalf("expected one row per candidate (%d), got %d", len(RegisteredAgents()), n)
	}
	var selected int
	if err := db.QueryRow("SELECT COUNT(*) FROM route_decisions WHERE job_id='j' AND selected=1").Scan(&selected); err != nil {
		t.Fatal(err)
	}
	if selected != 1 {
		t.Fatalf("expected exactly one selected row, got %d", selected)
	}
}

func TestFailureSeverityDifferentiates(t *testing.T) {
	// Two backends with identical valid rates but different failure severity:
	// the one whose single failure is mild (VALIDATION_FAILED) must outrank the
	// one whose single failure is severe (SCOPE_DRIFT). Equal cost keeps only
	// severity in play.
	db := newLedger(t)
	seedProfile(t, db, "claude-code", "code_change", 2, 1, 1)
	seedProfile(t, db, "glm", "code_change", 2, 1, 1)
	seedRun(t, db, "c-fail", "claude-code", "code_change", "VALIDATION_FAILED") // mild (0.4)
	seedRun(t, db, "g-fail", "glm", "code_change", "SCOPE_DRIFT")               // severe (1.0)
	r := Router{Binary: allPresent}
	req := baseReq("code_change")
	req.Objective = "most_reliable" // severity weight 0.30, cost ~0
	req.Candidates = []string{"claude-code", "glm"}
	d := mustResolve(t, r, db, req)
	if d.Selected != "claude-code" {
		t.Fatalf("mild-failure backend should outrank severe-failure one, got %q\n%s", d.Selected, d.Format())
	}
}

func TestQuotaHeadroomPenalizesWhenAvailable(t *testing.T) {
	// When quota telemetry IS available, low headroom penalizes a backend.
	// Two otherwise-equal backends: the one with full headroom wins.
	db := newLedger(t)
	r := Router{
		Binary: allPresent,
		Health: stubHealth{quotas: map[string]QuotaSnapshot{
			"codex": {Available: true, HeadroomPct: 0.0}, // exhausted
		}},
	}
	req := baseReq("code_change")
	req.Candidates = []string{"claude-code", "codex"}
	d := mustResolve(t, r, db, req)
	if d.Selected != "claude-code" {
		t.Fatalf("low-headroom codex should lose, got %q\n%s", d.Selected, d.Format())
	}
}

// toRows maps a router Decision to the observability persistence rows. This is
// the same mapping internal/runtime performs when recording a real decision.
func toRows(d Decision) []observability.RouteDecisionRow {
	rows := make([]observability.RouteDecisionRow, 0, len(d.Candidates))
	for _, c := range d.Candidates {
		rows = append(rows, observability.RouteDecisionRow{
			Candidate:            c.Agent,
			ValidRateScore:       c.ValidRateScore,
			FailureSeverityScore: c.FailureSeverityScore,
			CostScore:            c.CostScore,
			BreakerScore:         c.BreakerScore,
			QuotaScore:           c.QuotaScore,
			RepairAffinityScore:  c.RepairAffinityScore,
			Total:                c.Total,
			Excluded:             c.Excluded,
			ExclusionReason:      c.ExclusionReason,
			Selected:             c.Selected,
		})
	}
	return rows
}

// A taxonomy missing from the severity table must count as a medium failure,
// never weigh zero (a zero weight would flatter the failing backend).
func TestSeverityWeightDefaultsUnknownToMedium(t *testing.T) {
	if w := severityWeight("FUTURE_KIND"); w != 0.7 {
		t.Fatalf("unknown taxonomy weight = %v, want 0.7", w)
	}
	if w := severityWeight("SCOPE_DRIFT"); w != 1.0 {
		t.Fatalf("SCOPE_DRIFT weight = %v, want 1.0", w)
	}
}

// --- Phase 1: RiskClass scoring ---

func weightSum(w weightSet) float64 {
	return w.validRate + w.severity + w.cost + w.breaker + w.quota + w.affinity
}

func TestRiskAdjustedWeightsHighMovesCostToReliability(t *testing.T) {
	base := objectiveWeights("cheapest")
	adjusted := riskAdjustedWeights(base, "high")
	if adjusted.cost >= base.cost {
		t.Fatalf("high risk must reduce cost weight, base=%.4f adjusted=%.4f", base.cost, adjusted.cost)
	}
	if adjusted.validRate <= base.validRate || adjusted.severity <= base.severity || adjusted.breaker <= base.breaker {
		t.Fatalf("high risk must raise validRate/severity/breaker weights, base=%+v adjusted=%+v", base, adjusted)
	}
	if adjusted.quota != base.quota || adjusted.affinity != base.affinity {
		t.Fatalf("high risk must not touch quota/affinity (rule 3), base=%+v adjusted=%+v", base, adjusted)
	}
	if sum := weightSum(adjusted); sum < 0.9999 || sum > 1.0001 {
		t.Fatalf("weights must still sum to 1.0, got %.10f", sum)
	}
}

func TestRiskAdjustedWeightsLowAndUnsetAreNoOp(t *testing.T) {
	base := objectiveWeights("balanced")
	for _, risk := range []string{"", "low"} {
		if got := riskAdjustedWeights(base, risk); got != base {
			t.Fatalf("risk=%q must be a no-op, base=%+v got=%+v", risk, base, got)
		}
	}
}

func TestRiskAdjustedWeightsShiftClampsToAvailableCostWeight(t *testing.T) {
	// most_reliable already keeps cost weight low (0.05); the nominal 0.15
	// high-risk shift must clamp to what's actually there rather than driving
	// cost negative.
	base := objectiveWeights("most_reliable")
	adjusted := riskAdjustedWeights(base, "high")
	if adjusted.cost < 0 {
		t.Fatalf("cost weight must never go negative, got %.4f", adjusted.cost)
	}
	if sum := weightSum(adjusted); sum < 0.9999 || sum > 1.0001 {
		t.Fatalf("weights must sum to 1.0 even when clamped, got %.10f", sum)
	}
}

func TestResolveAppliesRiskClassToScoring(t *testing.T) {
	// claude-code is reliable but priciest; glm is cheap but unreliable.
	// Under plain "cheapest" the heavy cost weight lets glm win despite its
	// poor valid-rate. risk_class: high should raise claude-code's score
	// (never glm's exclusion status — only soft scores move).
	db := newLedger(t)
	seedProfile(t, db, "claude-code", "code_change", 10, 10, 0)
	seedProfile(t, db, "glm", "code_change", 10, 2, 8)
	r := Router{Binary: allPresent}
	req := baseReq("code_change")
	req.Objective = "cheapest"
	req.MaxTokens = 1_000_000
	req.Candidates = []string{"claude-code", "glm"}

	plain := mustResolve(t, r, db, req)
	req.RiskClass = "high"
	risky := mustResolve(t, r, db, req)

	if risky.RiskClass != "high" {
		t.Fatalf("expected RiskClass recorded on the decision, got %q", risky.RiskClass)
	}
	if risky.PolicyHash == plain.PolicyHash {
		t.Fatalf("risk_class must change the effective policy hash")
	}
	claudeTotal := func(d Decision) float64 {
		for _, c := range d.Candidates {
			if c.Agent == "claude-code" {
				return c.Total
			}
		}
		t.Fatal("claude-code candidate missing from decision")
		return 0
	}
	if claudeTotal(risky) <= claudeTotal(plain) {
		t.Fatalf("high risk_class must raise the reliable candidate's score, plain=%.4f risky=%.4f", claudeTotal(plain), claudeTotal(risky))
	}
}

// --- Phase 1: policy hash ---

func TestPolicyHashDeterministicAndSensitiveToRequirements(t *testing.T) {
	db := newLedger(t)
	r := Router{Binary: allPresent}
	req := baseReq("code_change")
	d1 := mustResolve(t, r, db, req)
	d2 := mustResolve(t, r, db, req)
	if d1.PolicyHash == "" {
		t.Fatal("expected a non-empty policy hash")
	}
	if d1.PolicyHash != d2.PolicyHash {
		t.Fatalf("identical policy must hash identically, got %q vs %q", d1.PolicyHash, d2.PolicyHash)
	}
	req.Requirements = contracts.RoutingRequirements{NativeSandbox: true}
	d3 := mustResolve(t, r, db, req)
	if d3.PolicyHash == d1.PolicyHash {
		t.Fatal("a different requirement set must change the policy hash")
	}
}
