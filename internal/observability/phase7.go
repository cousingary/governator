package observability

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"time"
)

// Phase 7 (analytical projection): SQLite stays authoritative for every
// governance decision; everything in this file is a read-only derivation
// over the existing ledger tables. Nothing here feeds back into routing,
// the breaker, or quota (that boundary is Phase 3C's job, enforced there).
//
// Phase 3A deliberately never built a Supabase outbox — the assay bridge
// stays local/network-free by design (see internal/assay doc comments), so
// there is no outbox to "reuse" yet. ExportJSONL is therefore the whole
// shipping mechanism for now: a local, file-based sink that any external
// system (Langfuse, a spreadsheet, a jq pipeline) can tail or batch-load.
// An OpenTelemetry exporter or Langfuse adapter can read from this same
// snapshot later; building one is deferred until Jeremy actually wants it
// (spend/infra gate, per the hardening plan).

// BackendValidRate is the valid-output rate for one backend across all job
// types it has ever run (agent_profiles rows summed by agent).
type BackendValidRate struct {
	Backend      string  `json:"backend"`
	Runs         int     `json:"runs"`
	ValidOutputs int     `json:"valid_outputs"`
	ValidRate    float64 `json:"valid_rate"`
}

// BackendFailureType is a count of one failure taxonomy for one backend.
type BackendFailureType struct {
	Backend  string `json:"backend"`
	Taxonomy string `json:"taxonomy"`
	Count    int    `json:"count"`
}

// FallbackFrequency counts fallback_attempts rows per backend — how often a
// backend was reached for only after an earlier candidate failed.
type FallbackFrequency struct {
	Backend string `json:"backend"`
	Count   int    `json:"count"`
}

// QuotaUtilization is measured usage as a fraction of the estimated limit for
// one backend/account/window. Utilization is 0 (not 1, not an error) when no
// limit is known yet — an honest "insufficient data" rather than a fabricated
// number.
type QuotaUtilization struct {
	Backend        string  `json:"backend"`
	Account        string  `json:"account"`
	WindowType     string  `json:"window_type"`
	EstimatedLimit float64 `json:"estimated_limit"`
	MeasuredUsage  float64 `json:"measured_usage"`
	Utilization    float64 `json:"utilization"`
	Confidence     float64 `json:"confidence"`
}

// RepairDepthSummary aggregates RepairAttempts (internal/observability
// phase4.go) across every lineage: how many lineages needed repair at all,
// how many repair attempts total, and the shape of that distribution.
type RepairDepthSummary struct {
	Lineages     int     `json:"lineages"`
	TotalRepairs int     `json:"total_repairs"`
	MaxDepth     int     `json:"max_depth"`
	AvgDepth     float64 `json:"avg_depth"`
}

// ValidatorFailureCluster counts non-zero-exit validator commands — which
// checks fail most often, independent of which run they failed on.
type ValidatorFailureCluster struct {
	Command string `json:"command"`
	Count   int    `json:"count"`
}

// AssayFailureCluster counts individual failed checks (not whole
// evaluations) within fail/error assay verdicts, grouped by profile. A
// verdict with an empty failed_checks list (e.g. a bare ERROR before any
// check ran) is bucketed under "(error)" rather than silently dropped.
type AssayFailureCluster struct {
	Profile     string `json:"profile"`
	FailedCheck string `json:"failed_check"`
	Count       int    `json:"count"`
}

// PanelDisagreement reports how often a panel's members landed on different
// run outcomes (status). Requires panel_members rows, which are only
// populated once a caller wires RecordPanelMembers into an actual panel run
// (not yet done as of Phase 7) — an empty table yields Panels=0, not an
// error, which is the honest answer for "no panel evidence collected yet".
type PanelDisagreement struct {
	Panels        int     `json:"panels"`
	Disagreements int     `json:"disagreements"`
	Rate          float64 `json:"rate"`
}

// CostOutcome splits total run cost by terminal outcome: APPROVED (merged)
// vs. rejected (QUARANTINED or ROLLED_BACK).
type CostOutcome struct {
	ApprovedCount   int     `json:"approved_count"`
	ApprovedCostUSD float64 `json:"approved_cost_usd"`
	RejectedCount   int     `json:"rejected_count"`
	RejectedCostUSD float64 `json:"rejected_cost_usd"`
	CostPerApproved float64 `json:"cost_per_approved"`
	CostPerRejected float64 `json:"cost_per_rejected"`
}

// AnalyticsSnapshot is the full Phase 7 projection: every metric the
// hardening plan names, computed fresh from the ledger at GeneratedAt.
type AnalyticsSnapshot struct {
	GeneratedAt      string                    `json:"generated_at"`
	BackendValidRate []BackendValidRate        `json:"backend_valid_rate"`
	FailureByBackend []BackendFailureType      `json:"failure_by_backend"`
	FallbackFreq     []FallbackFrequency       `json:"fallback_frequency"`
	QuotaUtil        []QuotaUtilization        `json:"quota_utilization"`
	RepairDepth      RepairDepthSummary        `json:"repair_depth"`
	ValidatorFails   []ValidatorFailureCluster `json:"validator_failure_clusters"`
	AssayFails       []AssayFailureCluster     `json:"assay_failure_clusters"`
	PanelDisagree    PanelDisagreement         `json:"panel_disagreement"`
	CostByOutcome    CostOutcome               `json:"cost_by_outcome"`
}

// BuildAnalyticsSnapshot computes every Phase 7 metric in one pass. Each
// sub-query opens and closes its own *sql.DB (matching the existing
// ScoreAgents/Failures/CostPerValidOutput idiom) — analytics reads are cold
// path, not run-critical, so the extra Open() calls trade a little latency
// for staying consistent with the rest of the package.
func BuildAnalyticsSnapshot(home string) (AnalyticsSnapshot, error) {
	snap := AnalyticsSnapshot{GeneratedAt: time.Now().UTC().Format(time.RFC3339Nano)}

	var err error
	if snap.BackendValidRate, err = BackendValidOutputRates(home); err != nil {
		return AnalyticsSnapshot{}, fmt.Errorf("backend valid rate: %w", err)
	}
	if snap.FailureByBackend, err = FailureTypesByBackend(home); err != nil {
		return AnalyticsSnapshot{}, fmt.Errorf("failure by backend: %w", err)
	}
	if snap.FallbackFreq, err = FallbackFrequencies(home); err != nil {
		return AnalyticsSnapshot{}, fmt.Errorf("fallback frequency: %w", err)
	}
	if snap.QuotaUtil, err = QuotaUtilizations(home); err != nil {
		return AnalyticsSnapshot{}, fmt.Errorf("quota utilization: %w", err)
	}
	if snap.RepairDepth, err = RepairDepthDistribution(home); err != nil {
		return AnalyticsSnapshot{}, fmt.Errorf("repair depth: %w", err)
	}
	if snap.ValidatorFails, err = ValidatorFailureClusters(home); err != nil {
		return AnalyticsSnapshot{}, fmt.Errorf("validator failure clusters: %w", err)
	}
	if snap.AssayFails, err = AssayFailureClusters(home); err != nil {
		return AnalyticsSnapshot{}, fmt.Errorf("assay failure clusters: %w", err)
	}
	if snap.PanelDisagree, err = PanelDisagreementRate(home); err != nil {
		return AnalyticsSnapshot{}, fmt.Errorf("panel disagreement: %w", err)
	}
	if snap.CostByOutcome, err = CostByOutcome(home); err != nil {
		return AnalyticsSnapshot{}, fmt.Errorf("cost by outcome: %w", err)
	}
	return snap, nil
}

func BackendValidOutputRates(home string) ([]BackendValidRate, error) {
	db, err := Open(home)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.Query(`SELECT agent, SUM(runs), SUM(valid_outputs) FROM agent_profiles WHERE agent<>'' GROUP BY agent HAVING SUM(runs)>0 ORDER BY agent ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BackendValidRate
	for rows.Next() {
		var r BackendValidRate
		if err := rows.Scan(&r.Backend, &r.Runs, &r.ValidOutputs); err != nil {
			return nil, err
		}
		if r.Runs > 0 {
			r.ValidRate = float64(r.ValidOutputs) / float64(r.Runs)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func FailureTypesByBackend(home string) ([]BackendFailureType, error) {
	db, err := Open(home)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.Query(`SELECT COALESCE(agent,''), failure_taxonomy, COUNT(*) FROM runs WHERE failure_taxonomy<>'' GROUP BY agent, failure_taxonomy ORDER BY agent ASC, COUNT(*) DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BackendFailureType
	for rows.Next() {
		var r BackendFailureType
		if err := rows.Scan(&r.Backend, &r.Taxonomy, &r.Count); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func FallbackFrequencies(home string) ([]FallbackFrequency, error) {
	db, err := Open(home)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.Query(`SELECT backend, COUNT(*) FROM fallback_attempts WHERE backend<>'' GROUP BY backend ORDER BY COUNT(*) DESC, backend ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FallbackFrequency
	for rows.Next() {
		var r FallbackFrequency
		if err := rows.Scan(&r.Backend, &r.Count); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func QuotaUtilizations(home string) ([]QuotaUtilization, error) {
	db, err := Open(home)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.Query(`SELECT backend, account, window_type, estimated_limit, measured_usage, confidence FROM quota_windows ORDER BY backend ASC, account ASC, window_type ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []QuotaUtilization
	for rows.Next() {
		var r QuotaUtilization
		if err := rows.Scan(&r.Backend, &r.Account, &r.WindowType, &r.EstimatedLimit, &r.MeasuredUsage, &r.Confidence); err != nil {
			return nil, err
		}
		if r.EstimatedLimit > 0 {
			r.Utilization = r.MeasuredUsage / r.EstimatedLimit
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// RepairDepthDistribution aggregates the flat per-lineage repair counts
// RepairAttempts already computes one root at a time (see phase4.go) across
// every lineage that has ever needed a repair.
func RepairDepthDistribution(home string) (RepairDepthSummary, error) {
	db, err := Open(home)
	if err != nil {
		return RepairDepthSummary{}, err
	}
	defer db.Close()
	rows, err := db.Query(`SELECT repair_of, COUNT(*) FROM runs WHERE repair_of<>'' GROUP BY repair_of`)
	if err != nil {
		return RepairDepthSummary{}, err
	}
	defer rows.Close()
	var summary RepairDepthSummary
	for rows.Next() {
		var rootID string
		var count int
		if err := rows.Scan(&rootID, &count); err != nil {
			return RepairDepthSummary{}, err
		}
		summary.Lineages++
		summary.TotalRepairs += count
		if count > summary.MaxDepth {
			summary.MaxDepth = count
		}
	}
	if err := rows.Err(); err != nil {
		return RepairDepthSummary{}, err
	}
	if summary.Lineages > 0 {
		summary.AvgDepth = float64(summary.TotalRepairs) / float64(summary.Lineages)
	}
	return summary, nil
}

func ValidatorFailureClusters(home string) ([]ValidatorFailureCluster, error) {
	db, err := Open(home)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.Query(`SELECT command, COUNT(*) FROM validators WHERE exit_code<>0 GROUP BY command ORDER BY COUNT(*) DESC, command ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ValidatorFailureCluster
	for rows.Next() {
		var r ValidatorFailureCluster
		if err := rows.Scan(&r.Command, &r.Count); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// AssayFailureClusters tallies individual failed checks (not whole verdicts)
// so "no_boilerplate fails 40% of the time on profile X" is visible even
// when most evaluations bundle several checks into one verdict.
func AssayFailureClusters(home string) ([]AssayFailureCluster, error) {
	db, err := Open(home)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.Query(`SELECT profile, failed_checks FROM assay_evaluations WHERE verdict IN ('fail','error')`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	counts := map[[2]string]int{}
	for rows.Next() {
		var profile, failedJSON string
		if err := rows.Scan(&profile, &failedJSON); err != nil {
			return nil, err
		}
		var checks []string
		if failedJSON != "" {
			if err := json.Unmarshal([]byte(failedJSON), &checks); err != nil {
				return nil, err
			}
		}
		if len(checks) == 0 {
			counts[[2]string{profile, "(error)"}]++
			continue
		}
		for _, check := range checks {
			counts[[2]string{profile, check}]++
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]AssayFailureCluster, 0, len(counts))
	for key, count := range counts {
		out = append(out, AssayFailureCluster{Profile: key[0], FailedCheck: key[1], Count: count})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		if out[i].Profile != out[j].Profile {
			return out[i].Profile < out[j].Profile
		}
		return out[i].FailedCheck < out[j].FailedCheck
	})
	return out, nil
}

// PanelDisagreementRate joins panel_members to the runs each member produced
// (via job_id) and reports how many panels had members that landed on
// different terminal statuses. Panels with fewer than two distinct runs
// recorded can't disagree by definition and are excluded from the
// denominator, same as any other rate metric with no evidence.
func PanelDisagreementRate(home string) (PanelDisagreement, error) {
	db, err := Open(home)
	if err != nil {
		return PanelDisagreement{}, err
	}
	defer db.Close()
	rows, err := db.Query(`
SELECT pm.panel_id, pm.job_id, r.status
FROM panel_members pm
JOIN runs r ON r.job_id = pm.job_id
ORDER BY pm.panel_id ASC, pm.job_id ASC, r.created DESC`)
	if err != nil {
		return PanelDisagreement{}, err
	}
	defer rows.Close()

	seenJob := map[[2]string]bool{}          // (panel_id, job_id) -> keep only the newest run per job
	statuses := map[string]map[string]bool{} // panel_id -> set of distinct statuses
	for rows.Next() {
		var panelID, jobID, status string
		if err := rows.Scan(&panelID, &jobID, &status); err != nil {
			return PanelDisagreement{}, err
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
	if err := rows.Err(); err != nil {
		return PanelDisagreement{}, err
	}

	var report PanelDisagreement
	for _, distinct := range statuses {
		report.Panels++
		if len(distinct) > 1 {
			report.Disagreements++
		}
	}
	if report.Panels > 0 {
		report.Rate = float64(report.Disagreements) / float64(report.Panels)
	}
	return report, nil
}

func CostByOutcome(home string) (CostOutcome, error) {
	db, err := Open(home)
	if err != nil {
		return CostOutcome{}, err
	}
	defer db.Close()
	rows, err := db.Query(`SELECT status, COUNT(*), COALESCE(SUM(cost_usd),0) FROM runs WHERE status IN ('APPROVED','QUARANTINED','ROLLED_BACK') GROUP BY status`)
	if err != nil {
		return CostOutcome{}, err
	}
	defer rows.Close()
	var out CostOutcome
	for rows.Next() {
		var status string
		var count int
		var cost float64
		if err := rows.Scan(&status, &count, &cost); err != nil {
			return CostOutcome{}, err
		}
		switch status {
		case "APPROVED":
			out.ApprovedCount += count
			out.ApprovedCostUSD += cost
		case "QUARANTINED", "ROLLED_BACK":
			out.RejectedCount += count
			out.RejectedCostUSD += cost
		}
	}
	if err := rows.Err(); err != nil {
		return CostOutcome{}, err
	}
	if out.ApprovedCount > 0 {
		out.CostPerApproved = out.ApprovedCostUSD / float64(out.ApprovedCount)
	}
	if out.RejectedCount > 0 {
		out.CostPerRejected = out.RejectedCostUSD / float64(out.RejectedCount)
	}
	return out, nil
}

// ExportJSONL writes the current analytics snapshot as line-delimited JSON,
// one object per metric row, each tagged with which metric it belongs to.
// This is the whole Phase 7 shipping mechanism (see the file-level comment):
// a local, replayable projection any external system can consume. A write
// failure here never touches run state — BuildAnalyticsSnapshot has already
// returned by the time any byte is written, so an export failure can only
// ever affect the export itself, never a run outcome.
func ExportJSONL(home string, w io.Writer) error {
	snap, err := BuildAnalyticsSnapshot(home)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(w)

	row := func(metric string, fields map[string]any) error {
		fields["metric"] = metric
		fields["generated_at"] = snap.GeneratedAt
		return enc.Encode(fields)
	}

	for _, r := range snap.BackendValidRate {
		if err := row("backend_valid_rate", map[string]any{"backend": r.Backend, "runs": r.Runs, "valid_outputs": r.ValidOutputs, "valid_rate": r.ValidRate}); err != nil {
			return err
		}
	}
	for _, r := range snap.FailureByBackend {
		if err := row("failure_by_backend", map[string]any{"backend": r.Backend, "taxonomy": r.Taxonomy, "count": r.Count}); err != nil {
			return err
		}
	}
	for _, r := range snap.FallbackFreq {
		if err := row("fallback_frequency", map[string]any{"backend": r.Backend, "count": r.Count}); err != nil {
			return err
		}
	}
	for _, r := range snap.QuotaUtil {
		if err := row("quota_utilization", map[string]any{"backend": r.Backend, "account": r.Account, "window_type": r.WindowType, "estimated_limit": r.EstimatedLimit, "measured_usage": r.MeasuredUsage, "utilization": r.Utilization, "confidence": r.Confidence}); err != nil {
			return err
		}
	}
	if err := row("repair_depth", map[string]any{"lineages": snap.RepairDepth.Lineages, "total_repairs": snap.RepairDepth.TotalRepairs, "max_depth": snap.RepairDepth.MaxDepth, "avg_depth": snap.RepairDepth.AvgDepth}); err != nil {
		return err
	}
	for _, r := range snap.ValidatorFails {
		if err := row("validator_failure_cluster", map[string]any{"command": r.Command, "count": r.Count}); err != nil {
			return err
		}
	}
	for _, r := range snap.AssayFails {
		if err := row("assay_failure_cluster", map[string]any{"profile": r.Profile, "failed_check": r.FailedCheck, "count": r.Count}); err != nil {
			return err
		}
	}
	if err := row("panel_disagreement", map[string]any{"panels": snap.PanelDisagree.Panels, "disagreements": snap.PanelDisagree.Disagreements, "rate": snap.PanelDisagree.Rate}); err != nil {
		return err
	}
	if err := row("cost_by_outcome", map[string]any{
		"approved_count": snap.CostByOutcome.ApprovedCount, "approved_cost_usd": snap.CostByOutcome.ApprovedCostUSD,
		"rejected_count": snap.CostByOutcome.RejectedCount, "rejected_cost_usd": snap.CostByOutcome.RejectedCostUSD,
		"cost_per_approved": snap.CostByOutcome.CostPerApproved, "cost_per_rejected": snap.CostByOutcome.CostPerRejected,
	}); err != nil {
		return err
	}
	return nil
}
