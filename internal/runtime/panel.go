package runtime

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/cousingary/governator/internal/breaker"
	"github.com/cousingary/governator/internal/contracts"
	"github.com/cousingary/governator/internal/observability"
	"github.com/cousingary/governator/internal/router"
)

// PanelMemberOutcome is one member job's contribution to a panel run: which
// backend it ran on and how it finished. RunPanel fills Status once the
// member's run completes, or leaves it "TIMEOUT" for a straggler still in
// flight when the member level's quorum/hard-timeout condition was met.
type PanelMemberOutcome struct {
	JobID   string
	Agent   string
	Status  string // APPROVED, QUARANTINED, ERROR, or TIMEOUT (straggler; panel stopped waiting)
	RunID   string
	CostUSD float64
}

// PanelReport records the diversity and quorum decisions a panel run made —
// the Phase 2 "never silently" bar: `gov panel run`'s printed output always
// shows why a panel degraded rather than an operator only noticing fewer
// distinct backends, or a shorter member list, than expected.
type PanelReport struct {
	// Diversity is one router.Decision per auto member that was routed
	// (explicit-agent members never reach the broker, so they leave no
	// decision here even though they still count toward DiversityUnique).
	Diversity       []router.Decision
	DiversityKey    string
	DiversityUnique int
	DiversityWanted int

	Degraded        bool
	DegradedReasons []string

	Members          []PanelMemberOutcome
	SucceededMembers []string
}

func (r *PanelReport) degrade(reason string) {
	r.Degraded = true
	r.DegradedReasons = append(r.DegradedReasons, reason)
}

// diversityGroup maps a backend name to the grouping key panel diversity
// compares against. "backend" (the default) is the identity grouping: every
// backend is its own group. "model_family" is a coarser, hardcoded grouping
// by underlying vendor — Governator has no per-backend model declaration
// today (config.Backend only carries the capability booleans consumed by
// RoutingRequirements; see internal/agents.Capability's doc comment), so
// this is a judgment call rather than a config read. It only ever shapes the
// diversity *exclusion set* built by excludedFor, never a hard capability
// filter, so an imprecise grouping degrades panel diversity reporting, not
// routing correctness.
func diversityGroup(key, agent string) string {
	if key != "model_family" {
		return agent
	}
	switch agent {
	case "claude-code":
		return "anthropic"
	case "codex":
		return "openai"
	case "glm":
		return "zhipu"
	default:
		return agent
	}
}

// resolvePanelBackends assigns a concrete backend to every agent: auto
// member job, in spec.Members order, growing a router.Request.ExcludeAgents
// set as it goes so the router hard-excludes any group (per
// spec.EffectiveDiversity().GroupBy) already claimed by an earlier member — the
// "member 2 excludes member 1's backend" rule. It mutates a copy of jobs
// (Agent: auto becomes a concrete name) so runtime.Run's own agent==auto
// branch is a no-op for these jobs when they later launch: diversity is
// decided once, here, not re-litigated per job.
//
// A member whose contract already names an explicit agent (operator
// override) is never re-routed, but its backend still counts toward the
// diversity groups later auto members are excluded from.
//
// Fail-closed stays the router's job: if a member has no candidate at all
// even before diversity narrows the pool, resolvePanelBackends returns
// router.ErrNoCandidate immediately — diversity can degrade a panel, it can
// never be the reason a member runs with no backend.
func resolvePanelBackends(db *sql.DB, rtr router.Router, jobs []contracts.Contract, spec contracts.PanelSpec) ([]contracts.Contract, PanelReport, error) {
	out := append([]contracts.Contract(nil), jobs...)
	byID := make(map[string]int, len(out))
	for i, j := range out {
		byID[j.JobID] = i
	}
	div := spec.EffectiveDiversity()
	report := PanelReport{DiversityKey: div.GroupBy, DiversityWanted: div.MinUnique}

	usedGroups := map[string]bool{}
	for _, memberID := range spec.Members {
		idx, ok := byID[memberID]
		if !ok {
			return nil, report, fmt.Errorf("panel: member %q not found in job set", memberID)
		}
		job := out[idx]
		if job.Agent != contracts.AgentAuto {
			usedGroups[diversityGroup(div.GroupBy, job.Agent)] = true
			continue
		}

		req := router.RequestFromContract(job)
		req.ExcludeAgents = excludedFor(req, usedGroups, div.GroupBy)
		decision, err := rtr.Resolve(db, req)
		if err != nil {
			return nil, report, err
		}
		if decision.Selected == "" && len(req.ExcludeAgents) > 0 {
			decision, err = resolveDiversityFallback(db, rtr, job, usedGroups, div, &report, memberID)
			if err != nil {
				return nil, report, err
			}
		}
		if decision.Selected == "" {
			return nil, report, fmt.Errorf("%w (panel member %s):\n%s", router.ErrNoCandidate, memberID, decision.Format())
		}
		out[idx].Agent = decision.Selected
		usedGroups[diversityGroup(div.GroupBy, decision.Selected)] = true
		report.Diversity = append(report.Diversity, decision)
	}

	report.DiversityUnique = len(usedGroups)
	if report.DiversityUnique < div.MinUnique {
		report.degrade(fmt.Sprintf("insufficient_diversity: only %d unique %s group(s) available for %d member(s) (wanted >= %d)",
			report.DiversityUnique, div.GroupBy, len(spec.Members), div.MinUnique))
	}
	return out, report, nil
}

// resolveDiversityFallback runs once a member's primary-key exclusion left
// no candidate. It first tries div.FallbackGroupBy (a coarser regrouping may
// free a candidate the primary key didn't); failing that, it drops
// exclusions entirely and reuses a backend rather than fail the member.
// Either path records why in report — diversity can degrade a panel, it
// must never do so silently.
func resolveDiversityFallback(db *sql.DB, rtr router.Router, job contracts.Contract, usedGroups map[string]bool, div contracts.PanelDiversity, report *PanelReport, memberID string) (router.Decision, error) {
	if div.FallbackGroupBy != "" {
		fallbackReq := router.RequestFromContract(job)
		fallbackReq.ExcludeAgents = excludedFor(fallbackReq, usedGroups, div.FallbackGroupBy)
		if fbDecision, fbErr := rtr.Resolve(db, fallbackReq); fbErr != nil {
			return router.Decision{}, fbErr
		} else if fbDecision.Selected != "" {
			report.degrade(fmt.Sprintf("member %s: no candidate satisfied diversity exclusion (%s); used fallback grouping (%s)", memberID, div.GroupBy, div.FallbackGroupBy))
			return fbDecision, nil
		}
	}
	noExclusion := router.RequestFromContract(job)
	decision, err := rtr.Resolve(db, noExclusion)
	if err != nil {
		return router.Decision{}, err
	}
	if decision.Selected != "" {
		report.degrade(fmt.Sprintf("member %s: no candidate satisfied diversity exclusion (%s); reused a backend", memberID, div.GroupBy))
	}
	return decision, nil
}

// excludedFor returns every candidate in the router's pool whose diversity
// group is already used — the exclusion set for the *next* member's
// decision. It evaluates the same candidate pool router.Router.Resolve
// would (req.Candidates, or every registered backend when the contract
// names no allowlist), so an operator-restricted routing.candidates
// allowlist is respected instead of excluding backends that were never in
// the running for this job anyway.
func excludedFor(req router.Request, usedGroups map[string]bool, key string) []string {
	pool := req.Candidates
	if len(pool) == 0 {
		pool = router.RegisteredAgents()
	}
	var excluded []string
	for _, name := range pool {
		if usedGroups[diversityGroup(key, name)] {
			excluded = append(excluded, name)
		}
	}
	sort.Strings(excluded)
	return excluded
}

// RunPanel executes a panel's member level with backend diversity
// (resolvePanelBackends) and quorum semantics (this function), then runs
// the remaining levels (comparison, judge) against whichever members
// actually produced a usable artifact.
//
// levels must come from contracts.TopologicalLevels over the panel's full
// job set, with ArtifactSources already resolved (contracts.
// ResolveArtifactSources or contracts.ValidatePlan — both callers of
// TopologicalLevels already do this): levels[0] is exactly the member jobs
// (they share no depends_on edges with each other, so Kahn's algorithm
// always groups them into the first level), and spec.ComparisonJob must
// appear somewhere in levels[1:].
//
// Members run one at a time, in spec.Members order — not concurrently.
// Every governed run holds an exclusive per-workspace-root lock for its
// whole lifetime (runtime.lock, keyed on workspace.root; see its doc
// comment), and every panel member targets the same root, so true
// concurrency here would just be a race for that lock. Serial execution is
// therefore not a shortcut; it's what the existing single-run invariant
// requires.
//
// Quorum still does real work under serial execution: RunPanel stops
// launching further members once spec.EffectiveMinSuccess() have completed
// APPROVED (the rest are recorded SKIPPED — "quorum already satisfied,"
// never run, not degraded: this is the intended fast path, not a failure),
// and stops entirely once the cumulative wall-clock across this level
// passes EffectiveHardTimeoutSeconds (the rest are recorded TIMEOUT and the
// panel is marked degraded — this ceiling exists specifically for a slow or
// hung member, which the per-job budget.max_minutes gate cannot bound below
// one full minute). Fewer than 2 successful members is the one case that
// fails the whole panel (CompareArtifacts needs at least 2 inputs):
// comparison and judge are marked SKIPPED and no error is returned — a
// degraded panel result, not a Go error, exactly like RunBatchOrdered's own
// halt-and-skip pattern.
func (r *Runner) RunPanel(ctx context.Context, spec contracts.PanelSpec, levels [][]contracts.Contract, opts BatchOptions) (BatchSummary, PanelReport, error) {
	if len(levels) < 2 {
		return BatchSummary{}, PanelReport{}, fmt.Errorf("panel: expected at least a member level and a comparison level, got %d", len(levels))
	}

	db, err := dbOpen(r.Home)
	if err != nil {
		return BatchSummary{}, PanelReport{}, err
	}
	assigned, report, err := resolvePanelBackends(db, router.Router{Health: breaker.Store{DB: db}}, levels[0], spec)
	db.Close()
	if err != nil {
		return BatchSummary{}, report, err
	}

	minSuccess := spec.EffectiveMinSuccess()
	hardTimeout := time.Duration(spec.EffectiveHardTimeoutSeconds()) * time.Second
	start := time.Now()

	combined := BatchSummary{BatchID: fmt.Sprintf("panel-batch-%d", time.Now().UTC().UnixNano())}
	var succeededIDs []string
	hardTimeoutHit := false
	for _, job := range assigned {
		outcome := PanelMemberOutcome{JobID: job.JobID, Agent: job.Agent}
		switch {
		case time.Since(start) >= hardTimeout:
			hardTimeoutHit = true
			outcome.Status = "TIMEOUT"
			combined.Jobs = append(combined.Jobs, BatchJobResult{JobID: job.JobID, Status: "TIMEOUT", Error: "panel member level hard timeout elapsed before this member's turn"})
		case len(succeededIDs) >= minSuccess:
			outcome.Status = "SKIPPED"
			combined.Jobs = append(combined.Jobs, BatchJobResult{JobID: job.JobID, Status: "SKIPPED", Error: "panel quorum already satisfied"})
		default:
			rec, rerr := r.RunWithAutoRepair(ctx, job)
			var res BatchJobResult
			if rerr != nil {
				res = BatchJobResult{JobID: job.JobID, Status: "ERROR", Error: rerr.Error()}
			} else {
				res = BatchJobResult{JobID: job.JobID, RunID: rec.ID, Status: rec.Status, Taxonomy: rec.FailureTaxonomy, CostUSD: rec.CostUSD, Worktree: rec.Worktree}
			}
			combined.Jobs = append(combined.Jobs, res)
			combined.TotalCostUSD += res.CostUSD
			if res.Status == "QUARANTINED" {
				combined.Quarantined++
			}
			outcome.Status, outcome.RunID, outcome.CostUSD = res.Status, res.RunID, res.CostUSD
			if res.Status == "APPROVED" {
				succeededIDs = append(succeededIDs, job.JobID)
			}
		}
		report.Members = append(report.Members, outcome)
	}
	report.SucceededMembers = succeededIDs
	if hardTimeoutHit {
		report.degrade(fmt.Sprintf("hard_timeout_elapsed: panel member level exceeded %s before every member got a turn", hardTimeout))
	}
	recordPanelMembership(r.Home, spec, assigned)

	if len(succeededIDs) < 2 {
		report.degrade(fmt.Sprintf("panel failed: only %d member(s) produced a usable artifact (comparison needs at least 2)", len(succeededIDs)))
		for _, level := range levels[1:] {
			for _, job := range level {
				combined.Jobs = append(combined.Jobs, BatchJobResult{JobID: job.JobID, Status: "SKIPPED", Error: "panel comparison needs at least 2 member artifacts"})
			}
		}
		return combined, report, nil
	}
	if len(succeededIDs) < minSuccess {
		report.degrade(fmt.Sprintf("quorum_partial: %d/%d member(s) succeeded (min_success=%d)", len(succeededIDs), len(assigned), minSuccess))
	}

	tailLevels, err := adjustComparisonConsumes(levels[1:], spec, succeededIDs)
	if err != nil {
		return combined, report, err
	}
	tailSummary, err := r.RunBatchOrdered(ctx, tailLevels, opts)
	if err != nil {
		return combined, report, err
	}
	combined.Jobs = append(combined.Jobs, tailSummary.Jobs...)
	combined.TotalCostUSD += tailSummary.TotalCostUSD
	combined.Quarantined += tailSummary.Quarantined
	return combined, report, nil
}

// recordPanelMembership persists one panel_members row per member so the
// Phase 7 panel-disagreement metric (observability.PanelDisagreementRate,
// which joins panel_members to each member's runs via job_id) has data —
// before this call was wired in, the table was written by nothing and the
// metric correctly-but-uselessly reported zero panels. Labels are positional
// (member-1, member-2, ...) in spec.Members order, matching the anonymous
// ordering the comparison stage uses. Best-effort: a ledger write failure
// here must not fail a panel whose members already ran (same policy as the
// swallowed validator/assay audit-row writes in runtime.go).
func recordPanelMembership(home string, spec contracts.PanelSpec, assigned []contracts.Contract) {
	byID := make(map[string]contracts.Contract, len(assigned))
	for _, job := range assigned {
		byID[job.JobID] = job
	}
	records := make([]observability.PanelMemberRecord, 0, len(spec.Members))
	for i, memberID := range spec.Members {
		job := byID[memberID]
		artifact := ""
		if len(job.Produces) > 0 {
			artifact = job.Produces[0].Name
		}
		records = append(records, observability.PanelMemberRecord{
			PanelID:      spec.ID,
			MemberLabel:  fmt.Sprintf("member-%d", i+1),
			JobID:        memberID,
			Agent:        job.Agent,
			ArtifactName: artifact,
		})
	}
	db, err := dbOpen(home)
	if err != nil {
		return
	}
	defer db.Close()
	created := time.Now().UTC().Format(time.RFC3339Nano)
	if err := observability.RecordPanelMembers(db, records, created); err != nil {
		payload, _ := json.Marshal(panelMembersPayload{Records: records, Created: created})
		noteOperationalFailure(db, spec.ID, opPanelMembers, err, string(payload))
	}
}

// adjustComparisonConsumes trims the comparison job's Consumes (and the
// matching entries of its already-resolved ArtifactSources) down to the
// member artifacts that actually succeeded before the panel's quorum
// condition fired. Without this, stageConsumedArtifacts
// (internal/runtime/artifacts.go) would refuse to launch the comparison job
// at all: it hard-fails when a declared consumed artifact has no APPROVED
// producing run in the ledger — exactly the artifact a straggler member
// never produced. Every other job (the judge, and any consumed entry whose
// producer isn't a panel member) passes through unchanged.
func adjustComparisonConsumes(tail [][]contracts.Contract, spec contracts.PanelSpec, succeededIDs []string) ([][]contracts.Contract, error) {
	succeeded := make(map[string]bool, len(succeededIDs))
	for _, id := range succeededIDs {
		succeeded[id] = true
	}
	members := make(map[string]bool, len(spec.Members))
	for _, id := range spec.Members {
		members[id] = true
	}

	out := make([][]contracts.Contract, len(tail))
	comparisonFound := false
	for li, level := range tail {
		out[li] = append([]contracts.Contract(nil), level...)
		for ji, job := range out[li] {
			if job.JobID != spec.ComparisonJob {
				continue
			}
			comparisonFound = true
			kept := make([]string, 0, len(job.Consumes))
			keptSources := make(map[string]string, len(job.ArtifactSources))
			for _, name := range job.Consumes {
				producer, resolved := job.ArtifactSources[name]
				if resolved && members[producer] && !succeeded[producer] {
					continue // straggler member: its artifact was never produced
				}
				kept = append(kept, name)
				if resolved {
					keptSources[name] = producer
				}
			}
			out[li][ji].Consumes = kept
			out[li][ji].ArtifactSources = keptSources
		}
	}
	if !comparisonFound {
		return nil, fmt.Errorf("panel: comparison job %q not found among the remaining levels", spec.ComparisonJob)
	}
	return out, nil
}
