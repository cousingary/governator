package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cousingary/governator/internal/attest"
	"github.com/cousingary/governator/internal/breaker"
	"github.com/cousingary/governator/internal/claims"
	"github.com/cousingary/governator/internal/config"
	"github.com/cousingary/governator/internal/containment"
	"github.com/cousingary/governator/internal/contextgraph"
	"github.com/cousingary/governator/internal/contracts"
	"github.com/cousingary/governator/internal/doctor"
	"github.com/cousingary/governator/internal/enforce"
	"github.com/cousingary/governator/internal/observability"
	"github.com/cousingary/governator/internal/panel"
	"github.com/cousingary/governator/internal/policy"
	"github.com/cousingary/governator/internal/protect"
	"github.com/cousingary/governator/internal/protectedpaths"
	"github.com/cousingary/governator/internal/quota"
	"github.com/cousingary/governator/internal/router"
	govruntime "github.com/cousingary/governator/internal/runtime"
	"github.com/cousingary/governator/internal/snapshots"
	"github.com/cousingary/governator/internal/spend"
	"gopkg.in/yaml.v3"
)

var (
	version                = "1.5.0-dev"
	sourceCommit           = "unknown"
	buildTimestamp         = "unknown"
	claimsHash             = "unknown"
	adapterProtocolVersion = "adapter-protocol-v1"
)

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) == 0 {
		usage()
		return 2
	}
	// Session 5 (Sol P0-3): the sandbox-exec wrapper is not a user-facing
	// command -- it is the process that applies Landlock to itself and then
	// execs into the real governed backend (see internal/enforce). It must
	// be intercepted before every other branch below, including the config
	// guard: by design it carries no config dependency, the same posture
	// "hook" already has for the same reason (a high-frequency internal
	// path must stay resilient to an unrelated config problem).
	if args[0] == enforce.SandboxExecArg {
		return enforce.RunSandboxExec(args[1:])
	}
	// Sol Critical 2: a malformed configuration must fail the process at
	// startup, never be silently replaced by defaults inside Current(). init
	// (writes the config), validate (checks it explicitly below), version/help
	// (need no config) and hook (a high-frequency path that must stay
	// resilient — the launching job already validated config) skip the guard.
	switch args[0] {
	case "init", "validate", "version", "--version", "-version", "help", "--help", "-h", "hook":
	default:
		if code := guardConfig(); code != 0 {
			return code
		}
	}
	switch args[0] {
	case "init":
		return initCmd(args[1:])
	case "validate":
		if len(args) != 2 {
			return bad("usage: gov validate <job.yaml>")
		}
		// Sol Critical 2: validate the configuration too. A malformed config
		// must report INVALID with a specific message, never VALID plus silent
		// built-in defaults (the original reproduced failure).
		if _, err := config.LoadStrict(); err != nil {
			fmt.Fprintln(os.Stderr, "CONFIG INVALID:", err)
			return 1
		}
		c, err := contracts.ParseFile(args[1])
		if err != nil {
			return contractError(args[1], err)
		}
		fmt.Printf("VALID %s (job_id=%s mode=%s agent=%s)\n", args[1], c.JobID, c.Mode, c.Agent)
		if issue := policy.CleanupDoctrineIssue(*c); issue != "" {
			if config.Current().Doctrine.RequireCleanup {
				fmt.Fprintln(os.Stderr, "DOCTRINE ERROR:", issue)
				return 1
			}
			fmt.Fprintln(os.Stderr, "DOCTRINE WARNING:", issue)
		}
		return 0
	case "preflight":
		if len(args) != 2 {
			return bad("usage: gov preflight <job.yaml>")
		}
		c, err := contracts.ParseFile(args[1])
		if err != nil {
			return contractError(args[1], err)
		}
		report, err := policy.Preflight(*c)
		if err != nil {
			fmt.Fprintln(os.Stderr, "preflight:", err)
			return 1
		}
		output, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			fmt.Fprintln(os.Stderr, "preflight:", err)
			return 1
		}
		fmt.Println(string(output))
		if err := policy.Enforce(report, *c); err != nil {
			fmt.Fprintln(os.Stderr, "preflight:", err)
			return 1
		}
		return 0
	case "run":
		if len(args) < 2 {
			return bad("usage: gov run <job.yaml> [--agent <name>] | gov run inspect|resume|abandon <run_id> | gov run recover --stale")
		}
		// Phase 4 durable-recovery subcommands (`gov run inspect|resume|
		// abandon|recover`). These are reserved words: job.yaml paths never
		// collide with them since a contract file always ends in .yaml/.yml.
		switch args[1] {
		case "inspect", "resume", "abandon", "recover":
			return runRecoveryDispatch(args[1:])
		}
		if len(args) != 2 && len(args) != 4 {
			return bad("usage: gov run <job.yaml> [--agent <name>]")
		}
		c, err := contracts.ParseFile(args[1])
		if err != nil {
			return contractError(args[1], err)
		}
		if len(args) == 4 {
			if args[2] != "--agent" {
				return bad("usage: gov run <job.yaml> [--agent <name>]")
			}
			c.Agent = args[3]
			// The override lands after ParseFile already validated the
			// authored contract, so re-validate: an explicit --agent on a
			// contract with a routing: block is the same ambiguity the schema
			// rejects, and an unknown --agent name should refuse here rather
			// than mid-run.
			if err := c.Validate(); err != nil {
				return contractError(args[1], err)
			}
		}
		rec, err := govruntime.New().RunWithAutoRepair(context.Background(), *c)
		if err != nil {
			fmt.Fprintln(os.Stderr, "run:", err)
			return 1
		}
		fmt.Println(govruntime.MarshalRecord(rec))
		if rec.Status != "APPROVED" {
			return 1
		}
		return 0
	case "batch":
		return batchCmd(args[1:])
	case "plan":
		return planCmd(args[1:])
	case "panel":
		return panelCmd(args[1:])
	case "handoff":
		if len(args) > 2 {
			return bad("usage: gov handoff [last|run_id]")
		}
		id := "last"
		if len(args) == 2 {
			id = args[1]
		}
		handoff, err := govruntime.HandoffFor(id)
		if err != nil {
			fmt.Fprintln(os.Stderr, "handoff:", err)
			return 1
		}
		output, err := json.MarshalIndent(handoff, "", "  ")
		if err != nil {
			fmt.Fprintln(os.Stderr, "handoff:", err)
			return 1
		}
		fmt.Println(string(output))
		return 0
	case "diff":
		if len(args) > 2 {
			return bad("usage: gov diff [last|run_id]")
		}
		id := "last"
		if len(args) == 2 {
			id = args[1]
		}
		rec, err := govruntime.Last(id)
		if err != nil {
			fmt.Fprintln(os.Stderr, "diff:", err)
			return 1
		}
		fmt.Print(rec.Diff)
		return 0
	case "rollback":
		if len(args) != 2 {
			return bad("usage: gov rollback <run_id>")
		}
		rec, err := govruntime.Rollback(context.Background(), args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, "rollback:", err)
			return 1
		}
		fmt.Println(govruntime.MarshalRecord(rec))
		return 0
	case "quarantine":
		return quarantine(args[1:])
	case "score":
		if len(args) != 4 || args[1] != "agents" || args[2] != "--job-type" {
			return bad("usage: gov score agents --job-type <type>")
		}
		scores, err := observability.ScoreAgents(govruntime.Home(), args[3])
		if err != nil {
			fmt.Fprintln(os.Stderr, "score:", err)
			return 1
		}
		if len(scores) == 0 {
			fmt.Printf("no scored runs for job_type=%s\n", args[3])
			return 0
		}
		fmt.Println("agent\tjob_type\truns\tvalid\tfailures\tvalid_rate\tcost_per_valid_output")
		for _, score := range scores {
			fmt.Println(score.String())
		}
		return 0
	case "failures":
		if len(args) != 1 {
			return bad("usage: gov failures")
		}
		failures, err := observability.Failures(govruntime.Home(), 50)
		if err != nil {
			fmt.Fprintln(os.Stderr, "failures:", err)
			return 1
		}
		if len(failures) == 0 {
			fmt.Println("no classified failures")
			return 0
		}
		fmt.Println("run_id\tagent\tjob_type\ttaxonomy\tmessage\trepair_lineage")
		for _, failure := range failures {
			fmt.Println(failure.String())
		}
		return 0
	case "cost":
		if len(args) != 2 || args[1] != "--per-valid-output" {
			return bad("usage: gov cost --per-valid-output")
		}
		summary, err := observability.CostPerValidOutput(govruntime.Home())
		if err != nil {
			fmt.Fprintln(os.Stderr, "cost:", err)
			return 1
		}
		fmt.Println(summary.String())
		return 0
	case "spend":
		return spendCmd(args[1:])
	case "quota":
		return quotaCmd(args[1:])
	case "usage":
		if len(args) != 2 {
			return bad("usage: gov usage summary|<run_id>")
		}
		runID := args[1]
		if runID == "summary" {
			runID = ""
		}
		report, err := observability.UsageSummaryFor(govruntime.Home(), runID)
		if err != nil {
			fmt.Fprintln(os.Stderr, "usage:", err)
			return 1
		}
		if runID != "" && report.Runs == 0 {
			fmt.Fprintln(os.Stderr, "usage: run not found:", runID)
			return 1
		}
		fmt.Println(report.String())
		return 0
	case "analytics":
		return analyticsCmd(args[1:])
	case "route":
		if len(args) == 3 && args[1] == "--explain" {
			return routeExplain(args[2])
		}
		if len(args) != 3 || args[1] != "--job-type" {
			return bad("usage: gov route --job-type <type>  |  gov route --explain <contract.yaml>")
		}
		candidates, err := observability.RouteAgents(govruntime.Home(), args[2])
		if err != nil {
			fmt.Fprintln(os.Stderr, "route:", err)
			return 1
		}
		if len(candidates) == 0 {
			fmt.Printf("no routing evidence for job_type=%s\n", args[2])
			return 0
		}
		fmt.Println("agent\tjob_type\truns\tfailures\tfailure_rate")
		for _, candidate := range candidates {
			fmt.Println(candidate.String())
		}
		return 0
	case "repair-packet":
		if len(args) != 2 {
			return bad("usage: gov repair-packet <run_id>")
		}
		packet, err := observability.GenerateRepairPacket(govruntime.Home(), args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, "repair-packet:", err)
			return 1
		}
		output, err := json.MarshalIndent(packet, "", "  ")
		if err != nil {
			fmt.Fprintln(os.Stderr, "repair-packet:", err)
			return 1
		}
		fmt.Println(string(output))
		return 0
	case "eval":
		if len(args) == 3 && args[1] == "harness" {
			results, err := observability.RunEvalSuite(govruntime.Home(), args[2])
			if err != nil {
				fmt.Fprintln(os.Stderr, "eval:", err)
				return 1
			}
			failed := false
			for _, result := range results {
				status := "PASS"
				if !result.Passed {
					status = "FAIL"
					failed = true
				}
				fmt.Printf("%s\t%s\t%s\t%s\n", status, result.CaseName, result.Expected, result.Actual)
			}
			if failed {
				return 1
			}
			return 0
		}
		if len(args) == 2 && args[1] == "scorecard" {
			scores, err := observability.EvalScorecard(govruntime.Home())
			if err != nil {
				fmt.Fprintln(os.Stderr, "eval:", err)
				return 1
			}
			fmt.Println("agent\tmode\truns\tpassed\tpass_rate\tcost")
			for _, score := range scores {
				fmt.Println(score.String())
			}
			return 0
		}
		return bad("usage: gov eval harness <case-dir> | gov eval scorecard")
	case "protect":
		return protectCmd(args[1:])
	case "snap":
		return snapCmd(args[1:])
	case "graph":
		return graphCmd(args[1:])
	case "parity":
		return parityCmd(args[1:])
	case "hook":
		return hookCmd(args[1:])
	case "gate":
		return gateCmd(args[1:])
	case "reconcile":
		return reconcileCmd(args[1:])
	case "ask":
		return askCmd(args[1:])
	case "containment":
		return containmentCmd(args[1:])
	case "attest":
		return attestCmd(args[1:])
	case "cleanup":
		return cleanupCmd(args[1:])
	case "doctor":
		if len(args) != 1 {
			return bad("usage: gov doctor")
		}
		checks := doctor.Run()
		for _, c := range checks {
			label := "OK"
			if c.Status == doctor.StatusWarn {
				label = "WARN"
			} else if c.Status == doctor.StatusFail {
				label = "FAIL"
			}
			fmt.Printf("[%s] %-18s %s\n", label, c.Name, c.Detail)
		}
		if !doctor.Passed(checks) {
			fmt.Println("doctor: FAILED")
			return 1
		}
		fmt.Println("doctor: OK")
		return 0
	case "health":
		return healthCmd(args[1:])
	case "claims":
		return claimsCmd(args[1:])
	case "version":
		return versionCmd(args[1:])
	case "--version", "-version":
		return versionCmd(nil)
	case "help", "--help", "-h":
		usage()
		return 0
	default:
		return bad(fmt.Sprintf("unknown command %q", args[0]))
	}
}

func initCmd(args []string) int {
	if len(args) != 0 {
		return bad("usage: gov init")
	}
	cwd, err := os.Getwd()
	if err != nil {
		return bad("init: " + err.Error())
	}
	results, err := config.Scaffold(cwd)
	if err != nil {
		return bad("init: " + err.Error())
	}
	for _, result := range results {
		action := "WRITE"
		if result.Skipped {
			action = "SKIP"
		}
		fmt.Printf("%s %s\n", action, result.Path)
	}
	fmt.Printf("Next: gov validate %s\n", filepath.Join(config.HomeDir(), ".governator", "jobs", "example.yaml"))
	return 0
}

func quarantine(args []string) int {
	if len(args) == 1 && args[0] == "list" {
		rs, err := govruntime.Quarantines()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		for _, r := range rs {
			fmt.Printf("%s\t%s\t%s\t%s\n", r.ID, r.JobID, r.Created, r.Message)
		}
		return 0
	}
	if len(args) == 2 && (args[0] == "show" || args[0] == "diff") {
		r, err := govruntime.Last(args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if r.Status != "QUARANTINED" {
			fmt.Fprintln(os.Stderr, "run is not quarantined")
			return 1
		}
		if args[0] == "diff" {
			fmt.Print(r.Diff)
		} else {
			fmt.Println(govruntime.MarshalRecord(r))
		}
		return 0
	}
	return bad("usage: gov quarantine list|show <id>|diff <id>")
}

// analyticsCmd handles the Phase 7 analytical-projection subcommands.
// `summary` prints every metric as tab-separated tables (matching the
// score/failures/route command idiom); `export` writes the same snapshot as
// line-delimited JSON — the whole Phase 7 shipping mechanism, since no
// outbox/Supabase replication exists to hand this to (see phase7.go).
func analyticsCmd(args []string) int {
	if len(args) == 0 {
		return bad("usage: gov analytics summary|export [--out <path>]")
	}
	switch args[0] {
	case "summary":
		if len(args) != 1 {
			return bad("usage: gov analytics summary")
		}
		snap, err := observability.BuildAnalyticsSnapshot(govruntime.Home())
		if err != nil {
			fmt.Fprintln(os.Stderr, "analytics:", err)
			return 1
		}
		fmt.Println("backend\truns\tvalid_outputs\tvalid_rate")
		for _, r := range snap.BackendValidRate {
			fmt.Printf("%s\t%d\t%d\t%.4f\n", r.Backend, r.Runs, r.ValidOutputs, r.ValidRate)
		}
		fmt.Println("backend\ttaxonomy\tcount")
		for _, r := range snap.FailureByBackend {
			fmt.Printf("%s\t%s\t%d\n", r.Backend, r.Taxonomy, r.Count)
		}
		fmt.Println("backend\tfallback_count")
		for _, r := range snap.FallbackFreq {
			fmt.Printf("%s\t%d\n", r.Backend, r.Count)
		}
		fmt.Println("backend\taccount\twindow\tutilization\tconfidence")
		for _, r := range snap.QuotaUtil {
			fmt.Printf("%s\t%s\t%s\t%.4f\t%.2f\n", r.Backend, r.Account, r.WindowType, r.Utilization, r.Confidence)
		}
		fmt.Printf("repair_depth\tlineages=%d total=%d max=%d avg=%.2f\n",
			snap.RepairDepth.Lineages, snap.RepairDepth.TotalRepairs, snap.RepairDepth.MaxDepth, snap.RepairDepth.AvgDepth)
		fmt.Println("assay_profile\tfailed_check\tcount")
		for _, r := range snap.AssayFails {
			fmt.Printf("%s\t%s\t%d\n", r.Profile, r.FailedCheck, r.Count)
		}
		fmt.Println("validator_command\tfailures")
		for _, r := range snap.ValidatorFails {
			fmt.Printf("%s\t%d\n", r.Command, r.Count)
		}
		fmt.Printf("panel_disagreement\tpanels=%d disagreements=%d rate=%.4f\n",
			snap.PanelDisagree.Panels, snap.PanelDisagree.Disagreements, snap.PanelDisagree.Rate)
		fmt.Printf("cost_by_outcome\tapproved=%d($%.2f, $%.4f/ea)\trejected=%d($%.2f, $%.4f/ea)\n",
			snap.CostByOutcome.ApprovedCount, snap.CostByOutcome.ApprovedCostUSD, snap.CostByOutcome.CostPerApproved,
			snap.CostByOutcome.RejectedCount, snap.CostByOutcome.RejectedCostUSD, snap.CostByOutcome.CostPerRejected)
		return 0
	case "export":
		rest := args[1:]
		out := os.Stdout
		if len(rest) == 2 && rest[0] == "--out" {
			f, err := os.Create(rest[1])
			if err != nil {
				fmt.Fprintln(os.Stderr, "analytics export:", err)
				return 1
			}
			defer f.Close()
			out = f
		} else if len(rest) != 0 {
			return bad("usage: gov analytics export [--out <path>]")
		}
		if err := observability.ExportJSONL(govruntime.Home(), out); err != nil {
			fmt.Fprintln(os.Stderr, "analytics export:", err)
			return 1
		}
		return 0
	default:
		return bad("usage: gov analytics summary|export [--out <path>]")
	}
}

// runRecoveryDispatch handles the Phase 4 durable-recovery subcommands: `gov
// run inspect|resume|abandon <run_id>` and `gov run recover --stale`. args[0]
// is the subcommand name (inspect/resume/abandon/recover).
func runRecoveryDispatch(args []string) int {
	switch args[0] {
	case "inspect":
		if len(args) != 2 {
			return bad("usage: gov run inspect <run_id>")
		}
		rec, stages, err := govruntime.InspectRun(args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, "run inspect:", err)
			return 1
		}
		fmt.Println(govruntime.MarshalRecord(rec))
		fmt.Println("stage\tdetail\tcreated")
		for _, s := range stages {
			fmt.Printf("%s\t%s\t%s\n", s.Stage, s.Detail, s.Created)
		}
		return 0
	case "resume":
		if len(args) != 2 {
			return bad("usage: gov run resume <run_id>")
		}
		v, err := govruntime.ResumeRun(context.Background(), args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, "run resume:", err)
			return 1
		}
		return printRecoveryVerdicts([]govruntime.RecoveryVerdict{v})
	case "abandon":
		if len(args) != 2 {
			return bad("usage: gov run abandon <run_id>")
		}
		v, err := govruntime.AbandonRun(args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, "run abandon:", err)
			return 1
		}
		return printRecoveryVerdicts([]govruntime.RecoveryVerdict{v})
	case "recover":
		if len(args) != 2 || args[1] != "--stale" {
			return bad("usage: gov run recover --stale")
		}
		verdicts, err := govruntime.RecoverStaleRuns(context.Background())
		if err != nil {
			fmt.Fprintln(os.Stderr, "run recover:", err)
			return 1
		}
		if len(verdicts) == 0 {
			fmt.Println("no interrupted runs found")
			return 0
		}
		return printRecoveryVerdicts(verdicts)
	}
	return bad("usage: gov run inspect|resume|abandon <run_id> | gov run recover --stale")
}

func printRecoveryVerdicts(verdicts []govruntime.RecoveryVerdict) int {
	fmt.Println("run_id\taction\tdetail")
	for _, v := range verdicts {
		fmt.Printf("%s\t%s\t%s\n", v.RunID, v.Action, v.Detail)
	}
	return 0
}

func spendCmd(args []string) int {
	cfg := config.Current()
	if len(args) == 1 {
		switch args[0] {
		case "--halt":
			if err := spend.Halt(cfg); err != nil {
				fmt.Fprintln(os.Stderr, "spend:", err)
				return 1
			}
			fmt.Println("halted:", cfg.Spend.HaltFile)
			return 0
		case "--resume":
			if err := spend.Resume(cfg); err != nil {
				fmt.Fprintln(os.Stderr, "spend:", err)
				return 1
			}
			fmt.Println("resumed")
			return 0
		}
		return bad("usage: gov spend [--halt|--resume]")
	}
	if len(args) != 0 {
		return bad("usage: gov spend [--halt|--resume]")
	}
	db, err := observability.Open(govruntime.Home())
	if err != nil {
		fmt.Fprintln(os.Stderr, "spend:", err)
		return 1
	}
	defer db.Close()
	today, err := spend.TodaySpend(db)
	if err != nil {
		fmt.Fprintln(os.Stderr, "spend:", err)
		return 1
	}
	remaining := "unlimited"
	if cfg.Spend.DailyCapUSD > 0 {
		remaining = fmt.Sprintf("$%.4f", cfg.Spend.DailyCapUSD-today.TotalCostUSD)
	}
	fmt.Printf("date=%s total_cost_usd=%.4f cap_usd=%.2f remaining=%s runs=%d unknown_cost_runs=%d halted=%t\n",
		today.Date, today.TotalCostUSD, cfg.Spend.DailyCapUSD, remaining, today.Runs, today.UnknownCostRuns, spend.IsHalted(cfg))
	return 0
}

func quotaCmd(args []string) int {
	if len(args) != 0 {
		return bad("usage: gov quota")
	}
	db, err := observability.Open(govruntime.Home())
	if err != nil {
		fmt.Fprintln(os.Stderr, "quota:", err)
		return 1
	}
	defer db.Close()
	now := time.Now().UTC()
	cfg := config.Current()
	if err := quota.SeedFromConfig(db, cfg, now); err != nil {
		fmt.Fprintln(os.Stderr, "quota:", err)
		return 1
	}
	if err := quota.ExpireStale(db, now); err != nil {
		fmt.Fprintln(os.Stderr, "quota:", err)
		return 1
	}
	windows, err := quota.Windows(db, now)
	if err != nil {
		fmt.Fprintln(os.Stderr, "quota:", err)
		return 1
	}
	if len(windows) == 0 {
		fmt.Println("no quota windows configured")
		return 0
	}
	fmt.Println("backend\taccount\twindow\tlimit\tmeasured\treserved\theadroom\treset_at\tconfidence\tsource")
	for _, w := range windows {
		limit := w.EstimatedLimit
		headroom := 1.0
		if limit > 0 {
			headroom = (limit - w.MeasuredUsage - w.ReservedUsage) / limit
			if headroom < 0 {
				headroom = 0
			}
		}
		fmt.Printf("%s\t%s\t%s\t%.0f\t%.0f\t%.0f\t%.1f%%\t%s\t%.2f\t%s\n",
			w.Backend, w.Account, w.WindowType, limit, w.MeasuredUsage, w.ReservedUsage, headroom*100,
			orHealthDash(formatCooldown(w.ResetAt)), w.Confidence, w.Source)
	}
	return 0
}

// reconcileCmd drains the maintenance_outbox (Session 4 / Sol Phase 3): every
// post-run operation that was swallowed before now durably retries here
// instead of vanishing with the run that first attempted it.
func reconcileCmd(args []string) int {
	if len(args) != 0 {
		return bad("usage: gov reconcile")
	}
	report, err := govruntime.Reconcile(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, "reconcile:", err)
		return 1
	}
	output, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "reconcile:", err)
		return 1
	}
	fmt.Println(string(output))
	if report.Retried > 0 {
		return 1
	}
	return 0
}

// askCmd is the Session 5 (Sol Phase 4) uniform operator interface for a
// checkpointed ASK, regardless of which candidate target (network
// enablement, write outside intended scope, cost threshold, fallback after
// an unusual infra failure, or a custom contract/project-doctrine rule)
// produced it — the same list/show/approve/deny mechanism works across
// every backend, since every checkpoint lives in the one policy_checkpoints
// ledger table.
func askCmd(args []string) int {
	usage := "usage: gov ask list|show <id>|approve <id> [--rule] [--ttl <duration>] [--by <name>] [--note <text>]|deny <id> [--rule] [--ttl <duration>] [--by <name>] [--note <text>]"
	if len(args) == 0 {
		return bad(usage)
	}
	switch args[0] {
	case "list":
		if len(args) != 1 {
			return bad("usage: gov ask list")
		}
		items, err := govruntime.AskList()
		if err != nil {
			fmt.Fprintln(os.Stderr, "ask:", err)
			return 1
		}
		for _, cp := range items {
			fmt.Printf("%d\t%s\t%s\t%s\t%s\n", cp.ID, cp.JobID, cp.Target, cp.CreatedAt, cp.Reason)
		}
		return 0
	case "show":
		if len(args) != 2 {
			return bad("usage: gov ask show <id>")
		}
		id, err := strconv.ParseInt(args[1], 10, 64)
		if err != nil {
			return bad("gov ask show: id must be an integer")
		}
		cp, err := govruntime.AskShow(id)
		if err != nil {
			fmt.Fprintln(os.Stderr, "ask:", err)
			return 1
		}
		return printJSON("ask", cp)
	case "approve", "deny":
		return askResolveCmd(args)
	default:
		return bad(usage)
	}
}

// containmentCmd prints the exact bytes an operator signs (ed25519, hex
// signature) to authorize a risk-class containment override for one
// contract. The message binds job_id, the contract-content hash (containment
// block cleared — the signature can't cover itself), and the override
// reason, so an override can't be replayed against another job OR against an
// edited contract body. Workflow: `gov containment message job.yaml --reason
// "why" | <sign>`, then put both override_reason and the hex signature into
// the contract's containment block. --reason is required for first-time
// signing because a contract with a reason but no signature fails validation
// (half-declared overrides are rejected); a contract that already carries a
// complete override may omit it to re-derive the message for verification.
func attestCmd(args []string) int {
	if len(args) != 1 {
		return bad("usage: gov attest <backend>")
	}
	cfg := config.Current()
	db, err := observability.Open(cfg.LedgerDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "attest:", err)
		return 1
	}
	defer db.Close()
	a, err := attest.Generate(context.Background(), cfg, args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, "attest:", err)
		return 1
	}
	if err := attest.Store(db, a); err != nil {
		fmt.Fprintln(os.Stderr, "attest:", err)
		return 1
	}
	_ = json.NewEncoder(os.Stdout).Encode(a)
	if !attest.RequiredProbesPassedForBackend(a, args[0]) {
		fmt.Fprintln(os.Stderr, "attest: required capability probe failed")
		return 1
	}
	return 0
}

func containmentCmd(args []string) int {
	usage := "usage: gov containment message <job.yaml> [--reason <text>]"
	if len(args) < 2 || args[0] != "message" {
		return bad(usage)
	}
	path := args[1]
	reason := ""
	rest := args[2:]
	for len(rest) > 0 {
		switch rest[0] {
		case "--reason":
			if len(rest) < 2 {
				return bad("gov containment message: --reason requires text")
			}
			reason = rest[1]
			rest = rest[2:]
		default:
			return bad(usage)
		}
	}
	c, err := contracts.ParseFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "containment:", err)
		return 1
	}
	if reason != "" {
		c.Containment = &contracts.Containment{OverrideReason: reason}
	}
	if c.Containment == nil || strings.TrimSpace(c.Containment.OverrideReason) == "" {
		fmt.Fprintln(os.Stderr, "containment: no override reason — pass --reason <text> (the reason is part of what gets signed)")
		return 1
	}
	msg, err := containment.SigningMessage(*c)
	if err != nil {
		fmt.Fprintln(os.Stderr, "containment:", err)
		return 1
	}
	fmt.Print(string(msg))
	return 0
}

func askResolveCmd(args []string) int {
	verb := args[0]
	usage := fmt.Sprintf("usage: gov ask %s <id> [--rule] [--ttl <duration>] [--by <name>] [--note <text>]", verb)
	if len(args) < 2 {
		return bad(usage)
	}
	id, err := strconv.ParseInt(args[1], 10, 64)
	if err != nil {
		return bad("gov ask " + verb + ": id must be an integer")
	}
	res := govruntime.AskResolution{ResolvedBy: "operator", Verdict: "DENY"}
	if verb == "approve" {
		res.Verdict = "ALLOW"
	}
	rest := args[2:]
	for len(rest) > 0 {
		switch rest[0] {
		case "--rule":
			res.CreateRule = true
			rest = rest[1:]
		case "--ttl":
			if len(rest) < 2 {
				return bad("gov ask " + verb + ": --ttl requires a duration (e.g. 24h)")
			}
			d, err := time.ParseDuration(rest[1])
			if err != nil {
				return bad("gov ask " + verb + ": invalid --ttl duration: " + err.Error())
			}
			res.TTL = d
			rest = rest[2:]
		case "--by":
			if len(rest) < 2 {
				return bad("gov ask " + verb + ": --by requires a name")
			}
			res.ResolvedBy = rest[1]
			rest = rest[2:]
		case "--note":
			if len(rest) < 2 {
				return bad("gov ask " + verb + ": --note requires text")
			}
			res.Note = rest[1]
			rest = rest[2:]
		default:
			return bad(usage)
		}
	}
	cp, err := govruntime.AskResolve(id, res)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ask:", err)
		return 1
	}
	return printJSON("ask", cp)
}

// printJSON marshals v as indented JSON to stdout, the common tail of every
// gov subcommand that reports a single structured result (reconcileCmd,
// cleanupCmd, ...). label prefixes the stderr line on a marshal error only —
// callers already own their own error message for the operation itself.
func printJSON(label string, v any) int {
	output, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, label+":", err)
		return 1
	}
	fmt.Println(string(output))
	return 0
}

// cleanupCmd handles `gov cleanup --stale`: outbox rows that have exhausted
// their retry budget are marked dead so `gov reconcile` stops looping on an
// operation that has proven unrecoverable. Rows are never deleted — the
// operational_errors/outbox audit trail survives; only the status changes.
func cleanupCmd(args []string) int {
	if len(args) < 1 || args[0] != "--stale" {
		return bad("usage: gov cleanup --stale [--max-attempts N]")
	}
	maxAttempts := 8
	rest := args[1:]
	for len(rest) > 0 {
		switch rest[0] {
		case "--max-attempts":
			if len(rest) < 2 {
				return bad("usage: gov cleanup --stale [--max-attempts N]")
			}
			n, err := strconv.Atoi(rest[1])
			if err != nil || n < 1 {
				return bad("gov cleanup: --max-attempts must be a positive integer")
			}
			maxAttempts = n
			rest = rest[2:]
		default:
			return bad("usage: gov cleanup --stale [--max-attempts N]")
		}
	}
	report, err := govruntime.CleanupStale(maxAttempts)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cleanup:", err)
		return 1
	}
	output, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "cleanup:", err)
		return 1
	}
	fmt.Println(string(output))
	return 0
}

func batchCmd(args []string) int {
	if len(args) < 1 || args[0] != "run" {
		return bad("usage: gov batch run <job.yaml|dir|glob>... [--parallel N] [--halt-on-first-quarantine] [--ordered]")
	}
	args = args[1:]

	opts := govruntime.BatchOptions{}
	ordered := false
	var pathArgs []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--parallel":
			if i+1 >= len(args) {
				return bad("usage: gov batch run ... --parallel N")
			}
			n, err := strconv.Atoi(args[i+1])
			if err != nil || n <= 0 {
				return bad("gov batch run: --parallel must be a positive integer")
			}
			opts.Parallel = n
			i++
		case "--halt-on-first-quarantine":
			opts.HaltOnFirstQuarantine = true
		case "--ordered":
			ordered = true
		default:
			pathArgs = append(pathArgs, args[i])
		}
	}
	if len(pathArgs) == 0 {
		return bad("usage: gov batch run <job.yaml|dir|glob>... [--parallel N] [--halt-on-first-quarantine] [--ordered]")
	}

	paths, err := resolveJobPaths(pathArgs)
	if err != nil {
		fmt.Fprintln(os.Stderr, "batch:", err)
		return 2
	}
	if len(paths) == 0 {
		fmt.Fprintln(os.Stderr, "batch: no job files matched", pathArgs)
		return 2
	}

	jobs := make([]contracts.Contract, 0, len(paths))
	invalid := false
	for _, p := range paths {
		c, err := contracts.ParseFile(p)
		if err != nil {
			contractError(p, err)
			invalid = true
			continue
		}
		jobs = append(jobs, *c)
	}
	if invalid {
		fmt.Fprintln(os.Stderr, "batch: refusing to run — one or more contracts are invalid")
		return 2
	}

	// depends_on is only honored under --ordered, and TopologicalLevels
	// silently drops references it can't resolve within the set — so a
	// hand-picked subset would otherwise run a job WITHOUT its declared
	// prerequisite. Fail closed on both instead.
	ids := make(map[string]bool, len(jobs))
	for _, j := range jobs {
		ids[j.JobID] = true
	}
	hasDeps := false
	for _, j := range jobs {
		for _, dep := range j.DependsOn {
			hasDeps = true
			if !ids[dep] {
				fmt.Fprintf(os.Stderr, "batch: job %s depends_on %q, which is not in this batch — include it or fix the contract\n", j.JobID, dep)
				return 2
			}
		}
	}
	if hasDeps && !ordered {
		fmt.Fprintln(os.Stderr, "batch: contracts declare depends_on; run with --ordered so dependencies execute first")
		return 2
	}

	// ArtifactSources is yaml:"-": the consumed-artifact -> producing-job
	// mapping never survives the plan -> per-job-file -> ParseFile round trip,
	// so it must be recomputed over the batch before launch or every consuming
	// job would refuse to stage its inputs. Fails closed when a consumed
	// artifact has no producing depends_on ancestor in this batch.
	if aErrs := contracts.ResolveArtifactSources(jobs); len(aErrs) > 0 {
		fmt.Fprintln(os.Stderr, "batch:", aErrs.Sorted().Error())
		return 2
	}

	var panelSpec *contracts.PanelSpec
	if ordered {
		panelSpec, err = detectPanelSpec(pathArgs)
		if err != nil {
			fmt.Fprintln(os.Stderr, "batch:", err)
			return 2
		}
	}

	var summary govruntime.BatchSummary
	if ordered {
		levels, lErr := contracts.TopologicalLevels(jobs)
		if lErr != nil {
			fmt.Fprintln(os.Stderr, "batch:", lErr)
			return 2
		}
		if panelSpec != nil {
			var preport govruntime.PanelReport
			summary, preport, err = govruntime.New().RunPanel(context.Background(), *panelSpec, levels, opts)
			printPanelReport(preport)
		} else {
			summary, err = govruntime.New().RunBatchOrdered(context.Background(), levels, opts)
		}
	} else {
		summary, err = govruntime.New().RunBatch(context.Background(), jobs, opts)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "batch:", err)
		return 1
	}

	fmt.Println("batch_id:", summary.BatchID)
	fmt.Println("job_id\trun_id\tstatus\ttaxonomy\tcost_usd\tworktree")
	allApproved := true
	for _, j := range summary.Jobs {
		if j.Status != "APPROVED" {
			allApproved = false
		}
		fmt.Printf("%s\t%s\t%s\t%s\t%.4f\t%s\n", j.JobID, j.RunID, j.Status, j.Taxonomy, j.CostUSD, j.Worktree)
	}
	fmt.Printf("jobs=%d quarantined=%d total_cost_usd=%.4f\n", len(summary.Jobs), summary.Quarantined, summary.TotalCostUSD)
	if !allApproved {
		return 1
	}
	return 0
}

// resolveJobPaths expands a mix of explicit file paths, directories (every
// *.yaml file directly inside, non-recursive), and shell-style globs (for
// callers that quote the pattern so their shell doesn't expand it) into a
// flat, order-preserving list of job contract paths.
// planManifestName is the reserved filename for a gov plan's DAG manifest
// (contracts.Plan, a list of jobs — not itself a single runnable Contract).
// Directory/glob expansion below skips it so `gov batch run jobs/<slug>/`
// naturally picks up only the exploded per-job files sitting beside it.
const planManifestName = "PLAN.yaml"

func resolveJobPaths(args []string) ([]string, error) {
	var out []string
	for _, a := range args {
		switch {
		case strings.ContainsAny(a, "*?["):
			matches, err := filepath.Glob(a)
			if err != nil {
				return nil, fmt.Errorf("glob %s: %w", a, err)
			}
			out = append(out, excludePlanManifest(matches)...)
		default:
			info, err := os.Stat(a)
			if err != nil {
				return nil, fmt.Errorf("stat %s: %w", a, err)
			}
			if info.IsDir() {
				matches, err := filepath.Glob(filepath.Join(a, "*.yaml"))
				if err != nil {
					return nil, fmt.Errorf("glob %s: %w", a, err)
				}
				out = append(out, excludePlanManifest(matches)...)
			} else {
				out = append(out, a)
			}
		}
	}
	return out, nil
}

// detectPanelSpec looks for a PLAN.yaml with a panel: block alongside any
// directory argument in a `gov batch run --ordered` invocation. PLAN.yaml
// itself is always excluded from the job set (excludePlanManifest), so this
// is the only place batchCmd ever reads it: finding it here is what
// switches execution from plain RunBatchOrdered to RunPanel's
// diversity/quorum-aware path, without requiring a separate `gov panel run`
// subcommand or changing what `gov batch run --ordered jobs/panel/` looks
// like on the command line. Non-directory args and directories with no
// PLAN.yaml (or a PLAN.yaml with no panel: block) are ordinary batches.
// More than one panel plan among the arguments is refused — a single batch
// run drives at most one panel's quorum/diversity accounting.
func detectPanelSpec(pathArgs []string) (*contracts.PanelSpec, error) {
	var found *contracts.PanelSpec
	var foundAt string
	for _, a := range pathArgs {
		info, err := os.Stat(a)
		if err != nil || !info.IsDir() {
			continue
		}
		planPath := filepath.Join(a, planManifestName)
		data, err := os.ReadFile(planPath)
		if err != nil {
			continue
		}
		plan, perr := contracts.ParsePlan(data)
		if perr != nil {
			return nil, fmt.Errorf("%s: %w", planPath, perr)
		}
		if plan.Panel == nil {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("multiple panel plans found (%s and %s) — run each panel separately", foundAt, planPath)
		}
		found, foundAt = plan.Panel, planPath
	}
	return found, nil
}

// printPanelReport prints the diversity/quorum accounting RunPanel produced
// — the Phase 2 "never silently" bar applied to CLI output: an operator
// sees exactly which backends were chosen and why the panel degraded (if it
// did), not just a plain job table indistinguishable from an ordinary batch.
func printPanelReport(r govruntime.PanelReport) {
	if len(r.Diversity) > 0 {
		fmt.Printf("panel diversity: key=%s unique=%d/%d\n", r.DiversityKey, r.DiversityUnique, r.DiversityWanted)
		for _, d := range r.Diversity {
			fmt.Printf("  %s -> %s\n", d.JobID, d.Selected)
		}
	}
	if r.Degraded {
		fmt.Println("panel degraded:")
		for _, reason := range r.DegradedReasons {
			fmt.Println("  -", reason)
		}
	}
}

func excludePlanManifest(paths []string) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		if filepath.Base(p) == planManifestName {
			continue
		}
		out = append(out, p)
	}
	return out
}

const planUsage = "usage: gov plan <intent.md> --out <dir> --envelope <pattern>... --max-total-tokens <n> [--backend <name>]\n" +
	"       gov plan --panel <n> <intent.md> --out <dir> --envelope <pattern>... --max-total-tokens <n> [--backend <name>]\n" +
	"           [--min-success <n>] [--member-timeout-seconds <n>] [--hard-timeout-seconds <n>]\n" +
	"           [--diversity-key backend|model_family] [--diversity-min-unique <n>] [--diversity-fallback-key backend|model_family]\n" +
	"       gov plan --show <dir>"

func planCmd(args []string) int {
	if len(args) == 0 {
		return bad(planUsage)
	}
	if args[0] == "--show" {
		if len(args) != 2 {
			return bad(planUsage)
		}
		return planShow(args[1])
	}
	if args[0] == "--panel" {
		return planPanelCreate(args[1:])
	}
	return planCreate(args)
}

// planCreate compiles and runs the planner job that turns an intent file
// into a validated PLAN.yaml, then explodes each approved sub-contract into
// its own runnable job file inside --out. Every structural check (schema,
// envelope, budget, cycles) happens in contracts.ValidatePlan via the
// compiled contract's PostRunValidate hook, which runs in-process before the
// merge — so a malformed plan quarantines and nothing lands on disk, exactly
// like any other governed job.
func planCreate(args []string) int {
	intentPath := args[0]
	var outDir, backend string
	var envelope []string
	maxTotalTokens := 0
	rest := args[1:]
	for i := 0; i < len(rest); i++ {
		switch rest[i] {
		case "--out":
			if i+1 >= len(rest) {
				return bad(planUsage)
			}
			outDir = rest[i+1]
			i++
		case "--envelope":
			if i+1 >= len(rest) {
				return bad(planUsage)
			}
			envelope = append(envelope, rest[i+1])
			i++
		case "--max-total-tokens":
			if i+1 >= len(rest) {
				return bad(planUsage)
			}
			n, err := strconv.Atoi(rest[i+1])
			if err != nil || n <= 0 {
				return bad("gov plan: --max-total-tokens must be a positive integer")
			}
			maxTotalTokens = n
			i++
		case "--backend":
			if i+1 >= len(rest) {
				return bad(planUsage)
			}
			backend = rest[i+1]
			i++
		default:
			return bad(planUsage)
		}
	}
	if outDir == "" || len(envelope) == 0 || maxTotalTokens <= 0 {
		return bad(planUsage)
	}

	intent, err := os.ReadFile(intentPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "plan:", err)
		return 1
	}
	root, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, "plan:", err)
		return 1
	}

	outRel := filepath.ToSlash(filepath.Clean(outDir))
	if filepath.IsAbs(outRel) || outRel == ".." || strings.HasPrefix(outRel, "../") {
		return bad("gov plan: --out must be a relative path inside the project root")
	}
	slug := filepath.Base(outRel)
	planRel := outRel + "/" + planManifestName

	if backend == "" {
		if candidates, rErr := observability.RouteAgents(govruntime.Home(), "planning"); rErr == nil && len(candidates) > 0 {
			backend = candidates[0].Agent
		} else {
			backend = config.Current().Defaults.Agent
		}
	}

	c := contracts.Contract{
		Task:    planTask(string(intent), root, envelope, planRel, maxTotalTokens),
		JobID:   "plan-" + slug,
		JobType: "planning",
		Agent:   backend,
		Mode:    contracts.ModePlanner,
		Workspace: contracts.Workspace{
			Root: root, Worktree: "auto",
		},
		Allowed: contracts.Permissions{
			Read:  []string{"**"},
			Write: []string{outRel + "/**"},
		},
		Forbidden: contracts.Forbidden{
			Paths:     []string{".git/**"},
			Commands:  []string{"rm -rf"},
			Behaviors: []string{"network"},
		},
		Budget: contracts.Budget{
			// MaxFilesChanged/MaxNewFiles allow 2: PLAN.yaml plus the
			// backend's own RESULT.json, which lands in the worktree
			// alongside it and counts toward these budgets too.
			MaxMinutes: 15, MaxCommands: 10, MaxFilesChanged: 2,
			MaxLinesChanged: 1500, MaxNewFiles: 2, MaxDeleted: 0,
		},
		Preflight: contracts.Preflight{IntendedWrites: []string{planRel}},
		Success: contracts.Success{
			RequiredFiles: []string{planRel},
			Validators:    []string{"test -f " + planShQuote(planRel)},
		},
		OnViolation: "quarantine",
	}
	c.PostRunValidate = func(worktree string) error {
		plan, perr := contracts.ParsePlanFile(filepath.Join(worktree, filepath.FromSlash(planRel)))
		if perr != nil {
			return perr
		}
		_, verr := contracts.ValidatePlanManifest(plan, root, envelope, maxTotalTokens)
		return verr
	}

	rec, err := govruntime.New().RunWithAutoRepair(context.Background(), c)
	if err != nil {
		fmt.Fprintln(os.Stderr, "plan:", err)
		return 1
	}
	if rec.Status != "APPROVED" {
		fmt.Println(govruntime.MarshalRecord(rec))
		return 1
	}

	plan, err := contracts.ParsePlanFile(filepath.Join(root, filepath.FromSlash(planRel)))
	if err != nil {
		fmt.Fprintln(os.Stderr, "plan:", err)
		return 1
	}
	levels, err := contracts.ValidatePlanManifest(plan, root, envelope, maxTotalTokens)
	if err != nil {
		// PostRunValidate already gated this before the merge, so this
		// should be unreachable — surfaced defensively rather than exploding
		// a manifest nothing has actually approved.
		fmt.Fprintln(os.Stderr, "plan: approved manifest failed re-validation:", err)
		return 1
	}

	written := 0
	for _, job := range plan.Jobs {
		data, mErr := yaml.Marshal(job)
		if mErr != nil {
			fmt.Fprintln(os.Stderr, "plan:", mErr)
			return 1
		}
		path := filepath.Join(root, filepath.FromSlash(outRel), job.JobID+".yaml")
		if wErr := os.WriteFile(path, data, 0644); wErr != nil {
			fmt.Fprintln(os.Stderr, "plan:", wErr)
			return 1
		}
		written++
	}

	fmt.Printf("run_id: %s\nbackend: %s\nplan: %s\n", rec.ID, backend, filepath.Join(root, filepath.FromSlash(planRel)))
	printPlanTable(levels)
	fmt.Printf("jobs=%d levels=%d written=%d\n", len(plan.Jobs), len(levels), written)
	return 0
}

// planShow reads an already-written PLAN.yaml and renders its dependency
// DAG plus a per-job budget/risk table. It performs no envelope or budget
// re-validation (those aren't persisted in PLAN.yaml) — only cycle-safe
// topological ordering, which is intrinsic to the manifest itself.
func planShow(dir string) int {
	planPath := filepath.Join(dir, planManifestName)
	plan, err := contracts.ParsePlanFile(planPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "plan:", err)
		return 1
	}
	levels, err := contracts.TopologicalLevels(plan.Jobs)
	if err != nil {
		fmt.Fprintln(os.Stderr, "plan:", err)
		return 1
	}
	printPlanTable(levels)
	total := 0
	for _, job := range plan.Jobs {
		total += job.Budget.MaxTokens
	}
	fmt.Printf("jobs=%d levels=%d total_max_tokens=%d\n", len(plan.Jobs), len(levels), total)
	return 0
}

func printPlanTable(levels [][]contracts.Contract) {
	fmt.Println("level\tjob_id\trisk_class\tbudget.max_tokens\tdepends_on")
	for i, level := range levels {
		for _, job := range level {
			fmt.Printf("%d\t%s\t%s\t%d\t%s\n", i, job.JobID, job.RiskClass, job.Budget.MaxTokens, strings.Join(job.DependsOn, ","))
		}
	}
}

func planPanelCreate(args []string) int {
	if len(args) < 2 {
		return bad(planUsage)
	}
	count, err := strconv.Atoi(args[0])
	if err != nil || count < 2 {
		return bad("gov plan --panel: <n> must be an integer >= 2")
	}
	intentPath := args[1]
	var outDir, backend, diversityKey, diversityFallbackKey string
	var envelope []string
	maxTotalTokens, minSuccess, memberTimeoutSeconds, hardTimeoutSeconds, diversityMinUnique := 0, 0, 0, 0, 0
	rest := args[2:]
	intArg := func(name string, i int) (int, error) {
		if i+1 >= len(rest) {
			return 0, errors.New(planUsage)
		}
		n, err := strconv.Atoi(rest[i+1])
		if err != nil || n <= 0 {
			return 0, fmt.Errorf("gov plan --panel: %s must be a positive integer", name)
		}
		return n, nil
	}
	for i := 0; i < len(rest); i++ {
		switch rest[i] {
		case "--out":
			if i+1 >= len(rest) {
				return bad(planUsage)
			}
			outDir = rest[i+1]
			i++
		case "--envelope":
			if i+1 >= len(rest) {
				return bad(planUsage)
			}
			envelope = append(envelope, rest[i+1])
			i++
		case "--max-total-tokens":
			if i+1 >= len(rest) {
				return bad(planUsage)
			}
			n, nErr := strconv.Atoi(rest[i+1])
			if nErr != nil || n <= 0 {
				return bad("gov plan: --max-total-tokens must be a positive integer")
			}
			maxTotalTokens = n
			i++
		case "--backend":
			if i+1 >= len(rest) {
				return bad(planUsage)
			}
			backend = rest[i+1]
			i++
		case "--min-success":
			n, err := intArg("--min-success", i)
			if err != nil {
				return bad(err.Error())
			}
			minSuccess = n
			i++
		case "--member-timeout-seconds":
			n, err := intArg("--member-timeout-seconds", i)
			if err != nil {
				return bad(err.Error())
			}
			memberTimeoutSeconds = n
			i++
		case "--hard-timeout-seconds":
			n, err := intArg("--hard-timeout-seconds", i)
			if err != nil {
				return bad(err.Error())
			}
			hardTimeoutSeconds = n
			i++
		case "--diversity-key":
			if i+1 >= len(rest) {
				return bad(planUsage)
			}
			diversityKey = rest[i+1]
			i++
		case "--diversity-min-unique":
			n, err := intArg("--diversity-min-unique", i)
			if err != nil {
				return bad(err.Error())
			}
			diversityMinUnique = n
			i++
		case "--diversity-fallback-key":
			if i+1 >= len(rest) {
				return bad(planUsage)
			}
			diversityFallbackKey = rest[i+1]
			i++
		default:
			return bad(planUsage)
		}
	}
	if outDir == "" || len(envelope) == 0 || maxTotalTokens <= 0 {
		return bad(planUsage)
	}
	intent, err := os.ReadFile(intentPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "plan:", err)
		return 1
	}
	root, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, "plan:", err)
		return 1
	}
	if backend == "" {
		backend = config.Current().Defaults.Agent
	}
	plan, err := panel.GeneratePlan(panel.Options{
		Root: root, OutDir: outDir, Envelope: envelope, Count: count, Agent: backend, MaxTotalTokens: maxTotalTokens, Intent: string(intent),
		MinSuccess: minSuccess, MemberTimeoutSeconds: memberTimeoutSeconds, HardTimeoutSeconds: hardTimeoutSeconds,
		DiversityKey: diversityKey, DiversityMinUnique: diversityMinUnique, DiversityFallbackKey: diversityFallbackKey,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "plan:", err)
		return 1
	}
	levels, err := contracts.ValidatePlanManifest(&plan, root, envelope, maxTotalTokens)
	if err != nil {
		fmt.Fprintln(os.Stderr, "plan:", err)
		return 1
	}
	outRel := filepath.ToSlash(filepath.Clean(outDir))
	planPath := filepath.Join(root, filepath.FromSlash(outRel), planManifestName)
	if err := os.MkdirAll(filepath.Dir(planPath), 0755); err != nil {
		fmt.Fprintln(os.Stderr, "plan:", err)
		return 1
	}
	planData, err := yaml.Marshal(plan)
	if err != nil {
		fmt.Fprintln(os.Stderr, "plan:", err)
		return 1
	}
	if err := os.WriteFile(planPath, planData, 0644); err != nil {
		fmt.Fprintln(os.Stderr, "plan:", err)
		return 1
	}
	schemaDir := filepath.Join(root, filepath.FromSlash(outRel), "schemas")
	if err := os.MkdirAll(schemaDir, 0755); err != nil {
		fmt.Fprintln(os.Stderr, "plan:", err)
		return 1
	}
	for name, data := range panel.SchemaFiles() {
		if err := os.WriteFile(filepath.Join(schemaDir, name), data, 0644); err != nil {
			fmt.Fprintln(os.Stderr, "plan:", err)
			return 1
		}
	}
	written := 0
	for _, job := range plan.Jobs {
		data, mErr := yaml.Marshal(job)
		if mErr != nil {
			fmt.Fprintln(os.Stderr, "plan:", mErr)
			return 1
		}
		if wErr := os.WriteFile(filepath.Join(root, filepath.FromSlash(outRel), job.JobID+".yaml"), data, 0644); wErr != nil {
			fmt.Fprintln(os.Stderr, "plan:", wErr)
			return 1
		}
		written++
	}
	fmt.Printf("panel: %d members\nplan: %s\n", count, planPath)
	printPlanTable(levels)
	fmt.Printf("jobs=%d levels=%d written=%d schemas=%d\n", len(plan.Jobs), len(levels), written, len(panel.SchemaFiles()))
	return 0
}

func panelCmd(args []string) int {
	if len(args) < 4 || args[0] != "compare" || args[1] != "--out" {
		return bad("usage: gov panel compare --out <artifact.json> <input.json>...")
	}
	out := args[2]
	inputs := args[3:]
	data, err := panel.CompareFiles(inputs)
	if err != nil {
		fmt.Fprintln(os.Stderr, "panel:", err)
		return 1
	}
	if err := os.MkdirAll(filepath.Dir(out), 0755); err != nil {
		fmt.Fprintln(os.Stderr, "panel:", err)
		return 1
	}
	if err := os.WriteFile(out, data, 0644); err != nil {
		fmt.Fprintln(os.Stderr, "panel:", err)
		return 1
	}
	fmt.Println(out)
	return 0
}

func planTask(intent, root string, envelope []string, planRel string, maxTotalTokens int) string {
	return fmt.Sprintf(`Decompose the intent below into a governed execution plan.

INTENT:
%s

Write exactly one file, %s, containing a YAML mapping with a single top-level
key "jobs": an ordered list of governed sub-contracts. Every job in the list
must be a complete, valid Governator contract (the same shape as a normal
job.yaml: task, job_id, job_type, agent, mode, workspace, allowed, forbidden,
budget, preflight, success, on_violation) PLUS two extra fields:
  risk_class: low | medium | high
  depends_on: [other_job_id, ...]   # omit or leave empty if none

Hard requirements, checked deterministically after you finish:
  - Every job's workspace.root must equal %q exactly.
  - Every job's allowed.write / preflight.intended_writes patterns must stay
    inside this declared envelope: %v — writing anywhere else fails the plan.
  - Every job must set budget.max_tokens > 0, and the sum across all jobs
    must not exceed %d.
  - job_id must be unique across the plan.
  - depends_on may only reference other job_id values in this same plan, and
    must not form a cycle.
  - on_violation must be "quarantine" for every job.

Example single job entry (repeat this shape for each job in the list):
  - task: "Add input validation to the signup handler"
    job_id: signup-validation
    job_type: code_change
    agent: claude-code
    mode: surgeon
    workspace: {root: %q, worktree: auto}
    allowed: {read: ["**"], write: ["internal/signup/**"], execute: ["go test ./internal/signup"]}
    forbidden: {paths: [".git/**"], commands: ["rm -rf"], behaviors: [network]}
    budget: {max_minutes: 10, max_commands: 20, max_files_changed: 3, max_lines_changed: 150, max_new_files: 1, max_deleted: 0, max_tokens: 20000}
    preflight: {intended_writes: ["internal/signup/**"]}
    success: {required_files: ["internal/signup/handler.go"], validators: ["go test ./internal/signup"]}
    on_violation: quarantine
    risk_class: low
    depends_on: []

Do not write anything outside %s. Do not run any commands beyond what you
need to read the repository for context.`, strings.TrimSpace(intent), planRel, root, envelope, maxTotalTokens, root, planRel)
}

func planShQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }

func graphCmd(args []string) int {
	if len(args) == 0 {
		return bad("usage: gov graph status|refresh [path] | gov graph query <search> [--path <path>] [--limit <n>]")
	}
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, "graph:", err)
		return 1
	}
	printSnapshot := func(snapshot contextgraph.Snapshot) int {
		output, marshalErr := json.MarshalIndent(snapshot, "", "  ")
		if marshalErr != nil {
			fmt.Fprintln(os.Stderr, "graph:", marshalErr)
			return 1
		}
		fmt.Println(string(output))
		return 0
	}
	switch args[0] {
	case "status", "refresh":
		if len(args) > 2 {
			return bad("usage: gov graph " + args[0] + " [path]")
		}
		project := cwd
		if len(args) == 2 {
			project = args[1]
		}
		var snapshot contextgraph.Snapshot
		if args[0] == "status" {
			snapshot, err = contextgraph.Current(project)
		} else {
			snapshot, err = contextgraph.Prepare(context.Background(), project)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "graph:", err)
			return 1
		}
		return printSnapshot(snapshot)
	case "query":
		if len(args) < 2 {
			return bad("usage: gov graph query <search> [--path <path>] [--limit <n>]")
		}
		search, project, limit := args[1], cwd, 5
		for i := 2; i < len(args); i += 2 {
			if i+1 >= len(args) {
				return bad("usage: gov graph query <search> [--path <path>] [--limit <n>]")
			}
			switch args[i] {
			case "--path":
				project = args[i+1]
			case "--limit":
				limit, err = strconv.Atoi(args[i+1])
				if err != nil {
					return bad("graph: --limit must be an integer")
				}
			default:
				return bad("graph: unknown option " + args[i])
			}
		}
		snapshot, prepareErr := contextgraph.Prepare(context.Background(), project)
		if prepareErr != nil {
			fmt.Fprintln(os.Stderr, "graph:", prepareErr)
			return 1
		}
		output, queryErr := contextgraph.Query(context.Background(), snapshot, search, limit)
		if queryErr != nil {
			fmt.Fprintln(os.Stderr, "graph:", queryErr)
			return 1
		}
		fmt.Print(string(output))
		return 0
	default:
		return bad("usage: gov graph status|refresh [path] | gov graph query <search> [--path <path>] [--limit <n>]")
	}
}

func bad(s string) int { fmt.Fprintln(os.Stderr, s); return 2 }

// guardConfig is the Sol Critical 2 startup gate: load the configuration
// strictly and refuse to proceed when it is present-but-invalid (unreadable,
// malformed YAML, unknown field, invalid policy value). A missing file is NOT
// an error — built-in defaults apply. Returns 0 when the config is valid (or
// absent) and a non-zero exit code (with a specific message on stderr) when it
// is malformed, so Current() can never be reached with a bad file in the CLI
// path.
func guardConfig() int {
	if _, err := config.LoadStrict(); err != nil {
		fmt.Fprintln(os.Stderr, "governator: configuration is invalid — refusing to proceed:", err)
		fmt.Fprintln(os.Stderr, "fix the file or remove it to fall back to built-in defaults")
		return 2
	}
	return 0
}

// routeExplain implements `gov route --explain <contract.yaml>`: a dry run of
// the route broker against an agent: auto contract. It resolves and prints the
// full scored candidate table without launching anything and without writing a
// decision row to the ledger (print-only keeps the ledger clean of previews).
// The decision reflects current binary health via the default LookPath probe;
// breaker and quota are read from the live ledger-backed health source.
func routeExplain(path string) int {
	contract, err := contracts.ParseFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "route:", err)
		return 1
	}
	if contract.Agent != contracts.AgentAuto {
		fmt.Fprintln(os.Stderr, "route: --explain requires agent: auto; an explicit agent overrides the broker")
		return 1
	}
	db, err := observability.Open(govruntime.Home())
	if err != nil {
		fmt.Fprintln(os.Stderr, "route:", err)
		return 1
	}
	defer db.Close()
	decision, err := router.Router{Health: breaker.Store{DB: db}}.Resolve(db, router.RequestFromContract(*contract), config.Current())
	if err != nil {
		fmt.Fprintln(os.Stderr, "route:", err)
		return 1
	}
	if decision.Selected == "" {
		fmt.Fprintln(os.Stderr, router.ErrNoCandidate.Error())
		fmt.Print(decision.Format())
		return 1
	}
	fmt.Print(decision.Format())
	return 0
}

// healthCmd implements `gov health` — the infrastructure circuit-breaker view
// (plan Session 2). It prints one row per registered backend (state, failure
// kind, cooldown, consecutive failures) and, for doctor-gated kinds
// (AUTH_EXPIRED / BINARY_MISSING / FLAG_DRIFT), runs the backend's doctor probe
// and auto-closes any breaker whose underlying problem has resolved — so a
// re-installed binary or refreshed credential recovers without a manual reset.
// `gov health reset <backend>` forces a backend CLOSED with an audit row, the
// operator escape hatch for time-based kinds that should not wait out their
// cooldown.
func healthCmd(args []string) int {
	db, err := observability.Open(govruntime.Home())
	if err != nil {
		fmt.Fprintln(os.Stderr, "health:", err)
		return 1
	}
	defer db.Close()
	now := time.Now().UTC()
	if len(args) == 2 && args[0] == "reset" {
		if err := breaker.Reset(db, args[1], now, "manual reset via gov health"); err != nil {
			return bad("health: " + err.Error())
		}
		fmt.Printf("reset: %s breaker CLOSED\n", args[1])
		return 0
	}
	if len(args) != 0 {
		return bad("usage: gov health [reset <backend>]")
	}
	recovered := recoverDoctorGatedBreakers(db, now)
	rows, err := breaker.All(db, now)
	if err != nil {
		fmt.Fprintln(os.Stderr, "health:", err)
		return 1
	}
	fmt.Println("backend\tstate\tfailure_kind\tcooldown_until\tconsecutive\tupdated")
	for _, r := range rows {
		fmt.Printf("%s\t%s\t%s\t%s\t%d\t%s\n",
			r.Backend, r.EffectiveState, orHealthDash(r.FailureKind),
			orHealthDash(formatCooldown(r.CooldownUntil)), r.ConsecutiveFailures,
			orHealthDash(formatCooldown(r.UpdatedAt)))
	}
	for _, msg := range recovered {
		fmt.Println("recovered:", msg)
	}
	return 0
}

func versionCmd(args []string) int {
	if len(args) > 1 || (len(args) == 1 && args[0] != "--json") {
		return bad("usage: gov version [--json]")
	}
	if len(args) == 1 && args[0] == "--json" {
		payload := struct {
			Version                string `json:"version"`
			SourceCommit           string `json:"source_commit"`
			BuildTimestamp         string `json:"build_timestamp"`
			ClaimsHash             string `json:"claims_hash"`
			AdapterProtocolVersion string `json:"adapter_protocol_version"`
		}{
			Version:                version,
			SourceCommit:           sourceCommit,
			BuildTimestamp:         buildTimestamp,
			ClaimsHash:             claimsHash,
			AdapterProtocolVersion: adapterProtocolVersion,
		}
		if err := json.NewEncoder(os.Stdout).Encode(payload); err != nil {
			fmt.Fprintln(os.Stderr, "version:", err)
			return 1
		}
		return 0
	}
	fmt.Printf("gov %s\n", version)
	return 0
}

// claimsCmd handles `gov claims verify`: re-derives every docs/claims.yaml
// entry's maturity from the repository (internal/claims) instead of trusting
// a hand-written status field (plan v1.4 Session 6 / Sol Phase 11 — CI must
// fail when a claim is unwired, untested, stale, missing its acceptance
// artifact, or absent from the shipped binary).
func claimsCmd(args []string) int {
	usage := "usage: gov claims verify [--file <path>] [--repo <path>] [--artifact <path>] [--manifest <path>] [--release]"
	if len(args) < 1 || args[0] != "verify" {
		return bad(usage)
	}
	file := "docs/claims.yaml"
	repo := "."
	release := false
	opts := claims.VerifyOptions{}
	rest := args[1:]
	for len(rest) > 0 {
		switch rest[0] {
		case "--file":
			if len(rest) < 2 {
				return bad(usage)
			}
			file = rest[1]
			rest = rest[2:]
		case "--repo":
			if len(rest) < 2 {
				return bad(usage)
			}
			repo = rest[1]
			rest = rest[2:]
		case "--artifact":
			if len(rest) < 2 {
				return bad(usage)
			}
			opts.ArtifactPath = rest[1]
			rest = rest[2:]
		case "--manifest":
			if len(rest) < 2 {
				return bad(usage)
			}
			opts.ManifestPath = rest[1]
			rest = rest[2:]
		case "--release":
			release = true
			rest = rest[1:]
		default:
			return bad(usage)
		}
	}
	// P0-7 (Sol redteam v4 S8): a release pipeline invoking this in --release
	// mode is asserting "this is the full, exact-artifact claims check that
	// gates whether a release ships" -- the specific failure mode the report
	// found was that release.sh's own acceptance step called `claims verify`
	// WITHOUT --artifact/--manifest, so the binary-identity/commit-drift
	// checks in verifyArtifactManifest never actually ran against the shipped
	// artifact. --release refuses to silently degrade into the bare
	// source-only check that mode would otherwise produce. It does not
	// change the bare (no --release) invocation CI and local pre-commit runs
	// use every day to check claim-to-source consistency -- that check has
	// nothing to do with a built artifact and must keep working without one.
	if release && (opts.ArtifactPath == "" || opts.ManifestPath == "") {
		fmt.Fprintln(os.Stderr, "claims: --release requires both --artifact and --manifest")
		return bad(usage)
	}
	doc, err := claims.Load(file)
	if err != nil {
		fmt.Fprintln(os.Stderr, "claims:", err)
		return 1
	}
	results, err := claims.VerifyWithOptions(repo, doc, opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, "claims:", err)
		return 1
	}
	report, exit := claims.Report(results)
	fmt.Print(report)
	return exit
}

// recoverDoctorGatedBreakers runs the backend doctor probes and closes any
// breaker that is OPEN on a doctor-gated kind whose check now passes. It is
// best-effort: a doctor failure never blocks the health view, it just leaves
// the breaker OPEN (correctly — the problem has not resolved).
func recoverDoctorGatedBreakers(db *sql.DB, now time.Time) []string {
	checks := doctor.Run()
	healthy := backendDoctorStatus(checks)
	var recovered []string
	for _, backend := range []string{"claude-code", "codex", "glm", "opencode", "pi"} {
		rec := breaker.Snapshot(db, backend, now)
		if rec.PersistedState != breaker.Open {
			continue
		}
		if !doctorGatedKind(rec.FailureKind) {
			continue
		}
		if healthy[backend] {
			if err := breaker.Reset(db, backend, now, "doctor pass: backend:"+backend+" healthy"); err == nil {
				recovered = append(recovered, backend+" (was "+rec.FailureKind+", doctor now passes)")
			}
		}
	}
	return recovered
}

func backendDoctorStatus(checks []doctor.Check) map[string]bool {
	out := make(map[string]bool)
	for _, c := range checks {
		name := strings.TrimPrefix(c.Name, "backend:")
		if name == c.Name {
			continue
		}
		if name == "claude" {
			name = "claude-code"
		}
		out[name] = c.Status == doctor.StatusOK
	}
	return out
}

func doctorGatedKind(kind string) bool {
	switch kind {
	case observability.InfraAuthExpired, observability.InfraBinaryMissing, observability.InfraFlagDrift:
		return true
	}
	return false
}

func orHealthDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func formatCooldown(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// hookCmd implements `gov hook pre-tool-use` — the Phase 5 bridge that lets
// Governator replace harness_gate.py as the Claude Code PreToolUse hook. It
// reads the PreToolUse payload from stdin ({tool_name, tool_input, cwd}), runs
// the Go F1-F7 gate, and emits the Claude Code decision JSON. The --run flag is
// accepted for traceability (recorded in the ledger's hook audit log) but the
// gate decision derives only from the observed payload, never from the run id.
//
// F5 fail-closed: any stdin parse failure or gate error routes through the
// degraded denylist so the session never loses its irreversibility guards.
func protectCmd(args []string) int {
	if len(args) == 1 && args[0] == "status" {
		entries, err := protect.Status()
		if err != nil {
			return bad("protect: " + err.Error())
		}
		fmt.Printf("Protected-paths status (%s)\n", protectedpaths.Manifest())
		for _, entry := range entries {
			fmt.Printf("%-12s %s (%d files)\n", entry.State, entry.Path, entry.Files)
		}
		return 0
	}
	if len(args) == 1 && args[0] == "apply" {
		result, err := protect.Apply(true, nil)
		if err != nil {
			return bad("protect: " + err.Error())
		}
		fmt.Printf("Locked %d files across %d path(s).\n", result.Files, result.Roots)
		return 0
	}
	if len(args) == 2 && args[0] == "release" {
		result, err := protect.Apply(false, []string{args[1]})
		if err != nil {
			return bad("protect: " + err.Error())
		}
		fmt.Printf("Released %d files across %d path(s).\n", result.Files, result.Roots)
		return 0
	}
	return bad("usage: gov protect status|apply|release <path>")
}

func snapCmd(args []string) int {
	if len(args) >= 1 && args[0] == "create" && len(args) <= 2 {
		label := ""
		if len(args) == 2 {
			label = args[1]
		}
		manifest, err := snapshots.Create(label)
		if err != nil {
			return bad("snap: " + err.Error())
		}
		total := 0
		for _, root := range manifest.Roots {
			total += root.Files
		}
		fmt.Printf("Snapshot %s: %d files across %d root(s).\n", manifest.ID, total, len(manifest.Roots))
		return 0
	}
	if len(args) == 1 && args[0] == "list" {
		list, err := snapshots.List()
		if err != nil {
			return bad("snap: " + err.Error())
		}
		for _, manifest := range list {
			fmt.Printf("%s\t%s\t%d roots\n", manifest.ID, manifest.Label, len(manifest.Roots))
		}
		return 0
	}
	if len(args) == 2 && args[0] == "diff" {
		changes, err := snapshots.Diff(args[1])
		if err != nil {
			return bad("snap: " + err.Error())
		}
		for _, change := range changes {
			fmt.Printf("%s  %s\n", change.Kind, change.Path)
		}
		return 0
	}
	if len(args) >= 2 && args[0] == "restore" {
		mode := snapshots.RestoreOverlay
		dryRun := false
		yes := false
		for _, flag := range args[2:] {
			switch flag {
			case "--dry-run":
				dryRun = true
			case "--overlay":
				mode = snapshots.RestoreOverlay
			case "--exact":
				mode = snapshots.RestoreExact
			case "--yes":
				yes = true
			default:
				return bad("usage: gov snap restore <id> [--overlay|--exact] [--dry-run] [--yes]")
			}
		}
		unattended := yes || config.Current().Doctrine.ExactRestoreUnattended == "allow"
		result, err := snapshots.Restore(args[1], mode, dryRun, unattended)
		if errors.Is(err, snapshots.ErrExactRestoreConfirmationRequired) {
			fmt.Printf("Exact restore of %s would delete %d post-snapshot addition(s):\n", args[1], len(result.Deleted))
			for _, path := range result.Deleted {
				fmt.Printf("  - %s\n", path)
			}
			if len(result.Preserved) > 0 {
				fmt.Println("Protected paths kept despite --exact:")
				for _, path := range result.Preserved {
					fmt.Printf("  ! %s\n", path)
				}
			}
			fmt.Println("Re-run with --yes to confirm, or set doctrine.exact_restore_unattended: allow (or GOV_EXACT_RESTORE_UNATTENDED=allow) for unattended callers.")
			return 1
		}
		if err != nil {
			return bad("snap: " + err.Error())
		}
		verb := "Restored"
		if dryRun {
			verb = "DRY-RUN: would restore"
		}
		fmt.Printf("%s %d file(s).\n", verb, result.Restored)
		if mode == snapshots.RestoreExact {
			verb = "Deleted"
			if dryRun {
				verb = "DRY-RUN: would delete"
			}
			fmt.Printf("%s %d post-snapshot addition(s).\n", verb, len(result.Deleted))
			if len(result.Preserved) > 0 {
				fmt.Printf("Kept %d protected post-snapshot addition(s).\n", len(result.Preserved))
			}
		}
		return 0
	}
	if len(args) >= 1 && args[0] == "prune" {
		keep := 48
		if len(args) == 3 && args[1] == "--keep" {
			parsed, err := strconv.Atoi(args[2])
			if err != nil {
				return bad("usage: gov snap prune [--keep N]")
			}
			keep = parsed
		} else if len(args) != 1 {
			return bad("usage: gov snap prune [--keep N]")
		}
		removed, err := snapshots.Prune(keep)
		if err != nil {
			return bad("snap: " + err.Error())
		}
		fmt.Printf("Kept newest %d, pruned %d old snapshot(s).\n", keep, len(removed))
		return 0
	}
	return bad("usage: gov snap create [label]|list|diff <id>|restore <id> [--overlay|--exact] [--dry-run] [--yes]|prune [--keep N]")
}

func parityCmd(args []string) int {
	if len(args) != 1 || args[0] != "report" {
		return bad("usage: gov parity report")
	}
	report, err := observability.ParitySummary(govruntime.Home())
	if err != nil {
		return bad("parity: " + err.Error())
	}
	fmt.Printf("events=%d matches=%d mismatches=%d unavailable=%d coverage_days=%.2f\n", report.Total, report.Matches, report.Mismatches, report.Unavailable, report.CoverageDays)
	for _, event := range report.Events {
		fmt.Printf("%s\tmatch=%t\tpy_unavailable=%t\tgo=%q\tpython=%q\tpayload=%s\n", event.PayloadHash, event.Match, event.PythonUnavailable, event.GoDecision, event.PythonDecision, event.Payload)
	}
	return 0
}

// gateCmd implements `gov gate check`. Sol P1-11 / report §9 attack 15: a
// malformed/empty/oversized payload (`printf '{broken' | gov gate check`)
// used to hit an early `return 0` on either the stdin read or the
// json.Unmarshal/tool-name check — exit 0 with no output at all, which any
// integration reading "no denial" as approval treats as a silent ALLOW.
// "No decision" is reserved for *valid* input the gate simply has no
// applicable rule for; a payload that couldn't even be parsed must never
// reach that path. Fixed to fail closed via denyGateProtocolError, reusing
// the exact readHookPayload/hookProtocolError machinery `gov hook
// pre-tool-use` already uses correctly for the identical class of input.
func gateCmd(args []string) int {
	if len(args) != 1 || args[0] != "check" {
		return bad("usage: gov gate check")
	}
	data, protoErr := readHookPayload(os.Stdin, hookProtocolMaxBytes)
	if protoErr != nil {
		return denyGateProtocolError(protoErr)
	}
	var input govruntime.NeutralGateInput
	if json.Unmarshal(data, &input) != nil || strings.TrimSpace(input.Tool) == "" {
		return denyGateProtocolError(&hookProtocolError{"HOOK_PROTOCOL_ERROR", "malformed or incomplete gate check input"})
	}
	decision := govruntime.NeutralGateDecide(input)
	output := struct {
		Allow   bool   `json:"allow"`
		Reason  string `json:"reason"`
		Finding string `json:"finding"`
	}{decision.Allow, decision.Reason, decision.Finding}
	_ = json.NewEncoder(os.Stdout).Encode(output)
	return 0
}

// denyGateProtocolError is P1-11's fail-closed path for `gov gate check`
// (report §9 attack 15). Unlike `gov hook pre-tool-use` (which must always
// exit 0 to satisfy Claude Code's documented hook contract, carrying its
// denial only in stdout JSON), `gate check` has no such external exit-code
// constraint, so a malformed payload gets the plainer contract the plan
// calls for: a structured DENY on stdout (in the same {allow,reason,finding}
// shape a normal decision uses, so callers don't need a second parser), an
// explicit PROTOCOL_ERROR-class finding, a nonzero exit code the caller can
// act on directly without parsing stdout at all, and a durable emergency
// audit record via the same hook_events/emergency-journal fallback `gov hook
// pre-tool-use` already uses when the ledger itself is unavailable.
func denyGateProtocolError(pe *hookProtocolError) int {
	output := struct {
		Allow   bool   `json:"allow"`
		Reason  string `json:"reason"`
		Finding string `json:"finding"`
	}{false, "DENY: " + pe.Error(), pe.Code}
	_ = json.NewEncoder(os.Stdout).Encode(output)
	recordHookDecision("", govruntime.GateInput{ToolName: "<unparseable>"}, govruntime.GateDecision{Allow: false, Finding: pe.Code, Reason: pe.Error()})
	return 2
}

func hookCmd(args []string) int {
	if len(args) < 1 || args[0] != "pre-tool-use" {
		return bad("usage: gov hook pre-tool-use [--run <id>] [--shadow <python-gate>]")
	}
	var runID, shadow string
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--run":
			if i+1 >= len(args) {
				return bad("--run requires an id")
			}
			runID = args[i+1]
			i++
		case "--shadow":
			if i+1 >= len(args) {
				return bad("--shadow requires a path")
			}
			shadow = args[i+1]
			i++
		default:
			return bad("usage: gov hook pre-tool-use [--run <id>] [--shadow <python-gate>]")
		}
	}
	data, protoErr := readHookPayload(os.Stdin, hookProtocolMaxBytes)
	if protoErr != nil {
		return denyHookProtocolError(runID, protoErr)
	}
	in, protoErr := decodeHookInput(data)
	if protoErr != nil {
		return denyHookProtocolError(runID, protoErr)
	}
	if in.ToolInput == nil {
		in.ToolInput = map[string]any{}
	}
	decision := govruntime.GateDecide(in)
	if runID != "" {
		recordHookDecision(runID, in, decision)
	}
	if decision.Allow && in.ToolName == "Bash" {
		if cmd, ok := in.ToolInput["command"].(string); ok {
			govruntime.PreflightSnapshotIfDelete(cmd)
		}
	}
	if shadow == "" {
		return govruntime.EmitHookJSON(decision)
	}

	goOutput := govruntime.HookPayload(decision)
	// 35s comfortably exceeds harness_gate.py's own 30s pre-delete snapshot
	// ceiling (_preflight_snapshot) plus interpreter startup: a real local
	// delete on a slow drvfs mount measured at ~13s in practice, and 2s was
	// marking those legitimate runs py_unavailable instead of letting the
	// authoritative legacy decision land (governator ledger, 2026-07-06).
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "python3", shadow)
	cmd.Stdin = bytes.NewReader(data)
	var pythonOutput bytes.Buffer
	cmd.Stdout = &pythonOutput
	err := cmd.Run()
	event := observability.ParityEvent{Payload: string(data), GoDecision: string(goOutput), PythonDecision: pythonOutput.String()}
	if err != nil {
		event.PythonUnavailable = true
		event.Match = false
		_ = observability.RecordParity(govruntime.Home(), event)
		return govruntime.EmitHookJSON(decision)
	}
	event.Match = shadowVerdict(goOutput) == shadowVerdict(pythonOutput.Bytes())
	_ = observability.RecordParity(govruntime.Home(), event)
	_, _ = os.Stdout.Write(pythonOutput.Bytes())
	return 0
}

// shadowVerdict reduces a gate's raw hook output to the decision it carries so
// parity compares WHAT was decided, not how the reason is worded — the two
// planes phrase deny reasons differently by design ("GOVERNATOR GATE" vs
// "HARNESS AUTHORITY"), and byte-level comparison counted every deny as a
// mismatch, making the zero-mismatch cutover criterion unreachable. Empty
// output is the allow convention on both planes; unparseable non-empty output
// is returned verbatim so genuinely alien output still registers as a mismatch.
func shadowVerdict(out []byte) string {
	trimmed := bytes.TrimSpace(out)
	if len(trimmed) == 0 {
		return "allow"
	}
	var parsed struct {
		HookSpecificOutput struct {
			PermissionDecision string `json:"permissionDecision"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(trimmed, &parsed); err == nil && parsed.HookSpecificOutput.PermissionDecision != "" {
		return parsed.HookSpecificOutput.PermissionDecision
	}
	return string(trimmed)
}

// hookProtocolMaxBytes bounds the PreToolUse hook stdin payload (audit #7 /
// P0.7): oversized input is rejected before it is fully buffered. Real
// tool_input is small (paths, commands, at most a sizeable Edit/Write diff);
// this leaves generous headroom while still being a bound.
const hookProtocolMaxBytes = 8 << 20 // 8 MiB

// hookProtocolSupportedEvent is the only Claude Code hook_event_name this
// binary evaluates PreToolUse rules for — settings.json wires `gov hook
// pre-tool-use` only to the PreToolUse event. A payload that explicitly
// names a different event means this binary was invoked for the wrong hook;
// fail closed instead of silently applying PreToolUse semantics to it.
const hookProtocolSupportedEvent = "PreToolUse"

// hookProtocolError distinguishes a malformed/truncated/oversized/version-
// mismatched hook payload (audit #7) from a normal policy deny. Code is one
// of the two reason codes governator-sol-upgrade3.md names.
type hookProtocolError struct {
	Code   string // HOOK_PROTOCOL_ERROR | HOOK_VERSION_MISMATCH
	Reason string
}

func (e *hookProtocolError) Error() string { return e.Code + ": " + e.Reason }

// readHookPayload reads stdin bounded to maxBytes+1 so an oversized payload
// is detected without buffering an unbounded amount of input first, and
// distinguishes an empty payload from a read failure — both are protocol
// errors, not a basis for evaluating any decision.
func readHookPayload(r io.Reader, maxBytes int64) ([]byte, *hookProtocolError) {
	data, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return nil, &hookProtocolError{"HOOK_PROTOCOL_ERROR", "stdin read failed: " + err.Error()}
	}
	if len(data) == 0 {
		return nil, &hookProtocolError{"HOOK_PROTOCOL_ERROR", "empty hook payload"}
	}
	if int64(len(data)) > maxBytes {
		return nil, &hookProtocolError{"HOOK_PROTOCOL_ERROR", fmt.Sprintf("payload exceeds %d byte limit", maxBytes)}
	}
	return data, nil
}

// decodeHookInput applies strict schema decoding to an already size-bounded
// payload: well-formed JSON, no trailing content after the first JSON value
// (rejects truncated-then-resumed or accidentally concatenated payloads —
// the `{broken` reproduction plus its siblings), a non-empty tool_name, and
// — when the caller supplies it — a hook_event_name matching this binary's
// only supported event.
//
// This deliberately does NOT use json.Decoder's DisallowUnknownFields:
// Claude Code's real PreToolUse payload carries several common fields this
// gate doesn't act on (session_id, transcript_path, permission_mode,
// tool_use_id, ...), and rejecting those would make every future Claude
// Code release a fail-closed incident instead of a no-op for this gate.
// "Strict" here means structurally strict (shape, trailing bytes, required
// fields), not closed to additive fields.
func decodeHookInput(data []byte) (govruntime.GateInput, *hookProtocolError) {
	dec := json.NewDecoder(bytes.NewReader(data))
	var in govruntime.GateInput
	if err := dec.Decode(&in); err != nil {
		return govruntime.GateInput{}, &hookProtocolError{"HOOK_PROTOCOL_ERROR", "malformed JSON: " + err.Error()}
	}
	if err := dec.Decode(new(json.RawMessage)); err != io.EOF {
		return govruntime.GateInput{}, &hookProtocolError{"HOOK_PROTOCOL_ERROR", "trailing content after hook payload"}
	}
	if strings.TrimSpace(in.ToolName) == "" {
		return govruntime.GateInput{}, &hookProtocolError{"HOOK_PROTOCOL_ERROR", "missing tool_name"}
	}
	if in.HookEventName != "" && in.HookEventName != hookProtocolSupportedEvent {
		return govruntime.GateInput{}, &hookProtocolError{"HOOK_VERSION_MISMATCH",
			fmt.Sprintf("unsupported hook_event_name %q, expected %q", in.HookEventName, hookProtocolSupportedEvent)}
	}
	return in, nil
}

// denyHookProtocolError is the P0.7 fail-closed path for a hook payload that
// could not be trusted enough to evaluate. Claude Code's PreToolUse hook
// honors a block via exit 0 + stdout `hookSpecificOutput.permissionDecision:
// "deny"` (stdout JSON is parsed only on exit 0; any nonzero exit other than
// 2 is a NON-blocking hook error under Claude Code's documented contract,
// meaning the tool call would proceed despite the nonzero exit — and exit 2
// discards stdout JSON entirely, so it can't carry the structured
// HOOK_PROTOCOL_ERROR/HOOK_VERSION_MISMATCH reason). This reuses the exact
// exit-0-plus-JSON mechanism every other gate denial (F1-F7) already uses in
// production, rather than a second, unproven denial channel.
func denyHookProtocolError(runID string, pe *hookProtocolError) int {
	// Reason carries "CODE: detail" (pe.Error()) rather than the bare detail
	// so the code survives into hookJSON's permissionDecisionReason on
	// stdout — Finding itself is DB/journal-only, never serialized to the
	// hook's stdout contract.
	decision := govruntime.GateDecision{Allow: false, Finding: pe.Code, Reason: pe.Error()}
	recordHookDecision(runID, govruntime.GateInput{ToolName: "<unparseable>"}, decision)
	return govruntime.EmitHookJSON(decision)
}

// recordHookDecision appends a row to the hook_events audit log — a table of
// its own, separate from `violations` (which feeds Phase-4 repair packets and
// ClassifyFailure; audit rows there would displace/corrupt real violation
// data). Records the decision (allow/deny), not just the input, so the
// interactive plane's audit trail actually reflects what the gate decided
// (the F6 unification goal). A ledger write failure must NEVER block an
// already-computed decision, but per audit "Policy hook emergency journal"
// the decision itself must never be silently lost either: when the ledger
// is unavailable or the write fails, it falls back to the append-only
// emergency journal instead of swallowing the error.
func recordHookDecision(runID string, in govruntime.GateInput, d govruntime.GateDecision) {
	home := govruntime.Home()
	if !tryRecordHookDecision(home, runID, in, d) {
		writeEmergencyHookJournal(home, runID, in, d)
	}
}

func tryRecordHookDecision(home, runID string, in govruntime.GateInput, d govruntime.GateDecision) bool {
	db, err := observability.Open(home)
	if err != nil {
		return false
	}
	defer db.Close()
	decision := "allow"
	if !d.Allow {
		decision = "deny"
	}
	payload, _ := json.Marshal(in.ToolInput)
	cmd, _ := in.ToolInput["command"].(string)
	detail := in.ToolName + " " + cmd + " " + string(payload)
	sourcesJSON, _ := json.Marshal(d.Sources)
	_, err = db.Exec(`INSERT INTO hook_events(run_id, tool, decision, finding, detail, sources, policy_hash, created) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		runID, in.ToolName, decision, d.Finding, detail, string(sourcesJSON), d.PolicyHash, time.Now().UTC().Format(time.RFC3339))
	return err == nil
}

// hookEmergencyJournalFile is the audit's "Policy hook emergency journal":
// an append-only, restrictively-permissioned filesystem record that survives
// even when the SQLite ledger itself is what's broken. One JSON line per
// decision; the file is only ever appended to, never truncated or rewritten.
const hookEmergencyJournalFile = "hook_emergency_journal.jsonl"

func writeEmergencyHookJournal(home, runID string, in govruntime.GateInput, d govruntime.GateDecision) {
	if home == "" {
		return
	}
	if err := os.MkdirAll(home, 0o700); err != nil {
		return
	}
	f, err := os.OpenFile(filepath.Join(home, hookEmergencyJournalFile), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	decision := "allow"
	if !d.Allow {
		decision = "deny"
	}
	line, err := json.Marshal(struct {
		Time     string `json:"time"`
		RunID    string `json:"run_id,omitempty"`
		Tool     string `json:"tool"`
		Decision string `json:"decision"`
		Finding  string `json:"finding,omitempty"`
		Reason   string `json:"reason,omitempty"`
	}{
		Time:     time.Now().UTC().Format(time.RFC3339Nano),
		RunID:    runID,
		Tool:     in.ToolName,
		Decision: decision,
		Finding:  d.Finding,
		Reason:   d.Reason,
	})
	if err != nil {
		return
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		return
	}
	_ = f.Sync()
}

func contractError(path string, err error) int {
	fmt.Fprintf(os.Stderr, "INVALID %s\n", path)
	var es contracts.ValidationErrors
	if errors.As(err, &es) {
		for _, e := range es.Sorted() {
			fmt.Fprintf(os.Stderr, "  - %s\n", e.Error())
		}
	} else {
		fmt.Fprintf(os.Stderr, "  - %v\n", err)
	}
	return 1
}
func usage() {
	fmt.Println(`Governator - contract-first runtime for replaceable coding agents

Usage:
  gov init
  gov validate <job.yaml>
  gov preflight <job.yaml>
  gov run <job.yaml> [--agent <name>]
  gov run inspect <run_id>
  gov run resume <run_id>
  gov run abandon <run_id>
  gov run recover --stale
  gov batch run <job.yaml|dir|glob>... [--parallel N] [--halt-on-first-quarantine] [--ordered]
  gov plan <intent.md> --out <dir> --envelope <pattern>... --max-total-tokens <n> [--backend <name>]
  gov plan --panel <n> <intent.md> --out <dir> --envelope <pattern>... --max-total-tokens <n> [--backend <name>]
  gov plan --show <dir>
  gov handoff [last|run_id]
  gov diff [last|run_id]
  gov rollback <run_id>
  gov quarantine list|show <id>|diff <id>
  gov score agents --job-type <type>
  gov failures
  gov cost --per-valid-output
  gov spend [--halt|--resume]
  gov quota
  gov usage summary|<run_id>
  gov analytics summary
  gov analytics export [--out <path>]
  gov route --job-type <type>
  gov route --explain <contract.yaml>
  gov repair-packet <run_id>
  gov eval harness <case-dir>
  gov eval scorecard
  gov protect status|apply|release <path>
  gov snap create [label]|list|diff <id>|restore <id> [--overlay|--exact] [--dry-run] [--yes]
  gov graph status|refresh [path]
  gov graph query <search> [--path <path>] [--limit <n>]
  gov hook pre-tool-use [--run <id>] [--shadow <python-gate>]
  gov panel compare --out <artifact.json> <input.json>...
  gov gate check
  gov parity report
  gov reconcile
  gov cleanup --stale [--max-attempts N]
  gov ask list
  gov ask show <id>
  gov ask approve <id> [--rule] [--ttl <duration>] [--by <name>] [--note <text>]
  gov ask deny <id> [--rule] [--ttl <duration>] [--by <name>] [--note <text>]
  gov containment message <job.yaml> [--reason <text>]
  gov attest <backend>
  gov doctor
  gov health [reset <backend>]
  gov claims verify [--file <path>] [--repo <path>] [--artifact <path>] [--manifest <path>] [--release]
  gov version`)
}
