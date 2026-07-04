package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/cousingary/governator/internal/contracts"
	"github.com/cousingary/governator/internal/doctor"
	"github.com/cousingary/governator/internal/observability"
	"github.com/cousingary/governator/internal/policy"
	govruntime "github.com/cousingary/governator/internal/runtime"
)

const version = "0.6.0-phase5"

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) == 0 {
		usage()
		return 2
	}
	switch args[0] {
	case "validate":
		if len(args) != 2 {
			return bad("usage: gov validate <job.yaml>")
		}
		c, err := contracts.ParseFile(args[1])
		if err != nil {
			return contractError(args[1], err)
		}
		fmt.Printf("VALID %s (job_id=%s mode=%s agent=%s)\n", args[1], c.JobID, c.Mode, c.Agent)
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
		}
		rec, err := govruntime.New().Run(context.Background(), *c)
		if err != nil {
			fmt.Fprintln(os.Stderr, "run:", err)
			return 1
		}
		fmt.Println(govruntime.MarshalRecord(rec))
		if rec.Status != "APPROVED" {
			return 1
		}
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
		fmt.Println("run_id\tagent\tjob_type\ttaxonomy\tmessage")
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
	case "route":
		if len(args) != 3 || args[1] != "--job-type" {
			return bad("usage: gov route --job-type <type>")
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
	case "hook":
		return hookCmd(args[1:])
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
	case "version", "--version", "-version":
		fmt.Printf("gov %s\n", version)
		return 0
	case "help", "--help", "-h":
		usage()
		return 0
	default:
		return bad(fmt.Sprintf("unknown command %q", args[0]))
	}
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
func bad(s string) int { fmt.Fprintln(os.Stderr, s); return 2 }

// hookCmd implements `gov hook pre-tool-use` — the Phase 5 bridge that lets
// Governator replace harness_gate.py as the Claude Code PreToolUse hook. It
// reads the PreToolUse payload from stdin ({tool_name, tool_input, cwd}), runs
// the Go F1-F7 gate, and emits the Claude Code decision JSON. The --run flag is
// accepted for traceability (recorded in the ledger's hook audit log) but the
// gate decision derives only from the observed payload, never from the run id.
//
// F5 fail-closed: any stdin parse failure or gate error routes through the
// degraded denylist so the session never loses its irreversibility guards.
func hookCmd(args []string) int {
	if len(args) < 1 {
		return bad("usage: gov hook pre-tool-use [--run <id>]")
	}
	sub := args[0]
	if sub != "pre-tool-use" {
		return bad("usage: gov hook pre-tool-use [--run <id>]")
	}
	var runID string
	for i := 1; i < len(args); i++ {
		if args[i] == "--run" && i+1 < len(args) {
			runID = args[i+1]
			i++
		}
	}
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return emitDegraded("stdin read failed: " + err.Error())
	}
	var in govruntime.GateInput
	if err := json.Unmarshal(data, &in); err != nil {
		// Unparseable payload — no tool/command to evaluate (matches Python).
		return emitAllow()
	}
	if in.ToolInput == nil {
		in.ToolInput = map[string]any{}
	}
	decision := govruntime.GateDecide(in)
	if runID != "" {
		// Traceability hook: audit the decision (not just the input) so the
		// interactive plane shares the scripted plane's audit trail (F6).
		recordHookDecision(runID, in, decision)
	}
	if decision.Allow && in.ToolName == "Bash" {
		if cmd, ok := in.ToolInput["command"].(string); ok {
			govruntime.PreflightSnapshotIfDelete(cmd)
		}
	}
	return govruntime.EmitHookJSON(decision)
}

func emitAllow() int {
	// Unparseable payload — no tool/command to evaluate. An allow decision
	// never writes stdout JSON (see EmitHookJSON), so this is silent success.
	return 0
}

func emitDegraded(why string) int {
	return govruntime.EmitHookJSON(govruntime.GateDecision{
		Allow: false, Degraded: true, Finding: "F5",
		Reason: "gate unavailable (" + why + "); degraded safety net active",
	})
}

// recordHookDecision appends a row to the hook_events audit log — a table of
// its own, separate from `violations` (which feeds Phase-4 repair packets and
// ClassifyFailure; audit rows there would displace/corrupt real violation
// data). Records the decision (allow/deny), not just the input, so the
// interactive plane's audit trail actually reflects what the gate decided
// (the F6 unification goal). Best-effort: a ledger write failure must NEVER
// block an already-computed decision, so errors are swallowed.
func recordHookDecision(runID string, in govruntime.GateInput, d govruntime.GateDecision) {
	home := govruntime.Home()
	db, err := observability.Open(home)
	if err != nil {
		return
	}
	defer db.Close()
	decision := "allow"
	if !d.Allow {
		decision = "deny"
	}
	payload, _ := json.Marshal(in.ToolInput)
	cmd, _ := in.ToolInput["command"].(string)
	detail := in.ToolName + " " + cmd + " " + string(payload)
	_, _ = db.Exec(`INSERT INTO hook_events(run_id, tool, decision, finding, detail, created) VALUES (?, ?, ?, ?, ?, ?)`,
		runID, in.ToolName, decision, d.Finding, detail, time.Now().UTC().Format(time.RFC3339))
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
  gov validate <job.yaml>
  gov preflight <job.yaml>
  gov run <job.yaml> [--agent <name>]
  gov diff [last|run_id]
  gov rollback <run_id>
  gov quarantine list|show <id>|diff <id>
  gov score agents --job-type <type>
  gov failures
  gov cost --per-valid-output
  gov route --job-type <type>
  gov repair-packet <run_id>
  gov eval harness <case-dir>
  gov eval scorecard
  gov hook pre-tool-use [--run <id>]
  gov doctor
  gov version`)
}
