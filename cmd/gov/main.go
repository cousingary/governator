package main

import (
	"bytes"
	"context"
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

	"github.com/cousingary/governator/internal/config"
	"github.com/cousingary/governator/internal/contextgraph"
	"github.com/cousingary/governator/internal/contracts"
	"github.com/cousingary/governator/internal/doctor"
	"github.com/cousingary/governator/internal/observability"
	"github.com/cousingary/governator/internal/policy"
	"github.com/cousingary/governator/internal/protect"
	"github.com/cousingary/governator/internal/protectedpaths"
	govruntime "github.com/cousingary/governator/internal/runtime"
	"github.com/cousingary/governator/internal/snapshots"
)

var version = "1.0.0-rc1"

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) == 0 {
		usage()
		return 2
	}
	switch args[0] {
	case "init":
		return initCmd(args[1:])
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
		dryRun := len(args) == 3 && args[2] == "--dry-run"
		if len(args) > 3 || (len(args) == 3 && !dryRun) {
			return bad("usage: gov snap restore <id> [--dry-run]")
		}
		count, err := snapshots.Restore(args[1], dryRun)
		if err != nil {
			return bad("snap: " + err.Error())
		}
		if dryRun {
			fmt.Printf("DRY-RUN: would restore %d file(s); nothing written.\n", count)
		} else {
			fmt.Printf("Restored %d file(s).\n", count)
		}
		return 0
	}
	return bad("usage: gov snap create [label]|list|diff <id>|restore <id> [--dry-run]")
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

func gateCmd(args []string) int {
	if len(args) != 1 || args[0] != "check" {
		return bad("usage: gov gate check")
	}
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return 0
	}
	var input govruntime.NeutralGateInput
	if json.Unmarshal(data, &input) != nil || strings.TrimSpace(input.Tool) == "" {
		return 0
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
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return emitDegraded("stdin read failed: " + err.Error())
	}
	var in govruntime.GateInput
	if err := json.Unmarshal(data, &in); err != nil {
		return emitAllow()
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
	err = cmd.Run()
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
  gov init
  gov validate <job.yaml>
  gov preflight <job.yaml>
  gov run <job.yaml> [--agent <name>]
  gov handoff [last|run_id]
  gov diff [last|run_id]
  gov rollback <run_id>
  gov quarantine list|show <id>|diff <id>
  gov score agents --job-type <type>
  gov failures
  gov cost --per-valid-output
  gov usage summary|<run_id>
  gov route --job-type <type>
  gov repair-packet <run_id>
  gov eval harness <case-dir>
  gov eval scorecard
  gov protect status|apply|release <path>
  gov snap create [label]|list|diff <id>|restore <id> [--dry-run]
  gov graph status|refresh [path]
  gov graph query <search> [--path <path>] [--limit <n>]
  gov hook pre-tool-use [--run <id>] [--shadow <python-gate>]
  gov gate check
  gov parity report
  gov doctor
  gov version`)
}
