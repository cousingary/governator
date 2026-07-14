package contracts

import (
	"fmt"
	"math"
	"strings"
	"testing"
)

const validContract = `job_id: clipart-regen-2026-07-03
job_type: batch_image
agent: claude
mode: batch_worker
workspace:
  root: /workspace/design-repository
  worktree: auto
allowed:
  read: ["designs/**", "mockups/**"]
  write: ["output/clipart/**"]
  execute: ["python3 remove_blue_fringe.py *", "python3 -c *"]
forbidden:
  paths: ["done/**", "*.psd"]
  commands: ["rm -rf", "git push"]
  behaviors: [refactor, reformat, rename_files, scope_expansion]
budget: {max_minutes: 20, max_commands: 60, max_files_changed: 30, max_lines_changed: 5000, max_new_files: 30, max_deleted: 0}
preflight:
  intended_writes: ["output/clipart/**"]
  scout_completed: true
success:
  required_files: ["output/clipart/*.png"]
  validators:
    - "python3 validators/image/check_transparency.py output/clipart"
    - "python3 validators/image/check_min_resolution.py --min 2000 output/clipart"
on_violation: quarantine
`

func TestParseValidContract(t *testing.T) {
	contract, err := Parse([]byte(validContract))
	if err != nil {
		t.Fatalf("Parse(valid) error = %v", err)
	}
	if contract.JobID != "clipart-regen-2026-07-03" || contract.Mode != ModeBatchWorker {
		t.Fatalf("unexpected contract: %#v", contract)
	}
}

func TestRejectsMalformedContractsWithFieldErrors(t *testing.T) {
	tests := []struct {
		name  string
		yaml  string
		field string
	}{
		{"missing job id", strings.Replace(validContract, "job_id: clipart-regen-2026-07-03\n", "", 1), "job_id"},
		{"invalid mode", strings.Replace(validContract, "mode: batch_worker", "mode: improviser", 1), "mode"},
		{"relative workspace", strings.Replace(validContract, "root: /workspace/design-repository", "root: relative/project", 1), "workspace.root"},
		{"unsupported direct-root worktree", strings.Replace(validContract, "worktree: auto", "worktree: none", 1), "workspace.worktree"},
		{"path escape", strings.Replace(validContract, "output/clipart/**", "../outside/**", 1), "allowed.write[0]"},
		{"zero budget", strings.Replace(validContract, "max_minutes: 20", "max_minutes: 0", 1), "budget.max_minutes"},
		// Sol P1-16 / report §9 attack 21: math.MaxInt32 minutes already
		// overflows time.Duration(minutes)*time.Minute (int64 nanoseconds) --
		// Validate must reject it outright rather than let it reach that
		// conversion. See internal/runtime's SafeMinutesDuration usage and
		// TestValidateRejectsBudgetMaxMinutesLargeEnoughToOverflowDuration
		// below for the direct Validate()/SafeMinutesDuration-level proof.
		{"huge budget minutes overflow", strings.Replace(validContract, "max_minutes: 20", fmt.Sprintf("max_minutes: %d", math.MaxInt32), 1), "budget.max_minutes"},
		{"unsupported halt action", strings.Replace(validContract, "on_violation: quarantine", "on_violation: halt", 1), "on_violation"},
		{"unsupported rollback action", strings.Replace(validContract, "on_violation: quarantine", "on_violation: rollback", 1), "on_violation"},
		{"invalid violation action", strings.Replace(validContract, "on_violation: quarantine", "on_violation: ignore", 1), "on_violation"},
		{"unknown field", validContract + "surprise: true\n", "field surprise"},
		{"literal secret", strings.Replace(validContract, "git push", "Bearer abcdefghijklmnop", 1), "literal bearer token"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Parse([]byte(test.yaml))
			if err == nil {
				t.Fatal("Parse(malformed) unexpectedly succeeded")
			}
			if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(test.field)) {
				t.Fatalf("error %q does not identify %q", err, test.field)
			}
		})
	}
}

func TestReadOnlyModeRejectsWrites(t *testing.T) {
	input := strings.Replace(validContract, "mode: batch_worker", "mode: verifier", 1)
	_, err := Parse([]byte(input))
	if err == nil || !strings.Contains(err.Error(), "allowed.write") {
		t.Fatalf("expected allowed.write error, got %v", err)
	}
}

func TestRejectsMultipleDocuments(t *testing.T) {
	_, err := Parse([]byte(validContract + "---\n" + validContract))
	if err == nil || !strings.Contains(err.Error(), "multiple YAML documents") {
		t.Fatalf("expected multiple-document error, got %v", err)
	}
}

func FuzzContractParser(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte(validContract),
		{},
		[]byte("job_id: fuzz\n"),
		[]byte("---\n{}\n---\n{}\n"),
		[]byte("job_id: fuzz\nsurprise: true\n"),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64*1024 {
			t.Skip()
		}
		_, _ = Parse(data)
	})
}

func TestParseWithoutRepairBlockLeavesRepairNil(t *testing.T) {
	contract, err := Parse([]byte(validContract))
	if err != nil {
		t.Fatal(err)
	}
	if contract.Repair != nil {
		t.Fatalf("expected nil Repair for a contract with no repair block, got %+v", contract.Repair)
	}
}

func TestParseRepairBlock(t *testing.T) {
	withRepair := strings.Replace(validContract, "on_violation: quarantine", "repair: {auto: true, max_attempts: 2, backend: codex}\non_violation: quarantine", 1)
	contract, err := Parse([]byte(withRepair))
	if err != nil {
		t.Fatal(err)
	}
	if contract.Repair == nil || !contract.Repair.Auto || contract.Repair.MaxAttempts != 2 || contract.Repair.Backend != "codex" {
		t.Fatalf("repair=%+v", contract.Repair)
	}
}

func TestParseRepairNegativeMaxAttemptsRejected(t *testing.T) {
	withRepair := strings.Replace(validContract, "on_violation: quarantine", "repair: {auto: true, max_attempts: -1}\non_violation: quarantine", 1)
	_, err := Parse([]byte(withRepair))
	if err == nil || !strings.Contains(err.Error(), "repair.max_attempts") {
		t.Fatalf("expected repair.max_attempts error, got %v", err)
	}
}

func TestParseOutputPolicy(t *testing.T) {
	withOutput := strings.Replace(validContract, "on_violation: quarantine", "output: {style: terse, max_final_words: 80}\non_violation: quarantine", 1)
	contract, err := Parse([]byte(withOutput))
	if err != nil {
		t.Fatal(err)
	}
	if contract.Output == nil || contract.Output.Style != "terse" || contract.Output.EffectiveMaxFinalWords() != 80 {
		t.Fatalf("output=%+v", contract.Output)
	}
	invalid := strings.Replace(withOutput, "max_final_words: 80", "max_final_words: 10", 1)
	if _, err := Parse([]byte(invalid)); err == nil || !strings.Contains(err.Error(), "output.max_final_words") {
		t.Fatalf("error=%v", err)
	}
}

func TestParseWithoutCleanupBlockLeavesCleanupNil(t *testing.T) {
	contract, err := Parse([]byte(validContract))
	if err != nil {
		t.Fatal(err)
	}
	if contract.Cleanup != nil {
		t.Fatalf("expected nil Cleanup for a contract with no cleanup block, got %+v", contract.Cleanup)
	}
}

func TestParseCleanupBlock(t *testing.T) {
	withCleanup := strings.Replace(validContract, "on_violation: quarantine", "cleanup: {required: true, validators: [\"gofmt -l .\"]}\non_violation: quarantine", 1)
	contract, err := Parse([]byte(withCleanup))
	if err != nil {
		t.Fatal(err)
	}
	if contract.Cleanup == nil || !contract.Cleanup.Required || len(contract.Cleanup.Validators) != 1 || contract.Cleanup.Validators[0] != "gofmt -l ." {
		t.Fatalf("cleanup=%+v", contract.Cleanup)
	}
}

func TestParseCleanupBlockWithoutValidatorsRejected(t *testing.T) {
	withCleanup := strings.Replace(validContract, "on_violation: quarantine", "cleanup: {required: true, validators: []}\non_violation: quarantine", 1)
	_, err := Parse([]byte(withCleanup))
	if err == nil || !strings.Contains(err.Error(), "cleanup.validators") {
		t.Fatalf("expected cleanup.validators error, got %v", err)
	}
}

// autoContract is validContract with agent: auto — the base for every routing
// block test. The routing block only pairs with auto.
var autoContract = strings.Replace(validContract, "agent: claude", "agent: auto", 1)

func TestParseAgentAutoAcceptedWithoutRouting(t *testing.T) {
	contract, err := Parse([]byte(autoContract))
	if err != nil {
		t.Fatalf("agent: auto must validate without a routing block: %v", err)
	}
	if contract.Agent != AgentAuto {
		t.Fatalf("expected agent: auto, got %q", contract.Agent)
	}
}

func TestParseRoutingBlock(t *testing.T) {
	withRouting := strings.Replace(autoContract, "on_violation: quarantine",
		"routing:\n  objective: cheapest\n  candidates: [claude-code, codex, glm]\n  max_attempts: 2\n  fallback: infrastructure_only\n  requirements: {native_sandbox: true}\non_violation: quarantine", 1)
	contract, err := Parse([]byte(withRouting))
	if err != nil {
		t.Fatalf("routing block must validate with agent: auto: %v", err)
	}
	if contract.Routing == nil || contract.Routing.Objective != "cheapest" ||
		len(contract.Routing.Candidates) != 3 || contract.Routing.MaxAttempts != 2 ||
		contract.Routing.Fallback != "infrastructure_only" ||
		!contract.Routing.Requirements.NativeSandbox {
		t.Fatalf("routing not parsed: %+v", contract.Routing)
	}
}

func TestParseRoutingRequirementsExpandedFields(t *testing.T) {
	withRouting := strings.Replace(autoContract, "on_violation: quarantine",
		"routing:\n  requirements: {read_only_mode: true, vision: true, tool_calling: true, local_only: true, min_context_tokens: 100000, min_output_tokens: 8192}\non_violation: quarantine", 1)
	contract, err := Parse([]byte(withRouting))
	if err != nil {
		t.Fatalf("expanded requirements must validate: %v", err)
	}
	r := contract.Routing.Requirements
	if !r.ReadOnlyMode || !r.Vision || !r.ToolCalling || !r.LocalOnly || r.MinContextTokens != 100000 || r.MinOutputTokens != 8192 {
		t.Fatalf("requirements not parsed: %+v", r)
	}
}

func TestRoutingMinContextTokensNegativeRejected(t *testing.T) {
	withRouting := strings.Replace(autoContract, "on_violation: quarantine",
		"routing: {requirements: {min_context_tokens: -1}}\non_violation: quarantine", 1)
	_, err := Parse([]byte(withRouting))
	if err == nil || !strings.Contains(err.Error(), "routing.requirements.min_context_tokens") {
		t.Fatalf("expected routing.requirements.min_context_tokens error, got %v", err)
	}
}

func TestRoutingMinOutputTokensNegativeRejected(t *testing.T) {
	withRouting := strings.Replace(autoContract, "on_violation: quarantine",
		"routing: {requirements: {min_output_tokens: -1}}\non_violation: quarantine", 1)
	_, err := Parse([]byte(withRouting))
	if err == nil || !strings.Contains(err.Error(), "routing.requirements.min_output_tokens") {
		t.Fatalf("expected routing.requirements.min_output_tokens error, got %v", err)
	}
}

func TestRoutingBlockRejectedWithExplicitAgent(t *testing.T) {
	// explicit agent: claude-code + a routing block = ambiguity error.
	explicit := strings.Replace(validContract, "agent: claude", "agent: claude-code", 1)
	withRouting := strings.Replace(explicit, "on_violation: quarantine",
		"routing: {objective: balanced}\non_violation: quarantine", 1)
	_, err := Parse([]byte(withRouting))
	if err == nil || !strings.Contains(err.Error(), "routing") {
		t.Fatalf("expected routing ambiguity error, got %v", err)
	}
}

func TestRoutingUnknownObjectiveRejected(t *testing.T) {
	withRouting := strings.Replace(autoContract, "on_violation: quarantine",
		"routing: {objective: fastest}\non_violation: quarantine", 1)
	_, err := Parse([]byte(withRouting))
	if err == nil || !strings.Contains(err.Error(), "routing.objective") {
		t.Fatalf("expected routing.objective error, got %v", err)
	}
}

func TestRoutingUnknownCandidateRejected(t *testing.T) {
	withRouting := strings.Replace(autoContract, "on_violation: quarantine",
		"routing: {candidates: [claude-code, mystery]}\non_violation: quarantine", 1)
	_, err := Parse([]byte(withRouting))
	if err == nil || !strings.Contains(err.Error(), "routing.candidates") {
		t.Fatalf("expected routing.candidates error, got %v", err)
	}
}

func TestRoutingMaxAttemptsOutOfRangeRejected(t *testing.T) {
	for _, n := range []int{-1, 4} {
		withRouting := strings.Replace(autoContract, "on_violation: quarantine",
			fmt.Sprintf("routing: {max_attempts: %d}\non_violation: quarantine", n), 1)
		_, err := Parse([]byte(withRouting))
		if err == nil || !strings.Contains(err.Error(), "routing.max_attempts") {
			t.Fatalf("max_attempts=%d: expected routing.max_attempts error, got %v", n, err)
		}
	}
}

func TestExplicitUnknownAgentRejected(t *testing.T) {
	unknown := strings.Replace(validContract, "agent: claude", "agent: gemini", 1)
	_, err := Parse([]byte(unknown))
	if err == nil || !strings.Contains(err.Error(), "agent") {
		t.Fatalf("expected agent error for unknown backend, got %v", err)
	}
}

// TestParseWithoutAssayBlockLeavesAssayNil is the regression test for Phase
// 3A: every job YAML predating the assay field (i.e. every existing
// contract in this test file) must keep parsing and validating exactly as
// before — assay is opt-in, not a new required block.
func TestParseWithoutAssayBlockLeavesAssayNil(t *testing.T) {
	contract, err := Parse([]byte(validContract))
	if err != nil {
		t.Fatalf("Parse(validContract) error = %v", err)
	}
	if contract.Assay != nil {
		t.Fatalf("expected nil Assay on a contract without an assay block, got %+v", contract.Assay)
	}
}

func TestParseAssayBlock(t *testing.T) {
	withAssay := strings.Replace(validContract, "on_violation: quarantine",
		"assay: {profile: coding-output-v1, enforcement: blocking}\non_violation: quarantine", 1)
	contract, err := Parse([]byte(withAssay))
	if err != nil {
		t.Fatalf("assay block must validate: %v", err)
	}
	if contract.Assay == nil || contract.Assay.Profile != "coding-output-v1" || contract.Assay.Enforcement != "blocking" {
		t.Fatalf("assay not parsed: %+v", contract.Assay)
	}
}

func TestAssayAdvisoryAndTelemetryEnforcementAccepted(t *testing.T) {
	for _, enforcement := range []string{"advisory", "telemetry"} {
		withAssay := strings.Replace(validContract, "on_violation: quarantine",
			fmt.Sprintf("assay: {profile: coding-output-v1, enforcement: %s}\non_violation: quarantine", enforcement), 1)
		if _, err := Parse([]byte(withAssay)); err != nil {
			t.Fatalf("enforcement=%s must validate: %v", enforcement, err)
		}
	}
}

func TestAssayMissingProfileRejected(t *testing.T) {
	withAssay := strings.Replace(validContract, "on_violation: quarantine",
		"assay: {enforcement: blocking}\non_violation: quarantine", 1)
	_, err := Parse([]byte(withAssay))
	if err == nil || !strings.Contains(err.Error(), "assay.profile") {
		t.Fatalf("expected assay.profile error, got %v", err)
	}
}

func TestAssayUnknownEnforcementRejected(t *testing.T) {
	withAssay := strings.Replace(validContract, "on_violation: quarantine",
		"assay: {profile: coding-output-v1, enforcement: sometimes}\non_violation: quarantine", 1)
	_, err := Parse([]byte(withAssay))
	if err == nil || !strings.Contains(err.Error(), "assay.enforcement") {
		t.Fatalf("expected assay.enforcement error, got %v", err)
	}
}

// TestAssayPerArtifactListAcceptedWithoutContractWideDefault covers Sol
// audit finding #16: a contract may declare per-artifact assays[] entries
// covering every produced artifact instead of one contract-wide profile.
func TestAssayPerArtifactListAcceptedWithoutContractWideDefault(t *testing.T) {
	withProduces := strings.Replace(validContract, "on_violation: quarantine",
		"produces: [{name: patch-report, path: .governator/artifacts/patch.json, max_bytes: 1024}]\n"+
			"assay: {assays: [{artifact: patch-report, profile: coding-output-v2, enforcement: blocking}]}\n"+
			"on_violation: quarantine", 1)
	contract, err := Parse([]byte(withProduces))
	if err != nil {
		t.Fatalf("per-artifact assays[] without a contract-wide profile must validate: %v", err)
	}
	if len(contract.Assay.Artifacts) != 1 || contract.Assay.Artifacts[0].Artifact != "patch-report" {
		t.Fatalf("expected one parsed per-artifact assay entry, got %+v", contract.Assay.Artifacts)
	}
}

// TestAssayNoneExemptionRejectsEnforcement proves an artifact-level "none"
// exemption cannot also carry an enforcement value (there is nothing to
// enforce for an artifact explicitly opted out of assay).
func TestAssayNoneExemptionRejectsEnforcement(t *testing.T) {
	withProduces := strings.Replace(validContract, "on_violation: quarantine",
		"produces: [{name: patch-report, path: .governator/artifacts/patch.json, max_bytes: 1024}]\n"+
			"assay: {assays: [{artifact: patch-report, profile: none, enforcement: blocking}]}\n"+
			"on_violation: quarantine", 1)
	_, err := Parse([]byte(withProduces))
	if err == nil || !strings.Contains(err.Error(), "assays[0].enforcement") {
		t.Fatalf("expected assays[0].enforcement error for a none exemption carrying enforcement, got %v", err)
	}
}

// TestAssayNoneExemptionAcceptedWithoutEnforcement is the no-over-blocking
// companion: the same exemption, enforcement genuinely omitted, must parse.
func TestAssayNoneExemptionAcceptedWithoutEnforcement(t *testing.T) {
	withProduces := strings.Replace(validContract, "on_violation: quarantine",
		"produces: [{name: patch-report, path: .governator/artifacts/patch.json, max_bytes: 1024}]\n"+
			"assay: {assays: [{artifact: patch-report, profile: none}]}\n"+
			"on_violation: quarantine", 1)
	if _, err := Parse([]byte(withProduces)); err != nil {
		t.Fatalf("a bare none exemption must validate: %v", err)
	}
}

// TestAssayArtifactNameMustMatchProduces catches a typo'd assays[].artifact
// at contract-validation time rather than letting it silently never match
// anything at evaluation time.
func TestAssayArtifactNameMustMatchProduces(t *testing.T) {
	withProduces := strings.Replace(validContract, "on_violation: quarantine",
		"produces: [{name: patch-report, path: .governator/artifacts/patch.json, max_bytes: 1024}]\n"+
			"assay: {assays: [{artifact: typo-name, profile: coding-output-v2, enforcement: blocking}]}\n"+
			"on_violation: quarantine", 1)
	_, err := Parse([]byte(withProduces))
	if err == nil || !strings.Contains(err.Error(), "assays[0].artifact") {
		t.Fatalf("expected assays[0].artifact error for a name not in produces, got %v", err)
	}
}

// TestAssayBlockWithNeitherProfileNorArtifactsRejected: a bare `assay: {}`
// block (no contract-wide profile, no per-artifact list) would never
// evaluate anything — rejected the same way a missing profile always was.
func TestAssayBlockWithNeitherProfileNorArtifactsRejected(t *testing.T) {
	withAssay := strings.Replace(validContract, "on_violation: quarantine",
		"assay: {}\non_violation: quarantine", 1)
	_, err := Parse([]byte(withAssay))
	if err == nil || !strings.Contains(err.Error(), "assay.profile") {
		t.Fatalf("expected assay.profile error for an empty assay block, got %v", err)
	}
}
