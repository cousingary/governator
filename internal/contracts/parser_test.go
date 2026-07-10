package contracts

import (
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
