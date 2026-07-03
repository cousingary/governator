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
  root: /mnt/e/downloads/emmaNader
  worktree: auto
allowed:
  read: ["designs/**", "mockups/**"]
  write: ["output/clipart/**"]
  execute: ["python3 remove_blue_fringe.py *", "python3 -c *"]
forbidden:
  paths: ["done/**", "*.psd"]
  commands: ["rm -rf", "git push"]
  behaviors: [refactor, reformat, rename_files, scope_expansion]
budget: {max_minutes: 20, max_commands: 60, max_files_changed: 30, max_deleted: 0}
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
		{"relative workspace", strings.Replace(validContract, "root: /mnt/e/downloads/emmaNader", "root: relative/project", 1), "workspace.root"},
		{"write mode without worktree", strings.Replace(validContract, "worktree: auto", "worktree: none", 1), "workspace.worktree"},
		{"path escape", strings.Replace(validContract, "output/clipart/**", "../outside/**", 1), "allowed.write[0]"},
		{"zero budget", strings.Replace(validContract, "max_minutes: 20", "max_minutes: 0", 1), "budget.max_minutes"},
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
