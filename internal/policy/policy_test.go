package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cousingary/governator/internal/contracts"
)

func TestClassifyShellCommandParity(t *testing.T) {
	tests := []struct {
		command string
		high    bool
		verb    string
	}{
		{"echo ok && rm -rf dist", true, "delete"},
		{"find . -exec rm {} +", true, "delete"},
		{"dd if=/dev/zero of=/dev/sda", true, "delete"},
		{"git push origin main", true, "push"},
		{"git push --force origin feature", true, "push"},
		{"psql -c 'DROP TABLE users'", true, "drop"},
		{"rm one.txt", false, "delete"},
		{"rm one.txt", true, ""},
		{"rm -i one.txt", false, ""},
		{"go test ./...", false, ""},
		{"rtk rm -rf dist", true, "delete"},
		{"rtk -u git push origin main", true, "push"},
		{"rtk proxy psql -c 'DROP TABLE users'", true, "drop"},
		{"echo ok && rtk rm -rf dist", true, "delete"},
		{"sudo rtk proxy rm -rf dist", true, "delete"},
		{"FOO=1 nohup sudo rtk proxy rm -rf dist", true, "delete"},
	}
	for _, test := range tests {
		t.Run(test.command, func(t *testing.T) {
			got := ClassifyShellCommand(test.command, test.high)
			if test.verb == "" && got != nil {
				t.Fatalf("unexpected classification: %#v", got)
			}
			if test.verb != "" && (got == nil || got.Verb != test.verb) {
				t.Fatalf("want %s, got %#v", test.verb, got)
			}
		})
	}
}

func TestPreflightBlocksBroaderIntent(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "target.go"), []byte("package x\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c := contracts.Contract{
		JobID: "p2", JobType: "code", Agent: "claude", Mode: contracts.ModeSurgeon,
		Workspace: contracts.Workspace{Root: root, Worktree: "auto"},
		Allowed:   contracts.Permissions{Read: []string{"**"}, Write: []string{"internal/**"}, Execute: []string{"go test ./..."}},
		Preflight: contracts.Preflight{IntendedWrites: []string{"**"}},
		Budget:    contracts.Budget{MaxMinutes: 1, MaxCommands: 2, MaxFilesChanged: 2, MaxLinesChanged: 20, MaxNewFiles: 1},
		Success:   contracts.Success{RequiredFiles: []string{"internal/x.go"}, Validators: []string{"true"}}, OnViolation: "quarantine",
	}
	report, err := Preflight(c)
	if err != nil {
		t.Fatal(err)
	}
	if report.Risk != RiskBlocked || !strings.Contains(strings.Join(report.RiskFlags, " "), "exceeds") {
		t.Fatalf("unexpected report: %#v", report)
	}
}

func TestPatternWithinIsConservative(t *testing.T) {
	tests := []struct {
		pattern string
		allowed []string
		want    bool
	}{
		{"output/image.png", []string{"output/*.png"}, true},
		{"output/*.png", []string{"output/*.png"}, true},
		{"output/**", []string{"output/*.png"}, false},
		{"output/nested/**", []string{"output/**"}, true},
		{"other/**", []string{"output/**"}, false},
	}
	for _, test := range tests {
		if got := patternWithin(test.pattern, test.allowed); got != test.want {
			t.Errorf("patternWithin(%q, %q) = %v, want %v", test.pattern, test.allowed, got, test.want)
		}
	}
}

func TestHighRiskRequiresScoutOrApproval(t *testing.T) {
	root := t.TempDir()
	c := contracts.Contract{
		JobID: "high-risk", JobType: "batch", Agent: "claude", Mode: contracts.ModeBatchWorker,
		Workspace: contracts.Workspace{Root: root, Worktree: "auto"},
		Allowed:   contracts.Permissions{Read: []string{"**"}, Write: []string{"output/**"}, Execute: []string{"go test ./..."}},
		Preflight: contracts.Preflight{IntendedWrites: []string{"output/**"}},
		Budget:    contracts.Budget{MaxMinutes: 1, MaxCommands: 2, MaxFilesChanged: 5, MaxLinesChanged: 3000, MaxNewFiles: 2},
		Success:   contracts.Success{RequiredFiles: []string{"output/result.txt"}, Validators: []string{"true"}}, OnViolation: "quarantine",
	}
	report, err := Preflight(c)
	if err != nil {
		t.Fatal(err)
	}
	if report.Risk != RiskHigh {
		t.Fatalf("risk = %s, want HIGH", report.Risk)
	}
	if err := Enforce(report, c); err == nil {
		t.Fatal("HIGH risk unexpectedly passed without scout or approval")
	}
	c.Preflight.ScoutCompleted = true
	if err := Enforce(report, c); err != nil {
		t.Fatalf("scouted HIGH risk rejected: %v", err)
	}
}

func FuzzClassifyShellCommand(f *testing.F) {
	for _, seed := range []string{
		"go test ./...",
		"echo ok && rm -rf dist",
		"git push --force origin main",
		"psql -c 'DROP TABLE users'",
		"find . -exec rm {} +",
	} {
		f.Add(seed, false)
		f.Add(seed, true)
	}
	f.Fuzz(func(t *testing.T, command string, highDangerOnly bool) {
		if len(command) > 16*1024 {
			t.Skip()
		}
		_ = ClassifyShellCommand(command, highDangerOnly)
	})
}
