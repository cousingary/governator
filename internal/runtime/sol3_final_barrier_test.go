package runtime

// sol3_final_barrier_test covers Sol redteam v3 Session 5 / P0.3.

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cousingary/governator/internal/contracts"
)

func finalBarrierGitStatus(t *testing.T, root string) string {
	t.Helper()
	cmd := exec.Command("git", "-C", root, "status", "--porcelain")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git status --porcelain: %v: %s", err, out)
	}
	return string(out)
}

func TestSol3FinalBarrierQuarantinesValidatorCreatedUndeclaredFile(t *testing.T) {
	root, bin := fixture(t)
	t.Setenv("GOV_HOME", t.TempDir())
	t.Setenv("GOV_CLAUDE_BIN", bin)

	c := contract(root)
	c.Budget.MaxNewFiles = 4
	c.Success.Validators = []string{"test -f output/result.txt", "printf pwned > pwned.txt"}

	r, err := New().Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "QUARANTINED" || (!strings.Contains(r.Message, "final barrier write outside allowlist") && !strings.Contains(r.Message, "final barrier write outside intended_writes")) {
		t.Fatalf("status=%s message=%s", r.Status, r.Message)
	}
	if _, err := os.Stat(filepath.Join(root, "pwned.txt")); !os.IsNotExist(err) {
		t.Fatalf("validator-created file reached live root: %v", err)
	}
	if status := finalBarrierGitStatus(t, root); status != "" {
		t.Fatalf("live root has git changes after quarantine: %q", status)
	}
}

func TestSol3FinalBarrierQuarantinesValidatorProtectedPathMutation(t *testing.T) {
	root, bin := fixture(t)
	protected := t.TempDir()
	protectedFile := filepath.Join(protected, "secret.txt")
	manifest := filepath.Join(t.TempDir(), "protected_paths.txt")
	if err := os.WriteFile(manifest, []byte(protectedFile+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_HOME", t.TempDir())
	t.Setenv("GOV_CLAUDE_BIN", bin)
	t.Setenv("GOV_PROTECTED_PATHS", manifest)

	c := contract(root)
	c.Success.Validators = []string{"test -f output/result.txt", "printf leak > " + shQuote(protectedFile)}

	r, err := New().Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	// Real Landlock enforcement (Sol v7 S1/S2) can now block the validator's
	// leaking write itself before it ever lands on disk -- a strictly
	// stronger outcome than the post-hoc "final barrier protected path
	// mutation" ledger check this test predates, surfacing instead as an
	// ordinary nonzero validator exit.
	if r.Status != "QUARANTINED" || !(strings.Contains(r.Message, "final barrier protected path mutation") || strings.Contains(r.Message, "validator failed")) {
		t.Fatalf("status=%s message=%s", r.Status, r.Message)
	}
	if _, err := os.Stat(filepath.Join(root, "output", "result.txt")); !os.IsNotExist(err) {
		t.Fatalf("protected-path quarantine merged output: %v", err)
	}
	if _, err := os.Stat(protectedFile); !os.IsNotExist(err) {
		t.Fatalf("protected file was written: %v", err)
	}
	if status := finalBarrierGitStatus(t, root); status != "" {
		t.Fatalf("live root has git changes after quarantine: %q", status)
	}
}

func TestSol3FinalBarrierQuarantinesValidatorDeletesInScopeFile(t *testing.T) {
	root, bin := fixture(t)
	if err := os.MkdirAll(filepath.Join(root, "output"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "output", "keep.txt"), []byte("keep\n"), 0644); err != nil {
		t.Fatal(err)
	}
	git(t, root, "add", "output/keep.txt")
	git(t, root, "commit", "-m", "add keep")

	t.Setenv("GOV_HOME", t.TempDir())
	t.Setenv("GOV_CLAUDE_BIN", bin)

	c := contract(root)
	c.Budget.MaxFilesChanged = 6
	c.Success.Validators = []string{"test -f output/result.txt", "rm output/keep.txt"}

	r, err := New().Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "QUARANTINED" || !strings.Contains(r.Message, "final barrier max_deleted exceeded") {
		t.Fatalf("status=%s message=%s", r.Status, r.Message)
	}
	got, err := os.ReadFile(filepath.Join(root, "output", "keep.txt"))
	if err != nil {
		t.Fatalf("tracked file missing from live root after quarantine: %v", err)
	}
	if string(got) != "keep\n" {
		t.Fatalf("tracked file changed in live root: %q", got)
	}
	if status := finalBarrierGitStatus(t, root); status != "" {
		t.Fatalf("live root has git changes after quarantine: %q", status)
	}
}

func TestSol3FinalBarrierAllowsCleanupFormatterRewrite(t *testing.T) {
	root, bin := fixture(t)
	t.Setenv("GOV_HOME", t.TempDir())
	t.Setenv("GOV_CLAUDE_BIN", bin)

	c := contract(root)
	c.Cleanup = &contracts.Cleanup{Required: true, Validators: []string{"printf 'formatted\\n' > output/result.txt"}}

	r, err := New().Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "APPROVED" {
		t.Fatalf("status=%s message=%s", r.Status, r.Message)
	}
	got, err := os.ReadFile(filepath.Join(root, "output", "result.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "formatted\n" {
		t.Fatalf("cleanup rewrite did not merge approved content: %q", got)
	}
	if status := finalBarrierGitStatus(t, root); status != "" {
		t.Fatalf("live root has git changes after approved merge: %q", status)
	}
}

func TestSol3FinalBarrierQuarantinesValidatorLineBudgetOverflow(t *testing.T) {
	root, bin := fixture(t)
	t.Setenv("GOV_HOME", t.TempDir())
	t.Setenv("GOV_CLAUDE_BIN", bin)

	c := contract(root)
	c.Budget.MaxLinesChanged = 5
	c.Success.Validators = []string{"test -f output/result.txt", "printf '1\\n2\\n3\\n4\\n5\\n6\\n7\\n8\\n9\\n10\\n' > output/result.txt"}

	r, err := New().Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "QUARANTINED" || !strings.Contains(r.Message, "final barrier max_lines_changed exceeded") {
		t.Fatalf("status=%s message=%s", r.Status, r.Message)
	}
	if _, err := os.Stat(filepath.Join(root, "output", "result.txt")); !os.IsNotExist(err) {
		t.Fatalf("line-budget quarantine merged output: %v", err)
	}
	if status := finalBarrierGitStatus(t, root); status != "" {
		t.Fatalf("live root has git changes after quarantine: %q", status)
	}
}
