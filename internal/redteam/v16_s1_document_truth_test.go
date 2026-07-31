//go:build redteam

package redteam

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestV16Case392SecurityMdContradictionRejected is v16-release report case
// 392 (R3): SECURITY.md is the file GitHub surfaces in the security tab --
// the first thing a researcher opens -- and it went stale by roughly
// nineteen release-candidate-cycles' worth of work because no checker ever
// looked at it (High 11 fixed in docs/security.md, still described as open
// in SECURITY.md). scripts/check_release_docs.py's new SECURITY.md mode
// (check_security) is the mechanism; this proves it actually rejects a
// contradiction in either document, not only that the real pair happens to
// agree today.
func TestV16Case392SecurityMdContradictionRejected(t *testing.T) {
	repoRoot := repoRootForBundleTests(t)
	checker := filepath.Join(repoRoot, "scripts", "check_release_docs.py")
	realSecurity := filepath.Join(repoRoot, "SECURITY.md")
	realRegister := filepath.Join(repoRoot, "docs", "security.md")

	t.Run("the real SECURITY.md agrees with the real register", func(t *testing.T) {
		cmd := exec.Command("python3", checker, realSecurity, realRegister)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("expected the real SECURITY.md to satisfy check_release_docs.py, got:\n%s", out)
		}
	})

	t.Run("SECURITY.md mutated to claim a fixed finding is open is rejected", func(t *testing.T) {
		dir := t.TempDir()
		text := readRealFile(t, realSecurity)
		mutated := strings.Replace(text,
			"including High 11 (local-runner output capping), closed by commit `629cb62`",
			"High 11 (local-runner output capping) remains open",
			1,
		)
		if mutated == text {
			t.Fatal("mutation target string not found in SECURITY.md -- test fixture drifted from the real file")
		}
		mutatedPath := filepath.Join(dir, "SECURITY.md")
		if err := os.WriteFile(mutatedPath, []byte(mutated), 0o644); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("python3", checker, mutatedPath, realRegister)
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("expected check_release_docs.py to reject SECURITY.md claiming a fixed finding is open, but it passed:\n%s", out)
		}
		if !strings.Contains(string(out), "High 11") {
			t.Fatalf("expected the failure to name the contradicting finding, got:\n%s", out)
		}
	})

	t.Run("register mutated to drop a fix commit no longer contradicts SECURITY.md", func(t *testing.T) {
		// The reverse-direction mutation: docs/security.md is edited so High
		// 11 no longer carries a fix commit (as if the fix were reverted).
		// SECURITY.md (real, says "closed") is left untouched. This must
		// still PASS -- the checker only flags SECURITY.md asserting "open"
		// against a register that says "fixed", never the other way, and
		// this proves the fixed-finding set the checker computes actually
		// tracks the register's content rather than some hardcoded list.
		dir := t.TempDir()
		text := readRealFile(t, realRegister)
		mutated := strings.Replace(text,
			"`629cb62` (S3/S6 follow-up)",
			"(reverted, no fix commit)",
			1,
		)
		if mutated == text {
			t.Fatal("mutation target string not found in docs/security.md -- test fixture drifted from the real file")
		}
		mutatedPath := filepath.Join(dir, "security.md")
		if err := os.WriteFile(mutatedPath, []byte(mutated), 0o644); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("python3", checker, realSecurity, mutatedPath)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("expected no contradiction once the register no longer records a fix commit for High 11, got:\n%s", out)
		}
	})
}

// TestV16Case393NoticeLessTreeFailsSourceClosure is v16-release report case
// 393 (R8): internal/minimalism ships a YAGNI ruleset adapted from the
// ponytail project (MIT-licensed) with no NOTICE file carrying its
// copyright/permission notice -- LICENSE alone (Governator's own copyright)
// doesn't satisfy that. scripts/source_closure.py's generate command grew an
// opt-in --require-files check (audit_bundle.sh passes it for the
// Governator closure only, never Assayer's, which carries no such
// adaptation); this proves generate() actually refuses a tree missing a
// required file rather than only that the real repo happens to have one.
func TestV16Case393NoticeLessTreeFailsSourceClosure(t *testing.T) {
	repoRoot := repoRootForBundleTests(t)
	checker := filepath.Join(repoRoot, "scripts", "source_closure.py")

	buildFixtureRepo := func(t *testing.T, files map[string]string) string {
		t.Helper()
		fixture := t.TempDir()
		runGit := func(args ...string) {
			t.Helper()
			cmd := exec.Command("git", args...)
			cmd.Dir = fixture
			cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=redteam", "GIT_AUTHOR_EMAIL=redteam@example.com", "GIT_COMMITTER_NAME=redteam", "GIT_COMMITTER_EMAIL=redteam@example.com")
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("git %v: %v\n%s", args, err, out)
			}
		}
		runGit("init", "-q")
		runGit("config", "user.email", "redteam@example.com")
		runGit("config", "user.name", "redteam")
		for rel, content := range files {
			p := filepath.Join(fixture, rel)
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		runGit("add", "-A")
		runGit("commit", "-q", "-m", "fixture init")
		return fixture
	}

	runGenerate := func(t *testing.T, fixture string, requireFiles string) (string, error) {
		t.Helper()
		dir := t.TempDir()
		args := []string{
			checker, "generate",
			"--repo", fixture, "--ref", "HEAD",
			"--out-archive", filepath.Join(dir, "out.tar.gz"),
			"--out-tree", filepath.Join(dir, "out.tree.json"),
		}
		if requireFiles != "" {
			args = append(args, "--require-files", requireFiles)
		}
		cmd := exec.Command("python3", args...)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	t.Run("a NOTICE-less tree is rejected when LICENSE,NOTICE are required", func(t *testing.T) {
		fixture := buildFixtureRepo(t, map[string]string{
			"LICENSE":   "MIT License\n",
			"README.md": "hello\n",
		})
		out, err := runGenerate(t, fixture, "LICENSE,NOTICE")
		if err == nil {
			t.Fatalf("expected generate to reject a tree missing NOTICE, but it passed:\n%s", out)
		}
		if !strings.Contains(out, "NOTICE") {
			t.Fatalf("expected the failure to name the missing NOTICE file, got:\n%s", out)
		}
	})

	t.Run("a tree carrying both required files passes", func(t *testing.T) {
		fixture := buildFixtureRepo(t, map[string]string{
			"LICENSE":   "MIT License\n",
			"NOTICE":    "ponytail notice\n",
			"README.md": "hello\n",
		})
		if out, err := runGenerate(t, fixture, "LICENSE,NOTICE"); err != nil {
			t.Fatalf("expected generate to accept a tree carrying both required files, got:\n%s", out)
		}
	})

	t.Run("omitting --require-files never enforces it (Assayer's closure is unaffected)", func(t *testing.T) {
		fixture := buildFixtureRepo(t, map[string]string{
			"README.md": "hello, no license at all\n",
		})
		if out, err := runGenerate(t, fixture, ""); err != nil {
			t.Fatalf("expected generate with no --require-files to accept a tree with neither LICENSE nor NOTICE, got:\n%s", out)
		}
	})
}
