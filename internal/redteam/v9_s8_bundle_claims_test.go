//go:build redteam

package redteam

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// repoRootForBundleTests resolves the real governator repo root from this
// test file's own location, independent of the caller's working directory.
func repoRootForBundleTests(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not resolve this test file's own path")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..")
}

// buildAuditBundleFixtureRepo creates a fresh, isolated git repository and
// stages a real copy of scripts/audit_bundle.sh + scripts/check_architecture_doc.py
// inside it. scripts/audit_bundle.sh self-locates via BASH_SOURCE (the same
// pattern scripts/release.sh uses) so it always operates on its OWN
// containing repo -- the only way to exercise it against a synthetic
// fixture is to run a real copy of it from inside that fixture, exactly as
// an operator would from their own checkout.
func buildAuditBundleFixtureRepo(t *testing.T) string {
	t.Helper()
	repoRoot := repoRootForBundleTests(t)
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

	mustWrite := func(rel, content string) {
		t.Helper()
		p := filepath.Join(fixture, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite("main.go", "package main\n\nfunc main() {}\n")
	mustWrite("docs/claims.yaml", "version: 1\ncases: []\n")
	// dist/ is real build OUTPUT (scripts/release.sh's own OUT_DIR), never
	// meant to be tracked -- mirrors governator's own .gitignore so a test
	// that populates a fake dist/ (case 43) doesn't itself trip the
	// dirty-tree refusal.
	mustWrite(".gitignore", "dist/\naudit-out*/\n")
	mustWrite("scripts/audit_bundle.sh", readRealFile(t, filepath.Join(repoRoot, "scripts", "audit_bundle.sh")))
	mustWrite("scripts/check_architecture_doc.py", readRealFile(t, filepath.Join(repoRoot, "scripts", "check_architecture_doc.py")))
	if err := os.Chmod(filepath.Join(fixture, "scripts", "audit_bundle.sh"), 0o755); err != nil {
		t.Fatal(err)
	}

	runGit("add", "-A")
	runGit("commit", "-q", "-m", "fixture init")
	return fixture
}

func readRealFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// runAuditBundle commits any staged changes in fixture (audit_bundle.sh
// refuses a dirty tree by design -- see the fixture repo's own untracked-
// changes gate), then runs scripts/audit_bundle.sh from inside it with the
// given extra environment.
func runAuditBundle(t *testing.T, fixture string, outDir string, extraEnv ...string) (string, error) {
	t.Helper()
	cmd := exec.Command("bash", "scripts/audit_bundle.sh")
	cmd.Dir = fixture
	cmd.Env = append(os.Environ(), extraEnv...)
	cmd.Env = append(cmd.Env, "OUT_DIR="+outDir)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func commitAll(t *testing.T, fixture, message string) {
	t.Helper()
	for _, args := range [][]string{{"add", "-A"}, {"commit", "-q", "-m", message}} {
		cmd := exec.Command("git", args...)
		cmd.Dir = fixture
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=redteam", "GIT_AUTHOR_EMAIL=redteam@example.com", "GIT_COMMITTER_NAME=redteam", "GIT_COMMITTER_EMAIL=redteam@example.com")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
}

// TestV9Case38BundleWithStaleBinaryRejected is Sol9 report case 38: an
// audit bundle containing a stale binary (the report's concrete example:
// bin/gov = rc1-dirty sitting next to the real dist/gov) must be rejected,
// not shipped silently. source/ can only ever contain committed bytes
// (git archive), so the realistic way this happens is exactly what the
// audit found: someone accidentally `git add`s a build artifact. This
// fixture simulates that mistake directly -- a tracked bin/gov -- and
// proves audit_bundle.sh's post-build contamination scan still catches it
// even though it came from a real commit, not working-tree drift.
func TestV9Case38BundleWithStaleBinaryRejected(t *testing.T) {
	fixture := buildAuditBundleFixtureRepo(t)
	if err := os.MkdirAll(filepath.Join(fixture, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixture, "bin", "gov"), []byte("stale rc1-dirty binary bytes"), 0o755); err != nil {
		t.Fatal(err)
	}
	commitAll(t, fixture, "accidentally commit a stale binary")

	out, err := runAuditBundle(t, fixture, t.TempDir())
	if err == nil {
		t.Fatalf("expected audit_bundle.sh to refuse a bundle containing bin/gov, but it succeeded:\n%s", out)
	}
	if !strings.Contains(out, "bin/gov") {
		t.Fatalf("expected the refusal to name bin/gov, got:\n%s", out)
	}
}

// TestV9Case39BundleWithVenvOrCacheRejected is Sol9 report case 39: the
// same contamination scan must catch a Python venv/cache directory, not
// only a stale binary.
func TestV9Case39BundleWithVenvOrCacheRejected(t *testing.T) {
	fixture := buildAuditBundleFixtureRepo(t)
	if err := os.MkdirAll(filepath.Join(fixture, ".venv", "lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixture, ".venv", "lib", "marker.py"), []byte("# venv marker\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	commitAll(t, fixture, "accidentally commit a venv")

	out, err := runAuditBundle(t, fixture, t.TempDir())
	if err == nil {
		t.Fatalf("expected audit_bundle.sh to refuse a bundle containing .venv, but it succeeded:\n%s", out)
	}
	if !strings.Contains(out, ".venv") {
		t.Fatalf("expected the refusal to name .venv, got:\n%s", out)
	}
}

// TestV9Case40StaleArchitectureFinalSectionRejected is Sol9 report case 40:
// an architecture doc whose Status header is accurate but whose
// Remediation-history section still names an older release as current must
// be rejected, not bundled as though it were consistent.
func TestV9Case40StaleArchitectureFinalSectionRejected(t *testing.T) {
	fixture := buildAuditBundleFixtureRepo(t)
	staleDoc := filepath.Join(fixture, "..", "agents_governator_architecture.md")
	staleDoc, err := filepath.Abs(staleDoc)
	if err != nil {
		t.Fatal(err)
	}
	content := "# Doc\n**Status:** current v2.0.0\n## Remediation history\nOnly outstanding item is reinstalling v1.0.0.\n"
	if err := os.WriteFile(staleDoc, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(staleDoc) })

	out, err := runAuditBundle(t, fixture, t.TempDir(), "GOV_ARCHITECTURE_DOC="+staleDoc)
	if err == nil {
		t.Fatalf("expected audit_bundle.sh to refuse a stale architecture doc, but it succeeded:\n%s", out)
	}
	if !strings.Contains(out, "check_architecture_doc") && !strings.Contains(out, "stale architecture doc") {
		t.Fatalf("expected the refusal to reference the architecture-doc consistency check, got:\n%s", out)
	}
}

// TestV9Case41HMACPlaceholderNeverWrittenWithoutAKey is Sol9 report case
// 41: the old behavior wrote a file named "signature" containing the
// literal text "UNSIGNED: set GOV_RELEASE_HMAC_KEY..." even when a real
// checksums.txt.minisig sat right next to it -- reading as though the
// whole release were unsigned. scripts/release_hmac_sign.py (factored out
// of scripts/release.sh for exactly this testability) must never write a
// placeholder: no key configured means no file at all.
func TestV9Case41HMACPlaceholderNeverWrittenWithoutAKey(t *testing.T) {
	repoRoot := repoRootForBundleTests(t)
	dir := t.TempDir()
	checksums := filepath.Join(dir, "checksums.txt")
	if err := os.WriteFile(checksums, []byte("deadbeef  gov_1.0.0_linux_amd64.tar.gz\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "checksums.txt.hmac")

	t.Run("no key configured -- file must not exist", func(t *testing.T) {
		cmd := exec.Command("python3", filepath.Join(repoRoot, "scripts", "release_hmac_sign.py"), "--checksums", checksums, "--out", out)
		cmd.Env = envWithout(os.Environ(), "GOV_RELEASE_HMAC_KEY")
		if combinedOut, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("release_hmac_sign.py: %v\n%s", err, combinedOut)
		}
		if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
			t.Fatalf("expected no checksums.txt.hmac when GOV_RELEASE_HMAC_KEY is unset, but it exists (stat err=%v)", statErr)
		}
	})

	t.Run("key configured -- real HMAC, never a placeholder string", func(t *testing.T) {
		cmd := exec.Command("python3", filepath.Join(repoRoot, "scripts", "release_hmac_sign.py"), "--checksums", checksums, "--out", out)
		cmd.Env = append(envWithout(os.Environ(), "GOV_RELEASE_HMAC_KEY"), "GOV_RELEASE_HMAC_KEY=test-secret-key")
		if combinedOut, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("release_hmac_sign.py: %v\n%s", err, combinedOut)
		}
		got, err := os.ReadFile(out)
		if err != nil {
			t.Fatalf("expected checksums.txt.hmac to exist once a key is configured: %v", err)
		}
		if strings.Contains(string(got), "UNSIGNED") {
			t.Fatalf("checksums.txt.hmac contains the literal placeholder text 'UNSIGNED' while a real key was configured: %q", got)
		}
		if !strings.HasPrefix(strings.TrimSpace(string(got)), "hmac-sha256:") {
			t.Fatalf("expected a real hmac-sha256: signature, got %q", got)
		}
	})
}

func envWithout(env []string, key string) []string {
	out := make([]string, 0, len(env))
	prefix := key + "="
	for _, kv := range env {
		if strings.HasPrefix(kv, prefix) {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// TestV9Case42MissingPubkeyFingerprintRejected is Sol9 report case 42: a
// release doc that ships minisign verification instructions without also
// documenting where to obtain the public key fingerprint from is
// unverifiable in practice even though every file on disk is real.
// scripts/check_release_docs.py enforces the doc completeness; this proves
// it actually rejects a doc missing that guidance, not only that the real
// docs/publishing.md happens to currently pass.
func TestV9Case42MissingPubkeyFingerprintRejected(t *testing.T) {
	repoRoot := repoRootForBundleTests(t)
	checker := filepath.Join(repoRoot, "scripts", "check_release_docs.py")

	t.Run("doc missing fingerprint guidance is rejected", func(t *testing.T) {
		dir := t.TempDir()
		doc := filepath.Join(dir, "publishing.md")
		if err := os.WriteFile(doc, []byte("# Publishing\n\nRun scripts/release.sh and upload checksums.txt.minisig.\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("python3", checker, doc)
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("expected check_release_docs.py to reject a doc with no fingerprint/out-of-band guidance, but it passed:\n%s", out)
		}
		if !strings.Contains(string(out), "fingerprint") {
			t.Fatalf("expected the failure to mention the missing fingerprint guidance, got:\n%s", out)
		}
	})

	t.Run("the real docs/publishing.md passes", func(t *testing.T) {
		cmd := exec.Command("python3", checker, filepath.Join(repoRoot, "docs", "publishing.md"))
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("expected the real docs/publishing.md to satisfy check_release_docs.py, got:\n%s", out)
		}
	})
}

// TestV9Case43ClaimsDivergenceWithoutProvenanceRejected is Sol9 report case
// 43: source/docs/claims.yaml (current) and dist/claims.yaml (frozen into
// an earlier release build) are allowed to differ, but the bundle must
// never leave that divergence unexplained -- no unlabeled third copy in
// evidence/, and an explicit provenance record whenever the two hashes
// don't match.
func TestV9Case43ClaimsDivergenceWithoutProvenanceRejected(t *testing.T) {
	fixture := buildAuditBundleFixtureRepo(t)
	distDir := filepath.Join(fixture, "dist")
	if err := os.MkdirAll(distDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(distDir, "claims.yaml"), []byte("version: 1\ncases: [\"different from source\"]\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	auditOut := t.TempDir()
	out, err := runAuditBundle(t, fixture, auditOut)
	if err != nil {
		t.Fatalf("audit_bundle.sh should still succeed on a legitimate source/dist claims divergence, got error: %v\n%s", err, out)
	}

	provenancePath := filepath.Join(auditOut, "evidence", "CLAIMS_PROVENANCE.txt")
	provenance, rerr := os.ReadFile(provenancePath)
	if rerr != nil {
		t.Fatalf("expected evidence/CLAIMS_PROVENANCE.txt to exist and record the divergence: %v", rerr)
	}
	if !strings.Contains(string(provenance), "DIVERGENT") {
		t.Fatalf("expected CLAIMS_PROVENANCE.txt to flag the divergence as DIVERGENT, got:\n%s", provenance)
	}

	if _, statErr := os.Stat(filepath.Join(auditOut, "evidence", "claims.yaml")); !os.IsNotExist(statErr) {
		t.Fatalf("evidence/ must never carry an unlabeled third claims.yaml copy (stat err=%v)", statErr)
	}
}
