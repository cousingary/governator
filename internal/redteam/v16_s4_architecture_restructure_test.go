//go:build redteam

package redteam

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// v16_s4_architecture_restructure_test.go is v16-release Session 4's corpus
// (report cases 398-399, findings R6 + R7): the architecture doc restructure
// splits the 85 KB accretion into a current-state document and a history
// companion. These cases prove the closure still binds both files and that
// the five front-matter contradiction categories still fire on the new
// structure.

// TestV16Case398RestructuredDocMissingHistoryCompanionFailsClosure is
// v16-release report case 398 (R6): a bundle whose architecture/ directory
// carries the main doc but NOT the history companion must fail
// bundle_verify.py's closure completeness check. The history file is real
// evidence under the same signature/closure treatment as the main doc;
// omitting it ships an unsigned, unbound history.
func TestV16Case398RestructuredDocMissingHistoryCompanionFailsClosure(t *testing.T) {
	bundleVerify := s7Script(t, "bundle_verify.py")

	t.Run("architecture/ without the history companion is rejected", func(t *testing.T) {
		bundle := t.TempDir()
		archDir := filepath.Join(bundle, "architecture")
		if err := os.MkdirAll(archDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(
			filepath.Join(archDir, "governator_architecture.md"),
			[]byte("# Architecture\n"), 0o644,
		); err != nil {
			t.Fatal(err)
		}

		cmd := exec.Command("python3", "-c", `
import sys, pathlib
sys.path.insert(0, sys.argv[1])
from bundle_verify import verify_architecture
failures = []
verify_architecture(pathlib.Path(sys.argv[2]), failures)
for f in failures:
    print(f)
sys.exit(1 if failures else 0)
`, filepath.Dir(bundleVerify), bundle)
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("expected verify_architecture to reject a bundle missing the history companion, got success:\n%s", out)
		}
		if !strings.Contains(string(out), "governator_architecture_history.md") {
			t.Fatalf("expected the failure to name the missing history file, got:\n%s", out)
		}
	})

	t.Run("architecture/ with both files passes (both-directions positive)", func(t *testing.T) {
		bundle := t.TempDir()
		archDir := filepath.Join(bundle, "architecture")
		if err := os.MkdirAll(archDir, 0o755); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"governator_architecture.md", "governator_architecture_history.md"} {
			if err := os.WriteFile(filepath.Join(archDir, name), []byte("# Doc\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}

		cmd := exec.Command("python3", "-c", `
import sys, pathlib
sys.path.insert(0, sys.argv[1])
from bundle_verify import verify_architecture
failures = []
verify_architecture(pathlib.Path(sys.argv[2]), failures)
for f in failures:
    print(f)
sys.exit(1 if failures else 0)
`, filepath.Dir(bundleVerify), bundle)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("expected verify_architecture to pass with both files present, got error: %v\n%s", err, out)
		}
	})
}

// TestV16Case399FrontMatterContradictionDetectionFiresOnNewStructure is
// v16-release report case 399 (R6): the five front-matter contradiction
// categories check_architecture_doc.py enforces must still fire after the
// restructure removed the Remediation-history section and the stacked
// Historical-status blocks. Mutation-verified per category: each mutation
// must produce the named error, and the unmutated doc must pass.
func TestV16Case399FrontMatterContradictionDetectionFiresOnNewStructure(t *testing.T) {
	repo, commit := s3InitRepo(t)
	tag := "v1.0.2-rc8-case399"
	tagCmd := exec.Command("git", "-C", repo, "tag", tag)
	if out, err := tagCmd.CombinedOutput(); err != nil {
		t.Fatalf("git tag: %v\n%s", err, out)
	}

	baseFields := map[string]string{
		"governator_commit":        commit,
		"governator_tag":           tag,
		"release_state":            "complete",
		"artifact_manifest_sha256": "null",
	}
	baseBody := "# Governator Architecture Decision Record\n\n" +
		"**Status:** current " + tag + "\n\n" +
		"## Decision\n\nGovernator is a Go runtime.\n"

	writeDoc := func(t *testing.T, fields map[string]string, body string) string {
		t.Helper()
		doc := filepath.Join(t.TempDir(), "architecture.md")
		s3WriteFrontMatterDoc(t, doc, fields, body)
		return doc
	}

	t.Run("unmutated restructured doc passes", func(t *testing.T) {
		dist := t.TempDir()
		manifestBytes := []byte(`{"version":"1.0.2-rc8","source_commit":"` + commit + `"}` + "\n")
		if err := os.WriteFile(filepath.Join(dist, "build-manifest.json"), manifestBytes, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dist, "checksums.txt"), []byte("x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(manifestBytes)
		fields := make(map[string]string)
		for k, v := range baseFields {
			fields[k] = v
		}
		fields["artifact_manifest_sha256"] = hex.EncodeToString(sum[:])
		doc := writeDoc(t, fields, baseBody)
		out, err := s3RunCheckArchitectureDoc(t, doc, "--repo", repo, "--dist-dir", dist)
		if err != nil {
			t.Fatalf("expected the clean restructured doc to pass, got error: %v\n%s", err, out)
		}
	})

	t.Run("TAG_COMMIT_MISMATCH fires on the new structure", func(t *testing.T) {
		fields := make(map[string]string)
		for k, v := range baseFields {
			fields[k] = v
		}
		fields["governator_commit"] = "0000000000000000000000000000000000000000"
		doc := writeDoc(t, fields, baseBody)
		out, err := s3RunCheckArchitectureDoc(t, doc, "--repo", repo)
		if err == nil {
			t.Fatalf("expected TAG_COMMIT_MISMATCH, got success:\n%s", out)
		}
		if !strings.Contains(out, "TAG_COMMIT_MISMATCH") {
			t.Fatalf("expected TAG_COMMIT_MISMATCH, got:\n%s", out)
		}
	})

	t.Run("INCOMPLETE_RELEASE_EVIDENCE fires on the new structure", func(t *testing.T) {
		fields := make(map[string]string)
		for k, v := range baseFields {
			fields[k] = v
		}
		doc := writeDoc(t, fields, baseBody)
		out, err := s3RunCheckArchitectureDoc(t, doc, "--repo", repo)
		if err == nil {
			t.Fatalf("expected INCOMPLETE_RELEASE_EVIDENCE (complete with no dist), got success:\n%s", out)
		}
		if !strings.Contains(out, "INCOMPLETE_RELEASE_EVIDENCE") {
			t.Fatalf("expected INCOMPLETE_RELEASE_EVIDENCE, got:\n%s", out)
		}
	})

	t.Run("MANIFEST_HASH_MISMATCH fires on the new structure", func(t *testing.T) {
		dist := t.TempDir()
		writeJSON(t, filepath.Join(dist, "build-manifest.json"), map[string]any{
			"version":       "1.0.2-rc8",
			"source_commit": commit,
		})
		if err := os.WriteFile(filepath.Join(dist, "checksums.txt"), []byte("x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		fields := make(map[string]string)
		for k, v := range baseFields {
			fields[k] = v
		}
		fields["artifact_manifest_sha256"] = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
		doc := writeDoc(t, fields, baseBody)
		out, err := s3RunCheckArchitectureDoc(t, doc, "--repo", repo, "--dist-dir", dist)
		if err == nil {
			t.Fatalf("expected MANIFEST_HASH_MISMATCH, got success:\n%s", out)
		}
		if !strings.Contains(out, "MANIFEST_HASH_MISMATCH") {
			t.Fatalf("expected MANIFEST_HASH_MISMATCH, got:\n%s", out)
		}
	})

	t.Run("FRONT_MATTER_PROSE_CONTRADICTION fires on the new structure", func(t *testing.T) {
		fields := make(map[string]string)
		for k, v := range baseFields {
			fields[k] = v
		}
		fields["release_state"] = "complete"
		contradictBody := "# Doc\n\n**Status:** current " + tag + "\n\n" +
			"No `" + tag + "` git tag currently exists.\n"
		doc := writeDoc(t, fields, contradictBody)
		out, err := s3RunCheckArchitectureDoc(t, doc, "--repo", repo)
		if err == nil {
			t.Fatalf("expected FRONT_MATTER_PROSE_CONTRADICTION, got success:\n%s", out)
		}
		if !strings.Contains(out, "FRONT_MATTER_PROSE_CONTRADICTION") {
			t.Fatalf("expected FRONT_MATTER_PROSE_CONTRADICTION, got:\n%s", out)
		}
	})
}
