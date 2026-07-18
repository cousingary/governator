//go:build integration

package assay

// TestEvaluateAgainstRealCLIPassAndFail exercises the real Assayer `evaluate`
// subcommand end to end (as opposed to every other test in this package,
// which drives a stub subprocess). It is split into its own file behind the
// `integration` build tag so it is a separate, mandatory CI tier rather than
// part of the fast default `go test ./...` unit run (plan Session 2 item 2:
// "Keep the existing fast stub-subprocess unit tests as a separate, still-
// always-run tier").
//
// The fixture it runs against — testdata/assayer_fixture/ — is a pinned,
// checked-in copy of the real Assayer repo's cli.py + assayer/ package
// (source commit recorded in testdata/assayer_fixture/PINNED_COMMIT). It
// replaces the old behavior of copying from a live sibling checkout at
// /mnt/e/downloads/assayer and skipping the test outright if that path
// didn't exist on the machine (t.Skipf) — the exact silent-skip behavior the
// plan requires to stop being acceptable in CI. There is nothing left to
// skip: the fixture ships in this repo, so a missing/broken fixture or a
// missing python3 interpreter is a hard test failure (t.Fatal), never t.Skip.
//
// Rationale for a checked-in fixture over a submodule/CI checkout: the real
// Assayer repo (/mnt/e/downloads/assayer) has no git remote today (confirmed
// via `git remote -v`), so a submodule or `git clone` checkout step in CI is
// not viable. The evaluate path is also fully offline/stdlib-only (see
// internal/assay/assay.go's package doc and cli.py's own docstring: it never
// imports `supabase` — that import is lazy, inside Store.client — and never
// touches the network), so a small pinned fixture is sufficient to exercise
// the real CLI contract without vendoring the whole app (schema.sql,
// tests/, the Supabase-backed quarantine/store commands are all out of scope
// for what Evaluate() calls).
import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/cousingary/governator/internal/enforce"
)

func fixtureAssayerRepo(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("testdata", "assayer_fixture"))
	if err != nil {
		t.Fatalf("resolve fixture path: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "cli.py")); err != nil {
		t.Fatalf("pinned assayer fixture missing or broken at %s: %v (this is a mandatory CI failure, not a skip)", dir, err)
	}
	return dir
}

func TestEvaluateAgainstRealCLIPassAndFail(t *testing.T) {
	requirePython3Mandatory(t)
	if !enforce.Supported() {
		t.Skip("this host cannot provide external enforcement (Landlock/unshare unavailable); fail-closed behavior is covered by TestV8Case6AssayerFailsClosedWithoutExternalSandbox")
	}
	repo := fixtureAssayerRepo(t)

	dir := t.TempDir()
	content := `{"content":"This is a real, sufficiently long piece of generated content."}`
	path, sha := writeArtifact(t, dir, content)
	req := baseRequest(sha)
	req.Payload = json.RawMessage(`{"content":"This is a real, sufficiently long piece of generated content."}`)

	v := Evaluate(context.Background(), Config{Repo: repo, Python: "python3"}, req, path)
	if v.Verdict != VerdictPass {
		t.Fatalf("expected pass verdict against real assayer CLI, got %+v", v)
	}
	if v.ChecksResultHash == "" {
		t.Fatal("expected a non-empty checks_result_hash")
	}
	if v.ProfileDefinitionHash == "" {
		t.Fatal("expected a non-empty profile_definition_hash")
	}
	if v.ValidatorImplementationHash == "" {
		t.Fatal("expected a non-empty validator_implementation_hash")
	}
	if v.ValidatorConfigHash == "" {
		t.Fatal("expected a non-empty validator_config_hash")
	}

	// Now a payload missing the required field -> fail.
	badContent := `{}`
	badPath, badSHA := writeArtifact(t, dir, badContent)
	badReq := baseRequest(badSHA)
	badReq.Payload = json.RawMessage(`{}`)

	badV := Evaluate(context.Background(), Config{Repo: repo, Python: "python3"}, badReq, badPath)
	if badV.Verdict != VerdictFail {
		t.Fatalf("expected fail verdict for missing required field, got %+v", badV)
	}
	if len(badV.FailedChecks) == 0 {
		t.Fatal("expected at least one failed check name")
	}
}

// requirePython3Mandatory differs from the fast tier's requirePython3
// (assay_test.go): that one t.Skips, appropriate for an environment gap
// unrelated to the Assayer boundary itself. Here, in the tier the plan
// declares mandatory, "python3 isn't on PATH" IS the blocking Assayer
// boundary failing to execute — so it must fail the job, not skip it.
func requirePython3Mandatory(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("python3"); err != nil {
		t.Fatalf("python3 not available: %v (mandatory integration tier: this must fail CI, not skip)", err)
	}
}
