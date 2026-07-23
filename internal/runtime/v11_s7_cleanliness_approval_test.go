// v11_s7_cleanliness_approval_test.go implements the integration half of
// Sol11 rc5 Session 7's P1-2 mandatory red-team corpus
// (agents/governator-sol-upgrade11.md "P1-2: Failure to prove Assayer
// cleanliness is treated as clean", agents/governator-sol-upgrade11-rc5-plan.md
// Session 7, manifest case 189 / report corpus 40: "unknown cleanliness
// disables replay"). internal/assay's own v11_s7_cleanliness_test.go proves
// snapshotDirty's tri-state directly (corpus 37-39); this case proves the
// consequence Sol11 P1-2 also requires -- that an indeterminate
// (CleanlinessUnknown) Assayer checkout does not merely disable strict
// replay, it must block merge/approval outright, exactly like case
// 12/TestV11Case12LocalEffectfulTieringOffCannotReachApprovedOrMerge's
// existing dev-mode pattern in internal/redteam. That assertion needs the
// full runOnce merge/approval pipeline (assaySnapshot, violations, the
// pre-merge check added to runtime.go), which does not belong in
// internal/assay (that package's TestMain forces
// enforce.ForceUnsupported -- see assay_test.go's doc comment).
package runtime

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestV11Case44UnknownAssayerCleanlinessCannotMergeOrApprove is corpus 40.
// The Assayer checkout pointed at by GOV_ASSAY_REPO has a real `.git` entry
// that is NOT a real, resolvable git repository (git status fails against
// it, not merely absent) -- BuildSnapshot's snapshotDirty must report
// CleanlinessUnknown, not the pre-P1-2 silent CleanlinessClean. Even though
// the stub Assayer itself returns a clean PASS verdict for the one produced
// artifact, the run must still not reach APPROVED, and -- matching case
// 12's exact requirement for its own non-approving mode -- the merge itself
// must never execute: a fix that only changes the final status after the
// merge already landed would leave indeterminate-checkout work on the live
// root before retroactively quarantining it.
func TestV11Case44UnknownAssayerCleanlinessCannotMergeOrApprove(t *testing.T) {
	root, _ := fixture(t)
	writeArtifactSchema(t, root)
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)

	assayerRepo := writeAssayerStub(t, stubPassVerdict)
	// A `.git` entry exists (so BuildSnapshot's snapshotDirty does not take
	// the "no .git at all -> unambiguously clean" short-circuit) but it is
	// not a real repository -- `git status --porcelain` against it fails,
	// which is exactly the indeterminate condition this case exercises.
	if err := os.Mkdir(filepath.Join(assayerRepo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	setAssayEnv(t, assayerRepo)

	bin := writeFakeBackend(t, `mkdir -p output .governator/artifacts
printf 'ok\n' > output/result.txt
printf '{"summary":"ok"}' > .governator/artifacts/scout.json
printf '{"status":"complete","files_changed":["output/result.txt"],"commands_run":0,"validation":{"self_checked":true},"violations":[],"blockers":[],"next_recommended_action":"none"}\n' > RESULT.json
printf '{"type":"result","total_cost_usd":0.05}\n'
`)
	t.Setenv("GOV_CLAUDE_BIN", bin)
	promptRoot := t.TempDir()
	writePrompt(t, promptRoot, "claude-code", "surgeon")
	t.Setenv("GOV_PROMPTS", promptRoot)

	c := assayProducerContract(root, "blocking")

	rec, err := New().Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status == "APPROVED" {
		t.Fatalf("run reached APPROVED with an indeterminate (unknown) Assayer checkout cleanliness -- an indeterminate checkout must never be treated as clean (status=%s message=%s)", rec.Status, rec.Message)
	}
	if !strings.Contains(rec.Message, "cleanliness is unknown") {
		t.Fatalf("expected the quarantine reason to name the unknown-cleanliness violation, got message=%q", rec.Message)
	}
	if _, err := os.Stat(filepath.Join(root, "output", "result.txt")); err == nil {
		t.Fatal("an indeterminate-cleanliness run merged effectful work into the live root before quarantining -- merge must be skipped entirely, not merely marked non-approving after the merge already ran")
	}
}
