//go:build redteam

package redteam

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cousingary/governator/internal/contracts"
)

// TestAttack23NonGitMergeFailureHalfwayThrough is report P1-8 / §9 attack
// 23: mergeCopyChanged (internal/runtime/runtime.go) applies approved
// changes to a non-git live root sequentially; an error partway through
// (here: the destination parent for the second file is blocked by a plain
// file where a directory needs to exist) used to leave the root with the
// first file copied and the second missing -- a QUARANTINED run that still
// mutated the live root, not an all-or-nothing merge. Fixed by S7: the
// non-git merge branch already captured a pre-merge recall snapshot
// (captureRecall) but never used it automatically -- rollback was only ever
// operator-triggered, after the fact. runOnce now calls restoreRecall the
// instant the copy/delete loop produces any violation, mirroring the git
// branch's existing rollback-on-violation shape (buildApprovedMergeTree +
// rollbackLiveRoot), and refuses to attempt any copy at all if the snapshot
// itself failed to capture.
//
// Unlike most of this corpus, this attack needs no timing race -- it's
// deterministic filesystem setup -- so the fixture was already real and
// ready to run once the fix landed; only the assertion below (partial
// application must be impossible) needed to flip.
func TestAttack23NonGitMergeFailureHalfwayThrough(t *testing.T) {
	root := t.TempDir()
	// Block the second file's destination directory with a plain file, so
	// os.MkdirAll(filepath.Dir(dst)) fails partway through the sequential
	// copy loop, after the first file has already landed.
	if err := os.WriteFile(filepath.Join(root, "sub"), []byte("blocking file, not a dir\n"), 0644); err != nil {
		t.Fatal(err)
	}

	c := contracts.Contract{
		Task: "non-git merge atomicity fixture", JobID: "redteam-nongit-merge", JobType: "test", Agent: "claude-code", Mode: contracts.ModeSurgeon,
		Workspace:   contracts.Workspace{Root: root, Worktree: "auto"},
		Allowed:     contracts.Permissions{Read: []string{"**"}, Write: []string{"a.txt", "sub/b.txt"}, Execute: []string{"test"}},
		Forbidden:   contracts.Forbidden{Paths: []string{".git/**"}, Commands: []string{"rm -rf"}, Behaviors: []string{"network"}},
		Budget:      contracts.Budget{MaxMinutes: 1, MaxCommands: 5, MaxFilesChanged: 5, MaxLinesChanged: 20, MaxNewFiles: 5, MaxDeleted: 0},
		Preflight:   contracts.Preflight{IntendedWrites: []string{"a.txt", "sub/b.txt"}},
		Success:     contracts.Success{RequiredFiles: []string{"a.txt"}, Validators: []string{"test -f a.txt"}},
		OnViolation: "quarantine",
	}
	bin := fakeBackend(t, `
printf 'a\n' > a.txt
mkdir -p sub
printf 'b\n' > sub/b.txt
printf '{"status":"complete","files_changed":["a.txt","sub/b.txt"],"commands_run":0,"validation":{"self_checked":true},"violations":[],"blockers":[],"next_recommended_action":"none"}\n' > RESULT.json
printf '{"type":"result","total_cost_usd":0.25}\n'
`)

	rec := runGoverned(t, t.TempDir(), bin, c)

	_, aErr := os.Stat(filepath.Join(root, "a.txt"))
	aExists := aErr == nil
	if aExists && rec.Status != "APPROVED" {
		t.Fatalf("partial non-git merge: a.txt landed in the live root but the run was not APPROVED (status=%s message=%s) -- an incomplete merge must never mutate the live root", rec.Status, rec.Message)
	}
}
