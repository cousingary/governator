//go:build redteam

package redteam

import (
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/cousingary/governator/internal/contracts"
	"github.com/cousingary/governator/internal/toolregistry"
)

func TestV8Case14AssayerBranchAdvanceInvalidatesReplay(t *testing.T) {
	TestV7Case25AssayerCommitChangeInvalidatesReplay(t)
}

func TestV8Case16CleanupInterpreterSwapInvalidatesReplay(t *testing.T) {
	strictReplayConfig(t)
	root := fixtureRepo(t)
	home := t.TempDir()

	registryFile := filepath.Join(t.TempDir(), "tools.yaml")
	t.Setenv("GOV_TOOLREGISTRY_FILE", registryFile)
	strictReplayEnrollControllerTools(t)

	testPath, err := exec.LookPath("test")
	if err != nil {
		testPath = "/usr/bin/test"
	}
	cleanupToolA := copyToNewInode(t, testPath)
	if _, err := toolregistry.Enroll("cleanup-tool", cleanupToolA); err != nil {
		t.Fatal(err)
	}

	c := strictReplayContract(root)
	c.Cleanup = &contracts.Cleanup{
		Validators: []string{"test -f output/result.txt"},
		ValidatorSpecs: []contracts.ValidatorSpec{{
			Command: "test -f output/result.txt",
			Tools:   []string{"cleanup-tool"},
		}},
	}
	bin := fakeBackend(t, standardBackendBody(""))

	runStrictReplayBaseline(t, home, bin, c)

	cleanupToolB := copyToNewInode(t, testPath)
	if _, err := toolregistry.Enroll("cleanup-tool", cleanupToolB); err != nil {
		t.Fatal(err)
	}

	r3 := runGoverned(t, home, bin, c)
	if r3.Replayed {
		t.Fatal("run 3 replayed a stale approval after the cleanup validator's declared tool was re-enrolled at a different verified path -- replay identity does not bind the structured cleanup validator toolset")
	}
}

func TestV8Case24NoApplicableChecksBlockApproval(t *testing.T) {
	TestV7Case38NoApplicableChecksBlocksApproval(t)
}
