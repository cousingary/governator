//go:build integration

package assay

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/cousingary/governator/internal/toolregistry"
)

func writeArtifact(t *testing.T, dir, content string) (path, sha string) {
	t.Helper()
	path = filepath.Join(dir, "artifact.json")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(content))
	return path, hex.EncodeToString(sum[:])
}

func buildTestSnapshot(t *testing.T, repo string) *Snapshot {
	t.Helper()
	registry, err := toolregistry.Load()
	if err != nil {
		t.Fatalf("load trusted-tool registry: %v", err)
	}
	snap, err := BuildSnapshot(registry, Config{Repo: repo, Python: "python3"})
	if err != nil {
		t.Fatalf("build assayer execution snapshot for %s: %v", repo, err)
	}
	t.Cleanup(snap.Close)
	return snap
}

func baseRequest(sha string) Request {
	payload, _ := json.Marshal(map[string]any{
		"content": "This is a sufficiently long piece of real generated content for the check.",
	})
	return Request{
		RunID: "run-1", AttemptID: "run-1", JobID: "job-1", ContractHash: "deadbeef",
		JobType: "coding", Backend: "claude-code", ArtifactName: "output", ArtifactSHA256: sha,
		Payload: payload, CheckProfile: "coding-output-v1", PolicyVersion: "test-v1",
	}
}
