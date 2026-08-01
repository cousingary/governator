package runtime

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	goruntime "runtime"
	"testing"
)

func TestExecutionIdentityV2BindsExactPromptAndParticipants(t *testing.T) {
	base := ExecutionIdentity{ContractHash: "c", ExactPromptHash: "p1", StrictReplayEligible: true, Participants: map[string]ExecutableIdentity{"backend": {Role: "backend", SHA256: "a", Known: true}}}
	changed := base
	changed.ExactPromptHash = "p2"
	if base.Hash() == changed.Hash() {
		t.Fatal("model-visible prompt change did not invalidate identity")
	}
	changed = base
	changed.Participants = map[string]ExecutableIdentity{"backend": {Role: "backend", SHA256: "b", Known: true}}
	if base.Hash() == changed.Hash() {
		t.Fatal("participant bytes change did not invalidate identity")
	}
}

func TestUnknownRequiredParticipantDisablesStrictReplay(t *testing.T) {
	items := map[string]ExecutableIdentity{}
	for _, role := range participantRoles {
		items[role] = notApplicable(role)
	}
	items["git"] = ExecutableIdentity{Role: "git"}
	if err := validateParticipants(items); err == nil {
		t.Fatal("unknown required participant compared as equal")
	}
}

func TestSealedArtifactStagesCapturedBytes(t *testing.T) {
	if goruntime.GOOS != "linux" {
		t.Skip("sealed artifact staging requires Linux openat2")
	}
	data := []byte("before replay")
	sum := sha256.Sum256(data)
	a := stagedArtifact{Name: "a.txt", Path: ".governator/consumed/a.txt", SHA256: hex.EncodeToString(sum[:]), Bytes: int64(len(data)), data: append([]byte(nil), data...)}
	dir := filepath.Join(t.TempDir(), ".governator", "consumed")
	if _, err := stageConsumedArtifacts(dir, []stagedArtifact{a}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "a.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(data) {
		t.Fatalf("staged %q", got)
	}
	a.data[0] = 'X'
	if _, err := stageConsumedArtifacts(t.TempDir(), []stagedArtifact{a}); err == nil {
		t.Fatal("mutated sealed bytes were accepted")
	}
}

func TestTransactionSnapshotDeepCopiesTrustInputs(t *testing.T) {
	patterns := []string{"secret/**"}
	data := []byte("sealed")
	parts := map[string]ExecutableIdentity{"backend": {Role: "backend", SHA256: "abc", Known: true}}
	s := newTransactionSnapshot("c", "cfg", patterns, "g", "prompt", "env", "cred", parts, []stagedArtifact{{Name: "a", data: data}})
	patterns[0] = "changed"
	data[0] = "X"[0]
	parts["backend"] = ExecutableIdentity{}
	if s.ProtectedPatterns[0] != "secret/**" || string(s.Artifacts[0].data) != "sealed" || !s.Participants["backend"].Known {
		t.Fatal("transaction snapshot aliases mutable construction inputs")
	}
}
