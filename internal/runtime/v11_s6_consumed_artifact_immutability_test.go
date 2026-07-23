//go:build redteam

// v11_s6_consumed_artifact_immutability_test.go implements Sol11 rc5 Session
// 6's mandatory red-team corpus (agents/governator-sol-upgrade11.md "P0-7:
// Consumed artifacts remain transiently mutable at their source",
// agents/governator-sol-upgrade11-rc5-plan.md Session 6, manifest cases
// 181-182 / report corpus 32-33).
//
// The defect: Sol10 P0-1 moved consumed artifacts outside the writable
// worktree and exposed them to the backend/validators only through a
// read-only bind mount -- closing direct overwrite through the MOUNTED path
// (see v10_s1_consumed_artifact_immutability_test.go's cases 1-5). But the
// SOURCE object still lived at consumedArtifactStoreDir(home, runID), an
// ordinary same-UID-writable directory: another process running as
// Governator's own user could modify it after the pre-run hash check, let
// the backend read the changed bytes through the read-only mount, then
// restore the original bytes before the next integrity check -- the mount
// was read-only to the backend, but the underlying host source was never
// immutable to a same-UID sibling process.
//
// The fix (sealConsumedArtifacts/enforce.Plan.WithConsumedArtifacts,
// internal/runtime/artifacts.go): for the landlock-mount-namespace-ro-bind
// boundary, there is no host source directory at all anymore. Every
// consumed artifact exists only as a sealed, unlinked memfd
// (memfd_create + F_SEAL_WRITE|SHRINK|GROW|SEAL, Sol11 P0-6's exact
// precedent) that Governator projects directly into a fresh, private tmpfs
// at launch time -- for the backend's own launch and every validator launch
// alike, regardless of runner kind.
//
// Case 36 is the unit-level kernel-boundary proof, mirroring
// v11_s5_immutable_package_test.go's TestV11Case34 exactly: a same-UID
// process that somehow obtains a descriptor to the sealed memfd (via
// /proc/self/fd/<n>, standing in for /proc/<other-pid>/fd/<n>) still cannot
// write to it -- a strictly stronger adversary model than "races the host
// pathname," since there is no pathname to race in the first place. Case 37
// is the full-pipeline structural proof, mirroring TestV11Case35: after a
// real, governed producer/consumer run under the landlock boundary,
// consumedArtifactStoreDir was never created on disk at all -- there is
// nothing for a same-UID sibling process to locate, alter, or restore.
package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestV11Case36ConsumedArtifactSealedMemfdReopenWriteAttemptRejected is
// report corpus case 32 ("alter the consumed-artifact source only while the
// backend reads it") in its strongest form: even a same-UID process that
// discovers the memfd's descriptor number outright cannot mutate it, so
// there is no window during which an in-flight read could observe altered
// bytes.
func TestV11Case36ConsumedArtifactSealedMemfdReopenWriteAttemptRejected(t *testing.T) {
	original := []byte("original-consumed-artifact-content")
	sum := sha256.Sum256(original)
	sealed, err := sealConsumedArtifacts([]stagedArtifact{{
		Name:   "art",
		SHA256: hex.EncodeToString(sum[:]),
		Bytes:  int64(len(original)),
		data:   original,
	}})
	if err != nil {
		t.Fatalf("sealConsumedArtifacts: %v", err)
	}
	defer closeSealedConsumedArtifacts(sealed)
	if len(sealed) != 1 {
		t.Fatalf("expected 1 sealed artifact, got %d", len(sealed))
	}

	reopened, err := os.OpenFile(fmt.Sprintf("/proc/self/fd/%d", sealed[0].file.Fd()), os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("reopen sealed consumed-artifact memfd via /proc/self/fd: %v", err)
	}
	defer reopened.Close()

	if _, werr := reopened.WriteAt([]byte("MUTATED-BY-SAME-UID-PROCESS"), 0); werr == nil {
		t.Fatal("expected the reopened descriptor's write attempt (simulating a same-UID process that discovered the memfd elsewhere on the host) to fail, got nil error")
	} else if !strings.Contains(werr.Error(), "operation not permitted") {
		t.Fatalf("expected EPERM from the write seal, got %v", werr)
	}

	if verr := verifySealedConsumedArtifacts(sealed); verr != nil {
		t.Fatalf("expected the untampered sealed artifact to still verify clean after a rejected write attempt, got %v", verr)
	}
}

// TestV11Case37ConsumedArtifactStoreNeverCreatedUnderLandlockBoundary is
// report corpus case 33 ("restore the artifact before the post-run hash
// check") in its structural form: under the landlock-mount-namespace-ro-bind
// boundary there is nothing to restore, because
// consumedArtifactStoreDir(home, runID) is never created on disk in the
// first place. Drives a real producer/consumer pair through the actual
// governed pipeline (real Landlock + unshare, via fixture's
// enforce.SelfExeOverride), exactly like TestConsumedArtifactIsStagedReadOnlyForConsumer,
// then confirms the would-be host source directory does not exist -- both
// for the consumer's own run id and for home's "consumed" directory as a
// whole.
func TestV11Case37ConsumedArtifactStoreNeverCreatedUnderLandlockBoundary(t *testing.T) {
	root, _ := fixture(t)
	writeArtifactSchema(t, root)
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)

	producerBin := writeFakeBackend(t, `mkdir -p output .governator/artifacts
printf 'ok\n' > output/result.txt
printf '{"summary":"ok"}' > .governator/artifacts/scout.json
printf '{"status":"complete","files_changed":["output/result.txt"],"commands_run":0,"validation":{"self_checked":true},"violations":[],"blockers":[],"next_recommended_action":"none"}\n' > RESULT.json
printf '{"type":"result","total_cost_usd":0.05}\n'
`)
	t.Setenv("GOV_CLAUDE_BIN", producerBin)
	producer, err := New().Run(context.Background(), artifactProducerContract(root))
	if err != nil || producer.Status != "APPROVED" {
		t.Fatalf("producer status=%s err=%v message=%s", producer.Status, err, producer.Message)
	}

	consumerBin := writeFakeBackend(t, `test -r .governator/consumed/reconnaissance
grep -q '"summary":"ok"' .governator/consumed/reconnaissance
mkdir -p output
printf 'used\n' > output/result.txt
printf '{"status":"complete","files_changed":["output/result.txt"],"commands_run":0,"validation":{"self_checked":true},"violations":[],"blockers":[],"next_recommended_action":"none"}\n' > RESULT.json
printf '{"type":"result","total_cost_usd":0.05}\n'
`)
	t.Setenv("GOV_CLAUDE_BIN", consumerBin)
	consumer := contract(root)
	consumer.JobID = "artifact-consumer-v11s6"
	consumer.Consumes = []string{"reconnaissance"}
	consumer.ArtifactSources = map[string]string{"reconnaissance": "artifact-producer"}

	rec, err := New().Run(context.Background(), consumer)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != "APPROVED" {
		raw, _ := os.ReadFile(rec.Transcript)
		t.Fatalf("consumer status=%s message=%s transcript=%q", rec.Status, rec.Message, raw)
	}

	if _, serr := os.Stat(consumedArtifactStoreDir(home, rec.ID)); !os.IsNotExist(serr) {
		t.Fatalf("expected consumedArtifactStoreDir to have never been created for this run, stat err=%v", serr)
	}
	if _, serr := os.Stat(filepath.Join(home, "consumed")); !os.IsNotExist(serr) {
		t.Fatalf("expected home's consumed directory to have never been created at all, stat err=%v", serr)
	}
}
