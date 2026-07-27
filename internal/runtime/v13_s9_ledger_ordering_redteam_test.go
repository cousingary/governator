//go:build redteam

// v13_s9_ledger_ordering_redteam_test.go implements Sol13 rc6 corpus case 298.
//
// Session 9 found that TestV6Case22's intermittent failure under full-tier
// concurrency was NOT host contention, as the prior handoff and docs/security.md
// had classified it. It was a real correctness defect.
//
// runs.created (and capability_attestations.created_at) are TEXT columns
// written with time.RFC3339Nano. That layout is "...05.999999999Z07:00" -- the
// 9s mean trailing zeros in the fractional second are TRIMMED. SQLite compares
// TEXT lexicographically, so whenever an earlier timestamp's fraction is a
// prefix of a later one's, byte order inverts chronological order, because 'Z'
// (0x5A) sorts above every digit and above '.' (0x2E):
//
//	earlier "2026-07-27T12:00:00Z"      >  later "2026-07-27T12:00:00.5Z"
//	earlier "2026-07-27T12:00:00.123Z"  >  later "2026-07-27T12:00:00.1234567Z"
//
// `ORDER BY created DESC LIMIT 1` therefore returned the OLDER approved run and
// staged a STALE consumed artifact -- exactly the property TestV6Case22 exists
// to defend. It only surfaced under load because the trap requires the earlier
// timestamp to have trailing zeros trimmed, which a contended, coarsened clock
// produces far more often than an idle fine-grained one. That is why the test
// was green 5/5 in isolation and failed in the full tier, and why "re-run until
// green" would have shipped the bug.
//
// The fix orders by rowid instead. rowid is the run row's insertion order --
// identical semantics to created (both recorded at run start), but monotonic
// and immune to the text format. rowid must be the PRIMARY sort key: appending
// it as a tiebreak after created would never fire, because the defect is a
// mis-compare, not a tie.
//
// This case pins the property deterministically. The two timestamps below arm
// the trap by construction, so this test fails 100% of the time against the
// pre-fix query rather than probabilistically under concurrency.
package runtime

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cousingary/governator/internal/contracts"
	"github.com/cousingary/governator/internal/observability"
)

func TestV13Case298ConsumedArtifactSelectionIsNotLexicographicOnRFC3339Nano(t *testing.T) {
	// Earlier run, whose all-zero fraction RFC3339Nano trims away entirely.
	const olderCreated = "2026-07-27T12:00:00Z"
	// Later run (by 500ms), whose fraction survives.
	const newerCreated = "2026-07-27T12:00:00.5Z"

	// Premise 1: newerCreated really is chronologically later.
	older, err := time.Parse(time.RFC3339Nano, olderCreated)
	if err != nil {
		t.Fatalf("parse olderCreated: %v", err)
	}
	newer, err := time.Parse(time.RFC3339Nano, newerCreated)
	if err != nil {
		t.Fatalf("parse newerCreated: %v", err)
	}
	if !newer.After(older) {
		t.Fatalf("premise broken: %q is not chronologically after %q", newerCreated, olderCreated)
	}

	// Premise 2: the trap is armed -- lexicographically the EARLIER string
	// sorts higher, so `ORDER BY created DESC` would pick the older run. If
	// this ever stops holding, the case is no longer testing anything and
	// must be re-derived rather than silently passing.
	if !(olderCreated > newerCreated) {
		t.Fatalf("premise broken: lexicographic trap not armed -- %q must sort above %q for this case to exercise the defect", olderCreated, newerCreated)
	}

	home := t.TempDir()
	db, err := observability.Open(home)
	if err != nil {
		t.Fatalf("open ledger: %v", err)
	}
	defer db.Close()

	artifactsRoot := filepath.Join(home, "artifacts")
	if err := os.MkdirAll(artifactsRoot, 0o755); err != nil {
		t.Fatalf("mkdir artifacts root: %v", err)
	}
	writeArtifact := func(diskName, content string) (string, string, int64) {
		p := filepath.Join(artifactsRoot, diskName)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", diskName, err)
		}
		sum := sha256.Sum256([]byte(content))
		return p, hex.EncodeToString(sum[:]), int64(len(content))
	}
	stalePath, staleSHA, staleBytes := writeArtifact("stale.txt", "v1")
	freshPath, freshSHA, freshBytes := writeArtifact("fresh.txt", "v2")

	const producer = "v13-case298-producer"
	addRun := func(runID, created, path, sha string, size int64) {
		if _, err := db.Exec(
			`INSERT INTO runs(id,job_id,job_type,agent,mode,status,created) VALUES(?,?,'test','claude-code','surgeon','APPROVED',?)`,
			runID, producer, created); err != nil {
			t.Fatalf("insert run %s: %v", runID, err)
		}
		if _, err := db.Exec(
			`INSERT INTO artifacts(run_id,name,path,sha256,bytes,schema_ok,created) VALUES(?,'art',?,?,?,1,?)`,
			runID, path, sha, size, created); err != nil {
			t.Fatalf("insert artifact for %s: %v", runID, err)
		}
	}
	// Inserted in true chronological order, so rowid order is the correct
	// order and `created` byte order is the inverted one.
	addRun("run-older", olderCreated, stalePath, staleSHA, staleBytes)
	addRun("run-newer", newerCreated, freshPath, freshSHA, freshBytes)

	got, err := consumedArtifactIdentities(db, home, contracts.Contract{
		Consumes:        []string{"art"},
		ArtifactSources: map[string]string{"art": producer},
	})
	if err != nil {
		t.Fatalf("consumedArtifactIdentities: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 staged artifact, got %d", len(got))
	}
	if got[0].SHA256 == staleSHA {
		t.Fatalf("consumed artifact resolution served the STALE artifact from the older approved run "+
			"(sha=%s, content=%q) -- 'latest approved' was decided by lexicographic order on an "+
			"RFC3339Nano TEXT column, which inverts chronological order when the earlier timestamp's "+
			"fraction is trimmed. Order by rowid, not created.", staleSHA, "v1")
	}
	if got[0].SHA256 != freshSHA {
		t.Fatalf("consumed artifact sha256 = %s, want %s (the newer approved run's artifact)", got[0].SHA256, freshSHA)
	}
	if string(got[0].data) != "v2" {
		t.Fatalf("consumed artifact content = %q, want %q", string(got[0].data), "v2")
	}
	if got[0].Bytes != freshBytes {
		t.Fatalf("consumed artifact bytes = %d, want %d", got[0].Bytes, freshBytes)
	}
}
