package observability

import (
	"database/sql"
	"testing"
	"time"
)

func openEffectsTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestRecordEffects_EmptyIsNoop(t *testing.T) {
	db := openEffectsTestDB(t)
	if err := RecordEffects(db, nil); err != nil {
		t.Fatalf("RecordEffects(nil): %v", err)
	}
	got, err := EffectsForRun(db, "run-none")
	if err != nil {
		t.Fatalf("EffectsForRun: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("EffectsForRun after empty RecordEffects = %v, want none", got)
	}
}

func TestRecordEffects_RoundTripsInOrder(t *testing.T) {
	db := openEffectsTestDB(t)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	records := []EffectRecord{
		{RunID: "run-a", Kind: EffectProcessCreation, Detail: `{"processes_observed_peak":3}`, Created: now},
		{RunID: "run-a", Kind: EffectExecutableLaunch, Detail: `{"sha256":"deadbeef"}`, Created: now},
		{RunID: "run-a", Kind: EffectNetwork, Detail: `{"namespaced":true}`, Created: now},
		{RunID: "run-b", Kind: EffectNetwork, Detail: `{"namespaced":false}`, Created: now},
	}
	if err := RecordEffects(db, records); err != nil {
		t.Fatalf("RecordEffects: %v", err)
	}
	got, err := EffectsForRun(db, "run-a")
	if err != nil {
		t.Fatalf("EffectsForRun: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("EffectsForRun(run-a) = %d records, want 3: %+v", len(got), got)
	}
	wantKinds := []EffectKind{EffectProcessCreation, EffectExecutableLaunch, EffectNetwork}
	for i, k := range wantKinds {
		if got[i].Kind != k {
			t.Fatalf("record %d kind = %s, want %s", i, got[i].Kind, k)
		}
	}
	gotB, err := EffectsForRun(db, "run-b")
	if err != nil {
		t.Fatalf("EffectsForRun(run-b): %v", err)
	}
	if len(gotB) != 1 || gotB[0].Detail != `{"namespaced":false}` {
		t.Fatalf("EffectsForRun(run-b) = %+v, want the one run-b record untouched by run-a's rows", gotB)
	}
}

func TestRecordEffects_UnknownRunIDIsEmptyNotError(t *testing.T) {
	db := openEffectsTestDB(t)
	got, err := EffectsForRun(db, "never-recorded")
	if err != nil {
		t.Fatalf("EffectsForRun: %v", err)
	}
	if got != nil {
		t.Fatalf("EffectsForRun(unknown) = %+v, want nil", got)
	}
}
