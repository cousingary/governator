package observability

import "testing"

func TestPolicyCheckpointLifecycle(t *testing.T) {
	home := t.TempDir()
	db, err := Open(home)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	id, err := RecordPolicyCheckpoint(db, PolicyCheckpoint{
		RunID: "run-1", JobID: "job-1", Target: "cost-threshold", Reason: "estimated cost exceeds cap",
		Sources: "org_policy", PolicyHash: "abc123", CostUSD: 12.5, CreatedAt: "2026-07-12T00:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	if id == 0 {
		t.Fatal("expected a nonzero checkpoint id")
	}

	pending, err := PendingPolicyCheckpoints(db)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].ID != id || pending[0].Status != "pending" {
		t.Fatalf("unexpected pending checkpoints: %+v", pending)
	}

	got, err := PolicyCheckpointByID(db, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.JobID != "job-1" || got.Target != "cost-threshold" || got.CostUSD != 12.5 {
		t.Fatalf("unexpected checkpoint: %+v", got)
	}

	rows, err := ResolvePolicyCheckpoint(db, id, "approved", "operator", "looks fine", "2026-07-12T00:05:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("expected 1 row resolved, got %d", rows)
	}

	got, err = PolicyCheckpointByID(db, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "approved" || got.ResolvedBy != "operator" || got.Resolution != "looks fine" {
		t.Fatalf("unexpected resolved checkpoint: %+v", got)
	}

	pending, err = PendingPolicyCheckpoints(db)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("expected 0 pending after resolution, got %d", len(pending))
	}

	// Resolving an already-resolved checkpoint a second time must be a no-op
	// (0 rows affected), never silently overwrite the first operator's
	// decision.
	rows, err = ResolvePolicyCheckpoint(db, id, "denied", "someone-else", "too late", "2026-07-12T00:06:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Fatalf("expected 0 rows affected resolving an already-resolved checkpoint, got %d", rows)
	}
}

func TestPolicyCheckpointByIDNotFound(t *testing.T) {
	home := t.TempDir()
	db, err := Open(home)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := PolicyCheckpointByID(db, 999); err == nil {
		t.Fatal("expected an error for a nonexistent checkpoint id")
	}
}

func TestActivePolicyOverridesExpiry(t *testing.T) {
	home := t.TempDir()
	db, err := Open(home)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := RecordPolicyOverride(db, PolicyOverride{
		ScopeKey: "job_id:job-1", Target: "cost-threshold", Verdict: "ALLOW", Reason: "approved once",
		CreatedBy: "operator", CreatedAt: "2026-07-12T00:00:00Z", ExpiresAt: "2026-07-12T01:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}
	if err := RecordPolicyOverride(db, PolicyOverride{
		ScopeKey: "job_id:job-1", Target: "network-enablement", Verdict: "ALLOW", Reason: "never expires",
		CreatedBy: "operator", CreatedAt: "2026-07-12T00:00:00Z", ExpiresAt: "",
	}); err != nil {
		t.Fatal(err)
	}

	// Before the first override's expiry, both are active.
	active, err := ActivePolicyOverrides(db, "job_id:job-1", "2026-07-12T00:30:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 2 {
		t.Fatalf("expected 2 active overrides before expiry, got %d: %+v", len(active), active)
	}

	// After the first override's expiry, only the never-expiring one remains.
	active, err = ActivePolicyOverrides(db, "job_id:job-1", "2026-07-12T02:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 1 || active[0].Target != "network-enablement" {
		t.Fatalf("expected only the non-expiring override to remain active, got %+v", active)
	}

	// A different scope key sees nothing.
	active, err = ActivePolicyOverrides(db, "job_id:job-2", "2026-07-12T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 0 {
		t.Fatalf("expected no overrides for an unrelated scope key, got %+v", active)
	}
}
