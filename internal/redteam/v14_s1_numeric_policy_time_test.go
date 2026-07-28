//go:build redteam

package redteam

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cousingary/governator/internal/dbtime"
	"github.com/cousingary/governator/internal/observability"
	"github.com/cousingary/governator/internal/policy"
	_ "modernc.org/sqlite"
)

func TestV14Case298OlderWholeSecondAllowDoesNotOverrideNewerFractionalDeny(t *testing.T) {
	db := openV14PolicyLedger(t)
	defer db.Close()
	recordV14Override(t, db, "ALLOW", "2026-07-28T00:00:00Z", "")
	recordV14Override(t, db, "DENY", "2026-07-28T00:00:00.5Z", "")

	active, err := observability.ActivePolicyOverrides(db, "job_id:v14", "2026-07-28T00:00:01Z")
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 2 || active[0].Verdict != "DENY" {
		t.Fatalf("newest operator decision was not first: %+v", active)
	}
	resolved, _ := policy.ResolveOverrides(
		[]policy.LayerResult{{Verdict: policy.VerdictAsk, RuleID: "rule", OverrideTarget: "rule"}},
		v14PolicyOverrides(active),
	)
	if len(resolved) != 1 || resolved[0].Verdict != policy.VerdictDeny {
		t.Fatalf("older ALLOW overrode newer DENY: %+v", resolved)
	}
}

func TestV14Case299ExpiredWholeSecondAllowIsInactiveAtLaterFractionalTime(t *testing.T) {
	db := openV14PolicyLedger(t)
	defer db.Close()
	recordV14Override(t, db, "ALLOW", "2026-07-27T23:59:59Z", "2026-07-28T00:00:00Z")
	active, err := observability.ActivePolicyOverrides(db, "job_id:v14", "2026-07-28T00:00:00.5Z")
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 0 {
		t.Fatalf("expired override remained active: %+v", active)
	}
}

func TestV14Case300StaleWholeSecondOneShotReservationIsReclaimedAtFractionalCutoff(t *testing.T) {
	db := openV14PolicyLedger(t)
	defer db.Close()
	if err := observability.RecordPolicyOverride(db, observability.PolicyOverride{
		ScopeKey: "job_id:v14", Target: "rule", Verdict: "ALLOW", OneShot: true,
		CreatedBy: "operator", CreatedAt: "2026-07-27T23:59:59Z",
	}); err != nil {
		t.Fatal(err)
	}
	claimed, err := observability.ClaimActivePolicyOverrides(db, "job_id:v14", "2026-07-28T00:00:00Z")
	if err != nil || len(claimed) != 1 {
		t.Fatalf("initial claim = %+v, err=%v", claimed, err)
	}
	claimed, err = observability.ClaimActivePolicyOverrides(db, "job_id:v14", "2026-07-28T00:30:00.5Z")
	if err != nil {
		t.Fatal(err)
	}
	if len(claimed) != 0 {
		t.Fatalf("stale one-shot became claimable: %+v", claimed)
	}
	var expiredAt string
	if err := db.QueryRow(`SELECT expired_at FROM policy_overrides WHERE id=1`).Scan(&expiredAt); err != nil {
		t.Fatal(err)
	}
	if expiredAt != "2026-07-28T00:30:00.5Z" {
		t.Fatalf("stale reservation expired_at = %q", expiredAt)
	}
}

func TestV14Case301MultipleOverridesInSameSecondResolveByInsertionOrder(t *testing.T) {
	db := openV14PolicyLedger(t)
	defer db.Close()
	recordV14Override(t, db, "ALLOW", "2026-07-28T00:00:00.5Z", "")
	recordV14Override(t, db, "DENY", "2026-07-28T00:00:00.5Z", "")
	active, err := observability.ActivePolicyOverrides(db, "job_id:v14", "2026-07-28T00:00:01Z")
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 2 || active[0].ID <= active[1].ID || active[0].Verdict != "DENY" {
		t.Fatalf("overrides not returned in insertion order newest-first: %+v", active)
	}
	resolved, _ := policy.ResolveOverrides(
		[]policy.LayerResult{{Verdict: policy.VerdictAsk, RuleID: "rule", OverrideTarget: "rule"}},
		v14PolicyOverrides(active),
	)
	if resolved[0].Verdict != policy.VerdictDeny {
		t.Fatalf("latest inserted DENY did not resolve the rule: %+v", resolved)
	}
}

func TestV14Case302PolicyOverrideMigrationFromRc6LedgerPreservesAuthorityOrder(t *testing.T) {
	home := t.TempDir()
	legacy := createV14RC6PolicyLedger(t, home)
	insertV14RC6Override(t, legacy, "ALLOW", "2026-07-28T00:00:00Z", "", "")
	insertV14RC6Override(t, legacy, "DENY", "2026-07-28T00:00:00.5Z", "2026-07-28T01:00:00Z", "2026-07-28T00:10:00Z")
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}

	db, err := observability.Open(home)
	if err != nil {
		t.Fatalf("migrate rc6 ledger: %v", err)
	}
	defer db.Close()
	type row struct {
		createdText, expiresText, reservedText    string
		createdNanos, expiresNanos, reservedNanos int64
	}
	rows, err := db.Query(`SELECT created_at,expires_at,reserved_at,created_unix_nano,expires_unix_nano,reserved_unix_nano FROM policy_overrides ORDER BY id ASC`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []row
	for rows.Next() {
		var value row
		if err := rows.Scan(&value.createdText, &value.expiresText, &value.reservedText, &value.createdNanos, &value.expiresNanos, &value.reservedNanos); err != nil {
			t.Fatal(err)
		}
		got = append(got, value)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("migrated rows = %d, want 2", len(got))
	}
	for i, value := range got {
		if dbtime.UnixNanoToLegacy(value.createdNanos) != value.createdText ||
			dbtime.UnixNanoToLegacy(value.expiresNanos) != value.expiresText ||
			dbtime.UnixNanoToLegacy(value.reservedNanos) != value.reservedText {
			t.Fatalf("row %d did not round-trip: %+v", i+1, value)
		}
	}
	if !(got[0].createdText > got[1].createdText) {
		t.Fatal("fixture no longer arms the RFC3339Nano lexicographic inversion")
	}
	if !(got[0].createdNanos < got[1].createdNanos) {
		t.Fatalf("numeric authority did not restore chronology: %+v", got)
	}
}

func TestV14Case303UnparseableAuthoritativeTimestampFailsBackfillClosed(t *testing.T) {
	home := t.TempDir()
	legacy := createV14RC6PolicyLedger(t, home)
	insertV14RC6Override(t, legacy, "ALLOW", "not-a-timestamp", "", "")
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := observability.Open(home)
	if db != nil {
		db.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "created_at") {
		t.Fatalf("unparseable authoritative timestamp did not fail closed: %v", err)
	}
}

func openV14PolicyLedger(t *testing.T) *sql.DB {
	t.Helper()
	db, err := observability.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func recordV14Override(t *testing.T, db *sql.DB, verdict, created, expires string) {
	t.Helper()
	if err := observability.RecordPolicyOverride(db, observability.PolicyOverride{
		ScopeKey: "job_id:v14", Target: "rule", Verdict: verdict,
		CreatedBy: "operator", CreatedAt: created, ExpiresAt: expires,
	}); err != nil {
		t.Fatal(err)
	}
}

func v14PolicyOverrides(rows []observability.PolicyOverride) []policy.Override {
	out := make([]policy.Override, 0, len(rows))
	for _, row := range rows {
		out = append(out, policy.Override{ID: row.ID, RuleID: row.Target, Verdict: policy.Verdict(row.Verdict), OneShot: row.OneShot})
	}
	return out
}

func createV14RC6PolicyLedger(t *testing.T, home string) *sql.DB {
	t.Helper()
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(home, "ledger.db"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE policy_overrides(
id INTEGER PRIMARY KEY AUTOINCREMENT, scope_key TEXT NOT NULL, target TEXT NOT NULL,
verdict TEXT NOT NULL, reason TEXT NOT NULL DEFAULT '', created_by TEXT NOT NULL DEFAULT '',
created_at TEXT NOT NULL, expires_at TEXT NOT NULL DEFAULT '', one_shot INTEGER NOT NULL DEFAULT 0,
consumed_at TEXT NOT NULL DEFAULT '', reserved_at TEXT NOT NULL DEFAULT '', expired_at TEXT NOT NULL DEFAULT '')`)
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	return db
}

func insertV14RC6Override(t *testing.T, db *sql.DB, verdict, created, expires, reserved string) {
	t.Helper()
	_, err := db.Exec(`INSERT INTO policy_overrides(scope_key,target,verdict,created_by,created_at,expires_at,reserved_at) VALUES('job_id:v14','rule',?,'operator',?,?,?)`, verdict, created, expires, reserved)
	if err != nil {
		t.Fatal(err)
	}
}
