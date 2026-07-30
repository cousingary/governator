//go:build redteam

package redteam

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cousingary/governator/internal/config"
	"github.com/cousingary/governator/internal/dbtime"
	"github.com/cousingary/governator/internal/observability"
	"github.com/cousingary/governator/internal/quota"
	_ "modernc.org/sqlite"
)

// v15QuotaTimestampBoundaryCases is Sol15 P0-3's mandatory regression matrix:
// every value must be rejected at config load with a controlled error naming
// the field and the supported range, or accepted -- never panic, never
// silently substituted (upgrade-14's silent-zero-time substitution was
// already closed by Sol P1.2; this session closes the panic on the values
// that parse but fall outside dbtime's supported range).
type v15QuotaTimestampBoundaryCase struct {
	value      string
	wantAccept bool
}

func v15QuotaTimestampBoundaryMatrix() []v15QuotaTimestampBoundaryCase {
	return []v15QuotaTimestampBoundaryCase{
		{"0001-01-01T00:00:00Z", false},
		{"1677-09-20T00:00:00Z", false},
		{"1677-09-21T00:00:00Z", false},
		{"1970-01-01T00:00:00Z", true},
		{"2262-04-11T00:00:00Z", true},
		{"2262-04-12T00:00:00Z", false},
		{"2263-01-01T00:00:00Z", false},
		{"9999-01-01T00:00:00Z", false},
	}
}

func runV15QuotaTimestampBoundaryMatrix(t *testing.T) {
	t.Helper()
	for _, tc := range v15QuotaTimestampBoundaryMatrix() {
		t.Run(tc.value, func(t *testing.T) {
			t.Setenv("GOV_CONFIG", writeV15QuotaConfig(t, tc.value))
			_, err := config.LoadStrict()
			if tc.wantAccept {
				if err != nil {
					t.Fatalf("expected %s to be accepted, got: %v", tc.value, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected %s to be rejected at config load (not silently accepted, and never reaching quota.SeedFromConfig to panic)", tc.value)
			}
			if !strings.Contains(err.Error(), "quotas[0].reset_at") {
				t.Fatalf("error does not name the field path quotas[0].reset_at: %v", err)
			}
			if !strings.Contains(err.Error(), tc.value) {
				t.Fatalf("error does not name the rejected value %s: %v", tc.value, err)
			}
		})
	}
}

func writeV15QuotaConfig(t *testing.T, resetAt string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	body := fmt.Sprintf("quotas: [{backend: codex, window_type: daily, estimated_limit: 100, confidence: 0.5, reset_at: %q}]\n", resetAt)
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestV15Case345QuotaConfigResetAtYear9999IsRejectedAtLoadNotPanicked is
// Sol15's original reproduction: reset_at: "9999-01-01" used to load without
// error and panic deep inside quota.SeedFromConfig via quota.mustNanos.
func TestV15Case345QuotaConfigResetAtYear9999IsRejectedAtLoadNotPanicked(t *testing.T) {
	runV15QuotaTimestampBoundaryMatrix(t)
}

func TestV15Case346QuotaConfigResetAtYear0001IsRejectedAtLoadNotPanicked(t *testing.T) {
	runV15QuotaTimestampBoundaryMatrix(t)
}

func TestV15Case347NanosecondUpperBoundMinusOneIsAccepted(t *testing.T) {
	runV15QuotaTimestampBoundaryMatrix(t)
}

func TestV15Case348NanosecondUpperBoundPlusOneIsRejected(t *testing.T) {
	runV15QuotaTimestampBoundaryMatrix(t)
}

// TestV15Case349NegativeQuotaTTLIsRejectedAtConfigLoad: quota.Reserve's and
// spend.ReserveGlobal's TTL is derived entirely from
// (defaults.max_minutes+5)*time.Minute in internal/runtime/runtime.go --
// there is no separate operator-facing TTL field. The only way a negative
// TTL can ever reach Reserve is a negative max_minutes, and Sol P1.2 already
// made that fail at config load. This proves the invariant end to end
// (config -> the value that actually seeds Reserve's ttl parameter) rather
// than re-deriving it.
func TestV15Case349NegativeQuotaTTLIsRejectedAtConfigLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("defaults: {max_minutes: -5}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_CONFIG", path)
	_, err := config.LoadStrict()
	if err == nil {
		t.Fatal("expected a negative defaults.max_minutes to be rejected at config load -- it is the sole source of quota.Reserve's TTL")
	}
	if !strings.Contains(err.Error(), "max_minutes") {
		t.Fatalf("error does not name max_minutes: %v", err)
	}
}

// TestV15Case350MaximumDurationAdditionReturnsOverflowErrorNotWrappedTime:
// now+ttl must not silently wrap past dbtime's supported range. Before this
// session, quota.Reserve's expires_unix_nano column was written via the
// panicking mustNanos; a TTL large enough to push the expiry past
// MaxSupportedTime is exactly the "reset hint plus TTL overflow" class in
// Sol's mandatory matrix.
func TestV15Case350MaximumDurationAdditionReturnsOverflowErrorNotWrappedTime(t *testing.T) {
	db := openV14SpendLedger(t)
	defer db.Close()
	now := dbtime.MaxSupportedTime.Add(-time.Hour)
	seedQuotaWindow(t, db, "claude", now.Add(-24*time.Hour), dbtime.MaxSupportedTime, 1000)

	_, err := quota.Reserve(db, "claude", "default", "run-350", 10, 2*time.Hour, now)
	if err == nil {
		t.Fatal("expected a TTL that pushes the reservation's expiry past the supported range to fail")
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM quota_reservations WHERE run_id='run-350'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("overflowing reservation was persisted anyway: %d rows", count)
	}
}

// TestV15Case352CorruptNumericLedgerTimestampReturnsTypedCorruptionError:
// hand-corrupt only the numeric mirror of a quota_windows row (the text
// column still reads the real value) and confirm an authority path
// (quota.Reserve, via windowsFor) fails closed with dbtime.ErrCorruptTimestamp
// while a read path (quota.Windows, the `gov quota` listing) skips the row
// instead of hiding every window behind the one bad one.
func TestV15Case352CorruptNumericLedgerTimestampReturnsTypedCorruptionError(t *testing.T) {
	db := openV14SpendLedger(t)
	defer db.Close()
	now := time.Date(2026, 7, 28, 0, 0, 0, 0, time.UTC)
	reset := now.Add(24 * time.Hour)
	seedQuotaWindow(t, db, "claude", now, reset, 1000)
	if _, err := db.Exec(`UPDATE quota_windows SET reset_unix_nano=reset_unix_nano+1 WHERE backend='claude'`); err != nil {
		t.Fatal(err)
	}

	_, err := quota.Reserve(db, "claude", "default", "run-352", 10, time.Hour, now)
	if err == nil {
		t.Fatal("expected a corrupt numeric ledger timestamp to fail closed on an authority path")
	}
	if !errors.Is(err, dbtime.ErrCorruptTimestamp) {
		t.Fatalf("expected ErrCorruptTimestamp, got: %v", err)
	}

	windows, err := quota.Windows(db, now)
	if err != nil {
		t.Fatalf("Windows (a read path) must skip the corrupt row rather than fail closed, got: %v", err)
	}
	if len(windows) != 0 {
		t.Fatalf("expected the corrupt row to be skipped from the read-path listing, got %+v", windows)
	}
}

// TestV15Case353MigratedOutOfRangeTextualTimestampFailsClosed: a legacy text
// timestamp that merely parses (RFC3339) but falls outside dbtime's
// supported range must abort observability.Open (the numeric-authority
// backfill migration re-runs on every Open, not just first creation) rather
// than being silently accepted into the numeric ledger. This documents
// behavior migrateSpendQuotaTimes already has (rc7 Session 2's fail-closed
// rule) -- Session 1 adds the regression proof the corpus was missing.
func TestV15Case353MigratedOutOfRangeTextualTimestampFailsClosed(t *testing.T) {
	home := t.TempDir()
	db, err := observability.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 28, 0, 0, 0, 0, time.UTC)
	seedQuotaWindow(t, db, "claude", now, now.Add(24*time.Hour), 1000)
	if _, err := db.Exec(`UPDATE quota_windows SET reset_at='9999-01-01T00:00:00Z' WHERE backend='claude'`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := observability.Open(home); err == nil {
		t.Fatal("expected re-opening the ledger to fail closed on an out-of-range migrated textual timestamp")
	} else if !strings.Contains(err.Error(), "reset_at") {
		t.Fatalf("error does not name reset_at: %v", err)
	}
}
