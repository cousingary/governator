//go:build redteam

package redteam

import "testing"

// TestAttack20SpendSettleRacesExpiry is report P1-10 / §9 attack 20:
// SettleGlobal (internal/spend/reservation.go) used to read then
// conditionally update a reservation in two separate top-level statements,
// racing expireStaleReservations -- a reservation could be settled and
// independently expired at the same time, silently losing spend accounting
// (the UPDATE matched zero rows with no error surfaced). Fixed by S7:
// SettleGlobal now claims and settles in one transaction via
// UPDATE ... RETURNING (mirroring quota.Settle's existing
// claimReservation shape), so only the transaction that actually moves
// active->settled reads/books the estimate, and a lost race (sql.ErrNoRows)
// is the normal, safe no-op outcome rather than a silent write that never
// happened.
//
// The real regression test lives in internal/spend (this package can't
// import another package's _test.go file, and reliably forcing this
// interleaving needs concurrent goroutines racing against a real SQLite
// connection using internal/spend's own unexported functions -- not
// something this black-box corpus can exercise). This test only proves that
// fixture still exists: internal/spend/sol3_reservation_test.go::
// TestSol3SettleGlobalRacingExpiryNeverSilentlyLosesSettlement.
func TestAttack20SpendSettleRacesExpiry(t *testing.T) {
	assertPackageFileContains(t, "../spend", "sol3_reservation_test.go",
		"func TestSol3SettleGlobalRacingExpiryNeverSilentlyLosesSettlement(",
	)
	assertPackageFileContains(t, "../spend", "reservation.go",
		"RETURNING estimated_usd",
	)
}
