//go:build redteam

package redteam

import (
	"math"
	"testing"
)

// TestAttack21HugeTimeoutCausesDurationOverflow is report P1-16 / §9
// attack 21: `time.Duration(maxMinutes) * time.Minute`
// (internal/runtime/runtime.go:1980, and the +5 spend/quota TTL variants)
// overflows int64 for a large enough budget.max_minutes, silently wrapping
// into a bogus (possibly negative or tiny) duration instead of the huge
// timeout the contract author wrote. contracts.Validate() today only
// rejects <= 0 (internal/contracts/schema.go:788) -- no upper bound exists,
// so this value passes validation and reaches the overflowing multiply.
// Fixed by S7: contracts.Validate now enforces MaxSafeBudgetMinutes (an
// explicit schema maximum), and internal/runtime's own conversion uses
// contracts.SafeMinutesDuration (checked arithmetic, refuses rather than
// wraps) as defense in depth for a contract that bypasses Validate
// entirely. Explicit schema maximums were also added for the other counts
// the plan names (commands, files, lines, tokens, artifact bytes).
func TestAttack21HugeTimeoutCausesDurationOverflow(t *testing.T) {
	root := fixtureRepo(t)
	c := baseContract(root)
	c.Budget.MaxMinutes = math.MaxInt32 // (MaxInt32 * time.Minute) already overflows int64.

	if err := c.Validate(); err == nil {
		t.Fatal("expected Validate to reject a budget.max_minutes large enough to overflow its duration conversion, got no error")
	}
}
