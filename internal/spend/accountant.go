package spend

import (
	"database/sql"
	"fmt"
	"sync"

	"github.com/cousingary/governator/internal/config"
)

// Accountant coordinates in-process spend reservations across a batch's
// concurrent workers sharing one daily cap. CheckBudget alone isn't enough
// for gov batch: it reads the ledger, which excludes RUNNING rows, so two
// workers launched back to back would both pass CheckBudget before either's
// cost has landed. Accountant closes that gap — every worker reserves a
// conservative estimate here before calling Run, and settles it against the
// real cost_usd once Run returns, all funnelled through one mutex so the
// running total is exact regardless of goroutine interleaving. It is
// deliberately in-process only: gov batch is a single `gov` invocation, and
// nothing here is shared across separate `gov batch run` processes.
type Accountant struct {
	cfg config.Config

	mu      sync.Mutex
	spent   float64 // ledger baseline at construction, plus every settled actual since
	pending float64 // sum of outstanding reservations not yet settled
}

// NewAccountant seeds the accountant from today's ledger total, so a batch
// run respects spend already recorded before (and outside) this batch.
func NewAccountant(cfg config.Config, ledger *sql.DB) (*Accountant, error) {
	today, err := TodaySpend(ledger)
	if err != nil {
		return nil, err
	}
	return &Accountant{cfg: cfg, spent: today.TotalCostUSD}, nil
}

// Reserve attempts to reserve estimate dollars against the cap. ok=false
// means refuse — the caller must not launch the job — with a reason in the
// same shape CheckBudget uses, so callers can report it as SPEND_CAP too.
func (a *Accountant) Reserve(estimate float64) (ok bool, reason string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if IsHalted(a.cfg) {
		return false, fmt.Sprintf("halt file present: %s", a.cfg.Spend.HaltFile)
	}
	if a.cfg.Spend.DailyCapUSD <= 0 {
		a.pending += estimate
		return true, ""
	}
	committed := a.spent + a.pending
	if committed+estimate > a.cfg.Spend.DailyCapUSD {
		return false, fmt.Sprintf("daily spend $%.4f (settled+reserved) + estimate $%.4f > cap $%.2f",
			committed, estimate, a.cfg.Spend.DailyCapUSD)
	}
	a.pending += estimate
	return true, ""
}

// Settle releases a reservation and books the real cost (0 if the job never
// ran or produced no billable cost) against the running total, so later
// Reserve calls in this batch see true spend rather than the estimate.
func (a *Accountant) Settle(reserved, actual float64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pending -= reserved
	if a.pending < 0 {
		a.pending = 0
	}
	a.spent += actual
}

// Spent reports settled spend only (not outstanding reservations), for the
// batch summary.
func (a *Accountant) Spent() float64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.spent
}
