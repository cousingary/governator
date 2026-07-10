package runtime

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cousingary/governator/internal/config"
	"github.com/cousingary/governator/internal/contracts"
	"github.com/cousingary/governator/internal/observability"
	"github.com/cousingary/governator/internal/spend"
)

// BatchJobResult is one job's outcome within a gov batch run.
type BatchJobResult struct {
	JobID    string  `json:"job_id"`
	RunID    string  `json:"run_id,omitempty"`
	Status   string  `json:"status"` // APPROVED, QUARANTINED, SKIPPED (never launched), or ERROR
	Taxonomy string  `json:"failure_taxonomy,omitempty"`
	CostUSD  float64 `json:"cost_usd"`
	Worktree string  `json:"worktree,omitempty"`
	Error    string  `json:"error,omitempty"`
}

// BatchOptions configures a gov batch run.
type BatchOptions struct {
	// Parallel is the worker pool size. <=0 defaults to 2; clamped to 4.
	Parallel int
	// HaltOnFirstQuarantine stops launching new jobs once any job in the
	// batch quarantines. Jobs already in flight run to completion; jobs not
	// yet started are marked SKIPPED rather than queued indefinitely.
	HaltOnFirstQuarantine bool
}

// BatchSummary is the aggregate result of a gov batch run, also persisted as
// one observability.Batch ledger row (batch_id, started, jobs, quarantined,
// total_cost).
type BatchSummary struct {
	BatchID      string           `json:"batch_id"`
	Jobs         []BatchJobResult `json:"jobs"`
	Quarantined  int              `json:"quarantined"`
	TotalCostUSD float64          `json:"total_cost_usd"`
}

func effectiveParallel(n int) int {
	if n <= 0 {
		return 2
	}
	if n > 4 {
		return 4
	}
	return n
}

// RunBatch fans jobs out across a worker pool. Every job goes through
// RunWithAutoRepair unmodified — its own lock, spend check, gate, and
// validators apply exactly as `gov run` today; RunBatch reuses that single
// job path as a function rather than forking any of its logic. The one
// thing RunBatch adds on top is a shared in-process spend.Accountant so
// concurrent workers can't all pass the ledger-backed CheckBudget before
// any of their cost has actually landed in the ledger (RUNNING rows are
// excluded from TodaySpend) — see spend.Accountant's doc comment — plus
// optional early-exit once any job quarantines.
//
// Callers (contracts.ParseFile at the CLI layer) are expected to have
// already validated every contract; RunBatch assumes jobs is a fully valid
// set and refuses nothing at the contract level itself.
func (r *Runner) RunBatch(ctx context.Context, jobs []contracts.Contract, opts BatchOptions) (BatchSummary, error) {
	batchID := fmt.Sprintf("batch-%d", time.Now().UTC().UnixNano())
	started := time.Now().UTC().Format(time.RFC3339Nano)

	db, err := dbOpen(r.Home)
	if err != nil {
		return BatchSummary{}, err
	}
	startErr := observability.RecordBatch(db, observability.Batch{ID: batchID, Started: started})
	db.Close()
	if startErr != nil {
		return BatchSummary{}, startErr
	}

	cfg := config.Current()
	acctDB, err := dbOpen(r.Home)
	if err != nil {
		return BatchSummary{}, err
	}
	accountant, err := spend.NewAccountant(cfg, acctDB)
	acctDB.Close()
	if err != nil {
		return BatchSummary{}, err
	}

	parallel := effectiveParallel(opts.Parallel)
	jobCh := make(chan contracts.Contract)
	resultCh := make(chan BatchJobResult, len(jobs))
	var halted int32

	var workers sync.WaitGroup
	for i := 0; i < parallel; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for job := range jobCh {
				if opts.HaltOnFirstQuarantine && atomic.LoadInt32(&halted) != 0 {
					resultCh <- BatchJobResult{JobID: job.JobID, Status: "SKIPPED", Error: "batch halted after an earlier quarantine"}
					continue
				}
				resultCh <- r.runBatchJob(ctx, job, accountant, opts, &halted)
			}
		}()
	}

	go func() {
		defer close(jobCh)
		for _, job := range jobs {
			jobCh <- job
		}
	}()

	go func() {
		workers.Wait()
		close(resultCh)
	}()

	summary := BatchSummary{BatchID: batchID}
	for res := range resultCh {
		summary.Jobs = append(summary.Jobs, res)
		summary.TotalCostUSD += res.CostUSD
		if res.Status == "QUARANTINED" {
			summary.Quarantined++
		}
	}

	finalDB, err := dbOpen(r.Home)
	if err != nil {
		return summary, err
	}
	defer finalDB.Close()
	if err := observability.RecordBatch(finalDB, observability.Batch{
		ID: batchID, Started: started, Finished: time.Now().UTC().Format(time.RFC3339Nano),
		Jobs: len(summary.Jobs), Quarantined: summary.Quarantined, TotalCostUSD: summary.TotalCostUSD,
	}); err != nil {
		return summary, err
	}
	return summary, nil
}

// runBatchJob reserves a conservative cost estimate before launching job,
// releases it after Run returns (settled against the real reported cost),
// and never calls Run at all when the reservation is refused — the spend
// cap protects a batch the same way it protects a single `gov run`, just
// without waiting for a RUNNING row that isn't in the ledger yet.
func (r *Runner) runBatchJob(ctx context.Context, job contracts.Contract, accountant *spend.Accountant, opts BatchOptions, halted *int32) BatchJobResult {
	estimate := spend.EstimateCostUSD(job.Agent, job.Budget.MaxTokens, nil)
	if ok, reason := accountant.Reserve(estimate); !ok {
		return BatchJobResult{JobID: job.JobID, Status: "SKIPPED", Taxonomy: "SPEND_CAP", Error: reason}
	}

	rec, err := r.RunWithAutoRepair(ctx, job)
	if err != nil {
		accountant.Settle(estimate, 0)
		return BatchJobResult{JobID: job.JobID, Status: "ERROR", Error: err.Error()}
	}
	accountant.Settle(estimate, rec.CostUSD)

	if opts.HaltOnFirstQuarantine && rec.Status == "QUARANTINED" {
		atomic.StoreInt32(halted, 1)
	}
	return BatchJobResult{
		JobID: job.JobID, RunID: rec.ID, Status: rec.Status, Taxonomy: rec.FailureTaxonomy,
		CostUSD: rec.CostUSD, Worktree: rec.Worktree,
	}
}
