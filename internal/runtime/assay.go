package runtime

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/cousingary/governator/internal/assay"
	"github.com/cousingary/governator/internal/config"
	"github.com/cousingary/governator/internal/contracts"
	"github.com/cousingary/governator/internal/observability"
)

// runAssayStep is the Phase 3A call site: it decides whether to invoke the
// Assayer subprocess for c.Assay, records exactly one assay_evaluations
// ledger row for the attempt, and — only for a blocking FAIL/ERROR verdict —
// appends a violation string, reusing the existing quarantine machinery
// (Run's `violations` slice) instead of inventing a parallel one. It never
// touches the network: assay.Evaluate's only I/O is a local subprocess and
// local file reads, so a Supabase outage (which this path never talks to)
// cannot affect it either way.
func runAssayStep(ctx context.Context, db *sql.DB, cfg config.Config, c contracts.Contract, runID, contractHash, backend string, artifactRecords []observability.ArtifactRecord, violations *[]string) {
	created := time.Now().UTC().Format(time.RFC3339Nano)
	assayCfg := assay.Config{
		Repo:    cfg.Assay.Repo,
		Python:  cfg.Assay.Python,
		Timeout: time.Duration(cfg.Assay.TimeoutSeconds) * time.Second,
	}

	// A ledger write failure here must not itself quarantine an otherwise
	// fine run, matching the existing pattern for validator rows a few lines
	// above (INSERT INTO validators ...). Since Session 4 a failure is no
	// longer simply swallowed: noteOperationalFailure durably queues the
	// write for `gov reconcile`.
	record := func(verdict, policyVersion, checksHash string, failedChecks []string, durationMS int64) {
		if failedChecks == nil {
			failedChecks = []string{}
		}
		evalRec := observability.AssayEvaluationRecord{
			RunID: runID, AttemptID: runID, JobID: c.JobID, Profile: c.Assay.Profile,
			PolicyVersion: policyVersion, Verdict: verdict, FailedChecks: failedChecks,
			ChecksHash: checksHash, DurationMS: durationMS, Created: created,
		}
		if err := observability.RecordAssayEvaluation(db, evalRec); err != nil {
			payload, _ := json.Marshal(assayEvaluationPayload{Record: evalRec})
			noteOperationalFailure(db, runID, opAssayEvaluation, err, string(payload))
		}
	}

	if !assayCfg.Configured() {
		// Not configured: skip the subprocess call entirely (no network, no
		// Python invocation) and record the skip so the ledger shows *why*
		// no real verdict exists for this run, rather than looking
		// identical to a contract that never declared assay at all.
		//
		// Under advisory/telemetry that skip is the whole story. Under
		// blocking enforcement it is not: the contract explicitly demanded
		// a verdict gate the merge, and "the tool isn't installed" silently
		// waving every run through would be fail-open — the same reason
		// runner: docker errors rather than quietly running local. Quarantine
		// instead, with the remediation in the reason.
		record(assay.VerdictSkipped, "", "", nil, 0)
		if c.Assay.Enforcement == assay.EnforcementBlocking {
			*violations = append(*violations, "assay: blocking enforcement declared but no assayer is configured (set assay.repo in config.yaml or GOV_ASSAY_REPO)")
		}
		return
	}

	if len(artifactRecords) == 0 {
		// A contract declared assay but produced nothing to evaluate — this
		// is a configuration mismatch, not a silent pass. Only a blocking
		// contract turns it into a violation; advisory/telemetry just
		// record it.
		record(assay.VerdictError, "", "", nil, 0)
		if c.Assay.Enforcement == assay.EnforcementBlocking {
			*violations = append(*violations, "assay: no artifact produced to evaluate")
		}
		return
	}

	// 3A evaluates the first produced artifact. A contract with multiple
	// `produces` entries and one `assay` block is a multi-artifact profile
	// question left to 3B/3C; here it's the smallest reasonable choice that
	// keeps the common single-artifact case fully wired.
	artifact := artifactRecords[0]

	// The whole artifact file's bytes become the checked "content" field,
	// regardless of the artifact's own internal format (JSON, markdown,
	// code, ...) — see assayer/profiles.py's CODING_OUTPUT_REQUIRED_FIELDS
	// doc comment for the matching design choice on the Python side.
	data, readErr := os.ReadFile(artifact.Path)
	var payloadMap map[string]string
	if readErr == nil {
		payloadMap = map[string]string{"content": string(data)}
	} else {
		payloadMap = map[string]string{}
	}
	payload, _ := json.Marshal(payloadMap)

	req := assay.Request{
		RunID: runID, AttemptID: runID, JobID: c.JobID, ContractHash: contractHash,
		JobType: c.JobType, Backend: backend,
		ArtifactName: artifact.Name, ArtifactSHA256: artifact.SHA256,
		Payload: payload, CheckProfile: c.Assay.Profile,
	}

	start := time.Now()
	verdict := assay.Evaluate(ctx, assayCfg, req, artifact.Path)
	duration := time.Since(start)

	record(verdict.Verdict, verdict.PolicyVersion, verdict.ChecksHash, verdict.FailedChecks, duration.Milliseconds())

	if assay.Blocks(verdict.Verdict, c.Assay.Enforcement) {
		reason := verdict.Reason
		if reason == "" {
			reason = "see failed_checks"
		}
		*violations = append(*violations, fmt.Sprintf(
			"assay: profile=%s verdict=%s failed_checks=%s reason=%s",
			c.Assay.Profile, verdict.Verdict, strings.Join(verdict.FailedChecks, ","), reason,
		))
	}
}
