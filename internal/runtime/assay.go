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

// artifactAssayResolution is the outcome of resolving a contract's assay
// declarations against one produced artifact (Sol audit finding #16: every
// produced artifact must either map to a declared assay, explicitly declare
// assay: none, or inherit a contract-wide profile — anything else is an
// undeclared artifact and fails closed).
type artifactAssayResolution struct {
	Profile     string
	Enforcement string
	// Exempt is true for an artifact explicitly declared `assay: none`.
	Exempt bool
	// Undeclared is true when no per-artifact entry names this artifact and
	// the contract has no contract-wide default profile either — a
	// configuration gap, not a "nothing to check" pass.
	Undeclared bool
}

// resolveArtifactAssay looks up artifactName in a.Artifacts first (an exact
// per-artifact override always wins), then falls back to the contract-wide
// a.Profile/a.Enforcement, then reports Undeclared if neither applies.
func resolveArtifactAssay(a *contracts.Assay, artifactName string) artifactAssayResolution {
	for _, aa := range a.Artifacts {
		if aa.Artifact != artifactName {
			continue
		}
		if strings.TrimSpace(aa.Profile) == contracts.AssayProfileNone {
			return artifactAssayResolution{Exempt: true}
		}
		return artifactAssayResolution{Profile: aa.Profile, Enforcement: aa.Enforcement}
	}
	if strings.TrimSpace(a.Profile) != "" {
		return artifactAssayResolution{Profile: a.Profile, Enforcement: a.Enforcement}
	}
	return artifactAssayResolution{Undeclared: true}
}

// assayDeclaresBlocking reports whether any assay declaration on the
// contract — the contract-wide default or any per-artifact override — is
// "blocking". Used only to gate the two whole-contract-level cases below
// (assay not configured at all; assay declared but nothing was produced to
// evaluate), where no single artifact resolution exists yet to check.
func assayDeclaresBlocking(a *contracts.Assay) bool {
	if a.Enforcement == assay.EnforcementBlocking {
		return true
	}
	for _, aa := range a.Artifacts {
		if aa.Enforcement == assay.EnforcementBlocking {
			return true
		}
	}
	return false
}

// runAssayStep is the Phase 3A call site: it decides whether to invoke the
// Assayer subprocess for c.Assay, records one assay_evaluations ledger row
// per produced artifact evaluated (or skipped/exempted), and — only for a
// blocking FAIL/ERROR verdict — appends a violation string, reusing the
// existing quarantine machinery (Run's `violations` slice) instead of
// inventing a parallel one. It never touches the network: assay.Evaluate's
// only I/O is a local subprocess and local file reads, so a Supabase outage
// (which this path never talks to) cannot affect it either way.
//
// Sol audit finding #16 ("Assayer evaluates only the first produced
// artifact"): every entry in artifactRecords is now resolved and evaluated
// independently — a contract producing several artifacts under a blocking
// assay blocks on ANY failing artifact, not just the first.
func runAssayStep(ctx context.Context, db *sql.DB, cfg config.Config, c contracts.Contract, runID, contractHash, backend string, artifactRecords []observability.ArtifactRecord, violations *[]string, snap *assay.Snapshot) {
	created := time.Now().UTC().Format(time.RFC3339Nano)
	assayCfg := assay.Config{
		Repo:    cfg.Assay.Repo,
		Python:  cfg.Assay.Python,
		Timeout: time.Duration(cfg.Assay.TimeoutSeconds) * time.Second,
	}
	// Computed once per step (not once per record() call) since Repo/Python
	// don't change mid-run; stamped onto every row below — pass, fail,
	// error, AND skipped alike — per plan Session 2 item 3 ("record in
	// every evaluation"). Zero-value (all fields empty) when assay isn't
	// configured: DescribeEnvironment has nothing to introspect.
	env := assay.DescribeEnvironment(assayCfg)

	// A ledger write failure here must not itself quarantine an otherwise
	// fine run, matching the existing pattern for validator rows a few lines
	// above (INSERT INTO validators ...). Since Session 4 a failure is no
	// longer simply swallowed: noteOperationalFailure durably queues the
	// write for `gov reconcile`.
	record := func(artifactName, artifactSHA256, profile, verdict, policyVersion string, v assay.Verdict, durationMS int64) {
		failedChecks := v.FailedChecks
		if failedChecks == nil {
			failedChecks = []string{}
		}
		evalRec := observability.AssayEvaluationRecord{
			RunID: runID, AttemptID: runID, JobID: c.JobID,
			ArtifactName: artifactName, ArtifactSHA256: artifactSHA256,
			Profile: profile, PolicyVersion: policyVersion, Verdict: verdict, FailedChecks: failedChecks,
			ChecksHash: v.ChecksResultHash, DurationMS: durationMS, Created: created,
			AssayerCommit: env.AssayerCommit, ProfileHash: env.ProfileHash,
			ValidatorsHash: env.ValidatorsHash, PythonVersion: env.PythonVersion,
			ProfileDefinitionHash: v.ProfileDefinitionHash, ValidatorImplementationHash: v.ValidatorImplementationHash,
			ValidatorConfigHash: v.ValidatorConfigHash,
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
		record("", "", c.Assay.Profile, assay.VerdictSkipped, "", assay.Verdict{}, 0)
		if assayDeclaresBlocking(c.Assay) {
			*violations = append(*violations, "assay: blocking enforcement declared but no assayer is configured (set assay.repo in config.yaml or GOV_ASSAY_REPO)")
		}
		return
	}

	if len(artifactRecords) == 0 {
		// A contract declared assay but produced nothing to evaluate — this
		// is a configuration mismatch, not a silent pass. Only a contract
		// that declares blocking anywhere turns it into a violation;
		// advisory/telemetry-only contracts just record it.
		record("", "", c.Assay.Profile, assay.VerdictError, "", assay.Verdict{}, 0)
		if assayDeclaresBlocking(c.Assay) {
			*violations = append(*violations, "assay: no artifact produced to evaluate")
		}
		return
	}

	for _, artifact := range artifactRecords {
		resolution := resolveArtifactAssay(c.Assay, artifact.Name)

		if resolution.Exempt {
			record(artifact.Name, artifact.SHA256, contracts.AssayProfileNone, assay.VerdictSkipped, "", assay.Verdict{Reason: "artifact explicitly exempt via assay: none"}, 0)
			continue
		}

		if resolution.Undeclared {
			// Fail closed unconditionally (not enforcement-gated): there is
			// no enforcement mode to consult when the contract never said
			// what to do with this artifact at all (Sol audit finding #16
			// — "every produced artifact should either map to a declared
			// assay, explicitly declare assay: none, or inherit a
			// contract-wide profile"). Old-style contracts (a bare
			// contract-wide Profile, no Artifacts list) never hit this
			// branch: resolveArtifactAssay always falls back to the
			// contract-wide default first.
			record(artifact.Name, artifact.SHA256, "", assay.VerdictError, "", assay.Verdict{}, 0)
			*violations = append(*violations, fmt.Sprintf("assay: produced artifact %q has no declared assay and no assay: none exemption", artifact.Name))
			continue
		}

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
			// ArtifactDeclaredPath (Sol audit finding #17) is the artifact's
			// real workspace-relative path from the contract's ArtifactSpec
			// — the field a file-aware Assayer check should key off of, not
			// the logical ArtifactName (e.g. "code" vs "result.py").
			// ArtifactStoredPath is carried for completeness/audit trail
			// only; Assayer's cli.py does not forward it to validators.
			ArtifactDeclaredPath: artifact.DeclaredPath, ArtifactStoredPath: artifact.Path,
			ArtifactMediaType: artifact.MediaType, ArtifactLanguage: artifact.Language,
			Payload: payload, CheckProfile: resolution.Profile,
		}

		start := time.Now()
		verdict := assay.Evaluate(ctx, assayCfg, req, artifact.Path, snap)
		duration := time.Since(start)

		record(artifact.Name, artifact.SHA256, resolution.Profile, verdict.Verdict, verdict.PolicyVersion, verdict, duration.Milliseconds())

		if assay.Blocks(verdict.Verdict, resolution.Enforcement) {
			reason := verdict.Reason
			if reason == "" {
				reason = "see failed_checks"
			}
			*violations = append(*violations, fmt.Sprintf(
				"assay: artifact=%s profile=%s verdict=%s failed_checks=%s reason=%s",
				artifact.Name, resolution.Profile, verdict.Verdict, strings.Join(verdict.FailedChecks, ","), reason,
			))
		}
	}
}
