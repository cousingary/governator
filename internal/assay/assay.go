// Package assay bridges Governator to the Assayer Python CLI (plan Phase
// 3A — "Governator <-> Assayer bridge, synchronous"). It invokes Assayer's
// `cli.py evaluate --profile <name>` as a local subprocess: the request
// goes in on stdin as JSON, the verdict comes back on stdout as JSON. This
// path is deliberately network-free — no Supabase writes happen here; that
// is out of scope until 3B/3C wire up async persistence.
//
// The defining rule (mirrored from internal/breaker's doc comment style):
// a Supabase outage must never block a valid merge, because this path never
// touches Supabase at all. The only failure modes are local: the artifact
// changed on disk, the subprocess couldn't run, it timed out, or it
// produced unparseable output. Every one of those becomes an explicit ERROR
// verdict with a reason — never a silent pass-through.
package assay

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Verdict states Assayer's evaluate subcommand can return, plus one
// Governator-only pseudo-state (VerdictSkipped) for a run where assay was
// never invoked because it isn't configured.
const (
	VerdictPass     = "pass"
	VerdictAdvisory = "advisory"
	VerdictFail     = "fail"
	VerdictError    = "error"

	// VerdictSkipped never comes from Assayer; it is what Governator
	// records when internal/config's Assay.Repo is unset (plan 3A point 6:
	// "not configured => assay steps skipped and recorded as skipped").
	VerdictSkipped = "skipped"
)

// Enforcement modes a contract's Assay block may declare (mirrors
// contracts.AssayEnforcements).
const (
	EnforcementBlocking  = "blocking"
	EnforcementAdvisory  = "advisory"
	EnforcementTelemetry = "telemetry"
)

// BridgePolicyVersion identifies this request/response wire shape, sent to
// Assayer when the caller has no more specific policy_version of its own
// (Assayer's cli.py falls back to the same constant on its side when a
// request omits policy_version, so the two independently agree on a default
// rather than one silently dictating to the other).
const BridgePolicyVersion = "gov-assay-evaluate-v1"

const defaultTimeout = 60 * time.Second

// Request is the JSON object written to the Assayer subprocess's stdin.
// Field names/order follow the plan's Phase 3A schema (Sol §6) exactly.
type Request struct {
	RunID           string          `json:"run_id"`
	AttemptID       string          `json:"attempt_id"`
	JobID           string          `json:"job_id"`
	ContractHash    string          `json:"contract_hash"`
	JobType         string          `json:"job_type"`
	Backend         string          `json:"backend"`
	Model           string          `json:"model"`
	RouteDecisionID string          `json:"route_decision_id"`
	ArtifactName    string          `json:"artifact_name"`
	ArtifactSHA256  string          `json:"artifact_sha256"`
	Payload         json.RawMessage `json:"payload"`
	CheckProfile    string          `json:"check_profile"`
	PolicyVersion   string          `json:"policy_version"`
}

// Verdict is the JSON object read from the Assayer subprocess's stdout.
type Verdict struct {
	Verdict       string   `json:"verdict"`
	FailedChecks  []string `json:"failed_checks"`
	HadError      bool     `json:"had_error"`
	TraceID       string   `json:"trace_id"`
	QuarantineID  string   `json:"quarantine_id"`
	ChecksHash    string   `json:"checks_hash"`
	PolicyVersion string   `json:"policy_version"`
	Reason        string   `json:"reason,omitempty"`
}

// errorVerdict builds a locally-produced ERROR verdict for a failure this
// side of the subprocess boundary (sha mismatch, exec failure, timeout,
// unparseable stdout). had_error is always true; failed_checks is empty
// because no check ever ran.
func errorVerdict(reason string) Verdict {
	return Verdict{Verdict: VerdictError, FailedChecks: []string{}, HadError: true, Reason: reason}
}

// Config is the subset of config.Config's Assay block Evaluate needs. It is
// a separate type (not a direct dependency on internal/config) so this
// package never has to import config, avoiding any risk of an import
// cycle as config grows.
type Config struct {
	Repo    string
	Python  string
	Timeout time.Duration
}

// Configured reports whether cfg names an assayer checkout. An empty Repo
// means "assay not configured" — the caller must skip the subprocess call
// entirely and record a VerdictSkipped row instead (plan 3A point 6).
func (c Config) Configured() bool {
	return strings.TrimSpace(c.Repo) != ""
}

// Evaluate runs one synchronous assay check for the artifact at
// artifactPath: it verifies the file's sha256 against req.ArtifactSHA256
// BEFORE invoking the subprocess (catches a corrupted/tampered artifact
// before it's even sent for evaluation), invokes Assayer's `evaluate`
// subcommand with req on stdin, then re-verifies the same sha256 AFTER
// (catches a TOCTOU mutation during evaluation). Any failure at any stage —
// pre-check mismatch, subprocess exec/timeout, unparseable stdout,
// post-check mismatch — returns an explicit ERROR verdict with a specific
// reason. Evaluate always returns a Verdict; it deliberately has no error
// return; every failure mode this function can hit is itself a meaningful,
// recordable outcome (an ERROR verdict), not a Go-level exceptional
// condition the caller should be propagating past the ledger.
func Evaluate(ctx context.Context, cfg Config, req Request, artifactPath string) Verdict {
	before, err := sha256File(artifactPath)
	if err != nil {
		return errorVerdict(fmt.Sprintf("assay: read artifact for pre-check: %s", err))
	}
	if before != req.ArtifactSHA256 {
		return errorVerdict(fmt.Sprintf("assay: artifact_sha256 mismatch before evaluation (ledgered=%s actual=%s)", req.ArtifactSHA256, before))
	}

	if req.PolicyVersion == "" {
		req.PolicyVersion = BridgePolicyVersion
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return errorVerdict(fmt.Sprintf("assay: marshal request: %s", err))
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	python := strings.TrimSpace(cfg.Python)
	if python == "" {
		python = "python3"
	}
	cliPath := filepath.Join(cfg.Repo, "cli.py")

	cmd := exec.CommandContext(runCtx, python, cliPath, "evaluate", "--profile", req.CheckProfile)
	cmd.Dir = cfg.Repo
	cmd.Stdin = bytes.NewReader(payload)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	if runCtx.Err() == context.DeadlineExceeded {
		return errorVerdict(fmt.Sprintf("assay: subprocess timed out after %s", timeout))
	}
	if runErr != nil {
		return errorVerdict(fmt.Sprintf("assay: subprocess exit: %s; stderr: %s", runErr, strings.TrimSpace(stderr.String())))
	}

	var v Verdict
	if err := json.Unmarshal(stdout.Bytes(), &v); err != nil {
		return errorVerdict(fmt.Sprintf("assay: parse verdict JSON: %s; stdout: %s", err, strings.TrimSpace(stdout.String())))
	}

	after, err := sha256File(artifactPath)
	if err != nil {
		return errorVerdict(fmt.Sprintf("assay: read artifact for post-check: %s", err))
	}
	if after != req.ArtifactSHA256 {
		return errorVerdict(fmt.Sprintf("assay: artifact_sha256 mismatch after evaluation (ledgered=%s actual=%s)", req.ArtifactSHA256, after))
	}

	if v.FailedChecks == nil {
		v.FailedChecks = []string{}
	}
	return v
}

// Blocks reports whether verdict v under enforcement mode should quarantine
// the run. advisory/telemetry never block regardless of verdict. Under
// "blocking" enforcement only the two known-good verdicts (pass, advisory)
// clear the gate; fail, error, AND any string this side doesn't recognize
// (empty, wrong case, a future Assayer verdict this binary predates) all
// block. The subprocess boundary is exactly where fail-open would be
// cheapest to introduce by accident — an unrecognized verdict must read as
// "not verified," never as "fine."
func Blocks(verdict, enforcement string) bool {
	if enforcement != EnforcementBlocking {
		return false
	}
	return verdict != VerdictPass && verdict != VerdictAdvisory
}

func sha256File(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
