package observability

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

type AgentScore struct {
	Agent           string  `json:"agent"`
	JobType         string  `json:"job_type"`
	Runs            int     `json:"runs"`
	ValidOutputs    int     `json:"valid_outputs"`
	Failures        int     `json:"failures"`
	ValidRate       float64 `json:"valid_rate"`
	TotalCostUSD    float64 `json:"total_cost_usd"`
	CostPerValidUSD float64 `json:"cost_per_valid_output_usd"`
}

type Failure struct {
	RunID    string `json:"run_id"`
	JobID    string `json:"job_id"`
	Agent    string `json:"agent"`
	JobType  string `json:"job_type"`
	Taxonomy string `json:"taxonomy"`
	Message  string `json:"message"`
	Created  string `json:"created"`
	RepairOf string `json:"repair_of,omitempty"`
}

type CostSummary struct {
	Runs            int     `json:"runs"`
	ValidOutputs    int     `json:"valid_outputs"`
	TotalCostUSD    float64 `json:"total_cost_usd"`
	CostPerValidUSD float64 `json:"cost_per_valid_output_usd"`
}

type ArtifactRecord struct {
	RunID    string `json:"run_id"`
	Name     string `json:"name"`
	Path     string `json:"path"`
	SHA256   string `json:"sha256"`
	Bytes    int64  `json:"bytes"`
	SchemaOK bool   `json:"schema_ok"`
}

// PanelMemberRecord maps an anonymous panel label back to the real job/backend
// for operator audit. Judges see panelist labels only; the ledger keeps the
// reversible mapping outside model context.
type PanelMemberRecord struct {
	PanelID      string `json:"panel_id"`
	MemberLabel  string `json:"member_label"`
	JobID        string `json:"job_id"`
	Agent        string `json:"agent"`
	ArtifactName string `json:"artifact_name"`
}

type FallbackAttempt struct {
	RootRunID      string `json:"root_run_id"`
	RunID          string `json:"run_id"`
	Attempt        int    `json:"attempt"`
	Backend        string `json:"backend"`
	FallbackReason string `json:"fallback_reason,omitempty"`
	Created        string `json:"created"`
}

type TokenUsage struct {
	InputTokens         int64 `json:"input_tokens"`
	OutputTokens        int64 `json:"output_tokens"`
	CachedInputTokens   int64 `json:"cached_input_tokens"`
	CacheCreationTokens int64 `json:"cache_creation_tokens"`
	ReasoningTokens     int64 `json:"reasoning_tokens"`
	TotalTokens         int64 `json:"total_tokens"`
	Available           bool  `json:"available"`
}

type UsageReport struct {
	RunID           string `json:"run_id,omitempty"`
	Runs            int    `json:"runs"`
	MeasuredRuns    int    `json:"measured_runs"`
	InputTokens     int64  `json:"input_tokens"`
	OutputTokens    int64  `json:"output_tokens"`
	CachedTokens    int64  `json:"cached_tokens"`
	ReasoningTokens int64  `json:"reasoning_tokens"`
	TotalTokens     int64  `json:"total_tokens"`
	ToolCalls       int    `json:"tool_calls"`
	TranscriptBytes int64  `json:"transcript_bytes"`
}

type FileFact struct {
	Path       string
	ChangeType string
}

type CommandFact struct {
	Command        string
	Classification string
}

type Completion struct {
	RunID           string
	Agent           string
	JobType         string
	Status          string
	CostUSD         float64
	ValidOutput     bool
	FailureTaxonomy string
	SelfReviewJSON  string
	Notes           string
	Files           []FileFact
	Commands        []CommandFact
	Violations      []string
	Usage           TokenUsage
	ToolCalls       int
	TranscriptBytes int64
}

func Open(home string) (*sql.DB, error) {
	if err := os.MkdirAll(home, 0700); err != nil {
		return nil, err
	}
	// Every call to Run opens (and closes) its own *sql.DB against the same
	// ledger.db file (see runtime.dbOpen); gov batch launches several of
	// these concurrently. WAL lets readers and a writer overlap, and a
	// generous busy_timeout makes SQLite retry instead of returning
	// SQLITE_BUSY when two connections do briefly contend for the single
	// writer lock.
	db, err := sql.Open("sqlite", filepath.Join(home, "ledger.db")+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, err
	}
	schema := `CREATE TABLE IF NOT EXISTS runs(
id TEXT PRIMARY KEY, job_id TEXT, job_type TEXT, agent TEXT, mode TEXT, status TEXT, root TEXT, worktree TEXT, branch TEXT,
contract_hash TEXT, base_head TEXT, approved_head TEXT, diff TEXT, transcript TEXT, message TEXT, commit_hash TEXT, created TEXT,
cost_usd REAL NOT NULL DEFAULT 0, valid_output INTEGER NOT NULL DEFAULT 0, failure_taxonomy TEXT NOT NULL DEFAULT '', result_json TEXT NOT NULL DEFAULT '', prompt_version TEXT NOT NULL DEFAULT '', envelope_json TEXT NOT NULL DEFAULT '', notes TEXT NOT NULL DEFAULT '',
input_tokens INTEGER NOT NULL DEFAULT 0, output_tokens INTEGER NOT NULL DEFAULT 0, cached_input_tokens INTEGER NOT NULL DEFAULT 0, cache_creation_tokens INTEGER NOT NULL DEFAULT 0, reasoning_tokens INTEGER NOT NULL DEFAULT 0, total_tokens INTEGER NOT NULL DEFAULT 0, usage_available INTEGER NOT NULL DEFAULT 0, tool_calls INTEGER NOT NULL DEFAULT 0, transcript_bytes INTEGER NOT NULL DEFAULT 0,
graph_provider TEXT NOT NULL DEFAULT '', graph_version TEXT NOT NULL DEFAULT '', graph_fingerprint TEXT NOT NULL DEFAULT '', graph_files INTEGER NOT NULL DEFAULT 0, graph_nodes INTEGER NOT NULL DEFAULT 0, graph_edges INTEGER NOT NULL DEFAULT 0, graph_db_bytes INTEGER NOT NULL DEFAULT 0,
repair_of TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS jobs(job_id TEXT PRIMARY KEY, job_type TEXT, last_run_at TEXT);
CREATE TABLE IF NOT EXISTS agents(name TEXT PRIMARY KEY, first_run_at TEXT, last_run_at TEXT);
CREATE TABLE IF NOT EXISTS agent_profiles(agent TEXT, job_type TEXT, runs INTEGER NOT NULL DEFAULT 0, valid_outputs INTEGER NOT NULL DEFAULT 0, failures INTEGER NOT NULL DEFAULT 0, total_cost_usd REAL NOT NULL DEFAULT 0, PRIMARY KEY(agent,job_type));
CREATE TABLE IF NOT EXISTS files_touched(run_id TEXT, path TEXT, change_type TEXT);
CREATE TABLE IF NOT EXISTS commands_run(run_id TEXT, command TEXT, classification TEXT);
CREATE TABLE IF NOT EXISTS validators(run_id TEXT, command TEXT, exit_code INTEGER, output TEXT);
CREATE TABLE IF NOT EXISTS violations(run_id TEXT, kind TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS repair_packets(id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT, taxonomy TEXT, packet_json TEXT, created TEXT);
CREATE TABLE IF NOT EXISTS eval_runs(id INTEGER PRIMARY KEY AUTOINCREMENT, suite TEXT, case_name TEXT, agent TEXT, mode TEXT, job_type TEXT, passed INTEGER, taxonomy TEXT, cost_usd REAL, created TEXT);
CREATE TABLE IF NOT EXISTS hook_events(run_id TEXT, tool TEXT, decision TEXT, finding TEXT, detail TEXT, created TEXT);
CREATE TABLE IF NOT EXISTS parity_events(id INTEGER PRIMARY KEY AUTOINCREMENT, payload_hash TEXT, payload TEXT, go_decision TEXT, py_decision TEXT, matched INTEGER, py_unavailable INTEGER, created TEXT);
CREATE TABLE IF NOT EXISTS batches(batch_id TEXT PRIMARY KEY, started TEXT, finished TEXT, jobs INTEGER NOT NULL DEFAULT 0, quarantined INTEGER NOT NULL DEFAULT 0, total_cost_usd REAL NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS route_decisions(id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL DEFAULT '', job_id TEXT NOT NULL, job_type TEXT NOT NULL, objective TEXT NOT NULL DEFAULT 'balanced', candidate TEXT NOT NULL, valid_rate_score REAL NOT NULL DEFAULT 0, failure_severity_score REAL NOT NULL DEFAULT 0, cost_score REAL NOT NULL DEFAULT 0, breaker_score REAL NOT NULL DEFAULT 0, quota_score REAL NOT NULL DEFAULT 0, repair_affinity_score REAL NOT NULL DEFAULT 0, total REAL NOT NULL DEFAULT 0, excluded INTEGER NOT NULL DEFAULT 0, exclusion_reason TEXT NOT NULL DEFAULT '', selected INTEGER NOT NULL DEFAULT 0, preview INTEGER NOT NULL DEFAULT 0, created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS breaker_state(backend TEXT PRIMARY KEY, state TEXT NOT NULL DEFAULT 'CLOSED', failure_kind TEXT NOT NULL DEFAULT '', opened_at TEXT NOT NULL DEFAULT '', cooldown_until TEXT NOT NULL DEFAULT '', consecutive_failures INTEGER NOT NULL DEFAULT 0, last_probe_at TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS breaker_events(id INTEGER PRIMARY KEY AUTOINCREMENT, backend TEXT NOT NULL, event TEXT NOT NULL, failure_kind TEXT NOT NULL DEFAULT '', from_state TEXT NOT NULL DEFAULT '', to_state TEXT NOT NULL DEFAULT '', detail TEXT NOT NULL DEFAULT '', created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS fallback_attempts(id INTEGER PRIMARY KEY AUTOINCREMENT, root_run_id TEXT NOT NULL, run_id TEXT NOT NULL, attempt INTEGER NOT NULL, backend TEXT NOT NULL DEFAULT '', fallback_reason TEXT NOT NULL DEFAULT '', created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS quota_windows(backend TEXT NOT NULL, account TEXT NOT NULL DEFAULT 'default', window_type TEXT NOT NULL, window_started_at TEXT NOT NULL DEFAULT '', reset_at TEXT NOT NULL DEFAULT '', estimated_limit REAL NOT NULL DEFAULT 0, measured_usage REAL NOT NULL DEFAULT 0, reserved_usage REAL NOT NULL DEFAULT 0, confidence REAL NOT NULL DEFAULT 0, source TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL DEFAULT '', PRIMARY KEY(backend,account,window_type));
CREATE TABLE IF NOT EXISTS quota_reservations(id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL DEFAULT '', backend TEXT NOT NULL, account TEXT NOT NULL DEFAULT 'default', usage REAL NOT NULL DEFAULT 0, measured_usage REAL NOT NULL DEFAULT 0, expires_at TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT '', settled_at TEXT NOT NULL DEFAULT '', expired INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS artifacts(run_id TEXT NOT NULL, name TEXT NOT NULL, path TEXT NOT NULL, sha256 TEXT NOT NULL, bytes INTEGER NOT NULL DEFAULT 0, schema_ok INTEGER NOT NULL DEFAULT 0, created TEXT NOT NULL DEFAULT '', PRIMARY KEY(run_id,name));
CREATE TABLE IF NOT EXISTS panel_members(panel_id TEXT NOT NULL, member_label TEXT NOT NULL, job_id TEXT NOT NULL, agent TEXT NOT NULL DEFAULT '', artifact_name TEXT NOT NULL DEFAULT '', created TEXT NOT NULL DEFAULT '', PRIMARY KEY(panel_id,member_label));`
	if _, err = db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	for _, column := range []string{
		"job_type TEXT", "agent TEXT", "mode TEXT", "cost_usd REAL NOT NULL DEFAULT 0",
		"valid_output INTEGER NOT NULL DEFAULT 0", "failure_taxonomy TEXT NOT NULL DEFAULT ''", "result_json TEXT NOT NULL DEFAULT ''",
		"prompt_version TEXT NOT NULL DEFAULT ''", "envelope_json TEXT NOT NULL DEFAULT ''", "notes TEXT NOT NULL DEFAULT ''",
		"input_tokens INTEGER NOT NULL DEFAULT 0", "output_tokens INTEGER NOT NULL DEFAULT 0", "cached_input_tokens INTEGER NOT NULL DEFAULT 0",
		"cache_creation_tokens INTEGER NOT NULL DEFAULT 0", "reasoning_tokens INTEGER NOT NULL DEFAULT 0", "total_tokens INTEGER NOT NULL DEFAULT 0",
		"usage_available INTEGER NOT NULL DEFAULT 0", "tool_calls INTEGER NOT NULL DEFAULT 0", "transcript_bytes INTEGER NOT NULL DEFAULT 0",
		"graph_provider TEXT NOT NULL DEFAULT ''", "graph_version TEXT NOT NULL DEFAULT ''", "graph_fingerprint TEXT NOT NULL DEFAULT ''",
		"graph_files INTEGER NOT NULL DEFAULT 0", "graph_nodes INTEGER NOT NULL DEFAULT 0", "graph_edges INTEGER NOT NULL DEFAULT 0", "graph_db_bytes INTEGER NOT NULL DEFAULT 0",
		"repair_of TEXT NOT NULL DEFAULT ''",
	} {
		if _, alterErr := db.Exec("ALTER TABLE runs ADD COLUMN " + column); alterErr != nil && !strings.Contains(strings.ToLower(alterErr.Error()), "duplicate column") {
			db.Close()
			return nil, alterErr
		}
	}
	// stage distinguishes the cleanup pass (Session 5, doctrine gap #5) from
	// the pre-existing success.validators rows. Defaulting existing and new
	// rows to 'success' keeps every prior ledger query (which never filtered
	// by stage) reading the same rows it always did.
	if _, alterErr := db.Exec("ALTER TABLE validators ADD COLUMN stage TEXT NOT NULL DEFAULT 'success'"); alterErr != nil && !strings.Contains(strings.ToLower(alterErr.Error()), "duplicate column") {
		db.Close()
		return nil, alterErr
	}
	if _, err = db.Exec(`CREATE INDEX IF NOT EXISTS runs_key ON runs(contract_hash, approved_head, status);
CREATE INDEX IF NOT EXISTS runs_failure ON runs(failure_taxonomy, created);
CREATE INDEX IF NOT EXISTS runs_repair_of ON runs(repair_of);
CREATE INDEX IF NOT EXISTS files_run ON files_touched(run_id);
CREATE INDEX IF NOT EXISTS commands_run_id ON commands_run(run_id);
CREATE INDEX IF NOT EXISTS fallback_attempts_root ON fallback_attempts(root_run_id);
CREATE INDEX IF NOT EXISTS quota_windows_backend ON quota_windows(backend,account);
CREATE INDEX IF NOT EXISTS quota_reservations_run ON quota_reservations(run_id);
CREATE INDEX IF NOT EXISTS quota_reservations_open ON quota_reservations(settled_at,expires_at);
CREATE INDEX IF NOT EXISTS artifacts_name ON artifacts(name,run_id);
CREATE INDEX IF NOT EXISTS panel_members_job ON panel_members(job_id);`); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// Batch summarizes one gov batch run for the ledger's batches table.
type Batch struct {
	ID           string  `json:"batch_id"`
	Started      string  `json:"started"`
	Finished     string  `json:"finished,omitempty"`
	Jobs         int     `json:"jobs"`
	Quarantined  int     `json:"quarantined"`
	TotalCostUSD float64 `json:"total_cost_usd"`
}

// RecordBatch upserts a batch summary row, called once at batch start
// (jobs/quarantined/total_cost_usd zero, finished empty) and again after
// every job has settled.
func RecordBatch(db *sql.DB, b Batch) error {
	_, err := db.Exec(`INSERT INTO batches(batch_id,started,finished,jobs,quarantined,total_cost_usd) VALUES(?,?,?,?,?,?)
ON CONFLICT(batch_id) DO UPDATE SET finished=excluded.finished,jobs=excluded.jobs,quarantined=excluded.quarantined,total_cost_usd=excluded.total_cost_usd`,
		b.ID, b.Started, b.Finished, b.Jobs, b.Quarantined, b.TotalCostUSD)
	return err
}

// BatchByID looks up one batch summary row, for tests and CLI inspection.
func BatchByID(db *sql.DB, id string) (Batch, error) {
	var b Batch
	err := db.QueryRow(`SELECT batch_id,started,COALESCE(finished,''),jobs,quarantined,total_cost_usd FROM batches WHERE batch_id=?`, id).
		Scan(&b.ID, &b.Started, &b.Finished, &b.Jobs, &b.Quarantined, &b.TotalCostUSD)
	return b, err
}

// RouteDecisionRow is one scored candidate in a route-broker decision. A
// decision writes one row per candidate — excluded candidates included, with
// their exclusion reason — so every routing decision is fully explainable and
// replayable from the ledger alone (rule: every decision is ledgered).
type RouteDecisionRow struct {
	Candidate            string
	ValidRateScore       float64
	FailureSeverityScore float64
	CostScore            float64
	BreakerScore         float64
	QuotaScore           float64
	RepairAffinityScore  float64
	Total                float64
	Excluded             bool
	ExclusionReason      string
	Selected             bool
}

// RouteDecisionRecord is the persistence shape for one broker decision: the
// job/objective context plus one row per candidate. Created is RFC3339Nano;
// callers pass time.Now().UTC() (tests pass a fixed value for determinism).
// RunID is empty for a preview (`gov route --explain`), which the preview flag
// records so reports can separate dry-run decisions from real launches.
type RouteDecisionRecord struct {
	RunID     string
	JobID     string
	JobType   string
	Objective string
	Preview   bool
	Created   string
	Rows      []RouteDecisionRow
}

// RecordRouteDecision persists one broker decision: one route_decisions row
// per candidate. It runs in a single transaction so a decision is either
// fully recorded or not at all — a half-written decision table would make
// `gov route --explain` history misleading.
func RecordRouteDecision(db *sql.DB, rec RouteDecisionRecord) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, row := range rec.Rows {
		if _, err = tx.Exec(`INSERT INTO route_decisions(run_id,job_id,job_type,objective,candidate,valid_rate_score,failure_severity_score,cost_score,breaker_score,quota_score,repair_affinity_score,total,excluded,exclusion_reason,selected,preview,created) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			rec.RunID, rec.JobID, rec.JobType, rec.Objective, row.Candidate,
			row.ValidRateScore, row.FailureSeverityScore, row.CostScore,
			row.BreakerScore, row.QuotaScore, row.RepairAffinityScore, row.Total,
			boolInt(row.Excluded), row.ExclusionReason, boolInt(row.Selected),
			boolInt(rec.Preview), rec.Created); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// RecordFallbackAttempt links an agent:auto fallback chain together. The first
// row's root_run_id is its own run_id; later rows point at that first run so
// route/reporting code can treat the chain as one job without reusing
// repair_of (which is reserved for quality repair attempts). fallback_reason
// is populated on an attempt that qualified for infrastructure-only fallback.

func RecordArtifacts(db *sql.DB, artifacts []ArtifactRecord, created string) error {
	if len(artifacts) == 0 {
		return nil
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, artifact := range artifacts {
		if _, err := tx.Exec(`INSERT INTO artifacts(run_id,name,path,sha256,bytes,schema_ok,created) VALUES(?,?,?,?,?,?,?) ON CONFLICT(run_id,name) DO UPDATE SET path=excluded.path,sha256=excluded.sha256,bytes=excluded.bytes,schema_ok=excluded.schema_ok,created=excluded.created`,
			artifact.RunID, artifact.Name, artifact.Path, artifact.SHA256, artifact.Bytes, boolInt(artifact.SchemaOK), created); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func RecordPanelMembers(db *sql.DB, members []PanelMemberRecord, created string) error {
	if len(members) == 0 {
		return nil
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, member := range members {
		if _, err := tx.Exec(`INSERT INTO panel_members(panel_id,member_label,job_id,agent,artifact_name,created) VALUES(?,?,?,?,?,?) ON CONFLICT(panel_id,member_label) DO UPDATE SET job_id=excluded.job_id,agent=excluded.agent,artifact_name=excluded.artifact_name,created=excluded.created`,
			member.PanelID, member.MemberLabel, member.JobID, member.Agent, member.ArtifactName, created); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func RecordFallbackAttempt(db *sql.DB, a FallbackAttempt) error {
	_, err := db.Exec(`INSERT INTO fallback_attempts(root_run_id,run_id,attempt,backend,fallback_reason,created) VALUES(?,?,?,?,?,?)`,
		a.RootRunID, a.RunID, a.Attempt, a.Backend, a.FallbackReason, a.Created)
	return err
}

func RecordIdentity(db *sql.DB, jobID, jobType, agent, created string) error {
	if _, err := db.Exec(`INSERT INTO jobs(job_id,job_type,last_run_at) VALUES(?,?,?) ON CONFLICT(job_id) DO UPDATE SET job_type=excluded.job_type,last_run_at=excluded.last_run_at`, jobID, jobType, created); err != nil {
		return err
	}
	_, err := db.Exec(`INSERT INTO agents(name,first_run_at,last_run_at) VALUES(?,?,?) ON CONFLICT(name) DO UPDATE SET last_run_at=excluded.last_run_at`, agent, created, created)
	return err
}

func RecordCompletion(db *sql.DB, c Completion) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`UPDATE runs SET cost_usd=?,valid_output=?,failure_taxonomy=?,result_json=?,notes=?,input_tokens=?,output_tokens=?,cached_input_tokens=?,cache_creation_tokens=?,reasoning_tokens=?,total_tokens=?,usage_available=?,tool_calls=?,transcript_bytes=? WHERE id=?`,
		c.CostUSD, c.ValidOutput, c.FailureTaxonomy, c.SelfReviewJSON, c.Notes, c.Usage.InputTokens, c.Usage.OutputTokens,
		c.Usage.CachedInputTokens, c.Usage.CacheCreationTokens, c.Usage.ReasoningTokens, c.Usage.TotalTokens,
		boolInt(c.Usage.Available), c.ToolCalls, c.TranscriptBytes, c.RunID); err != nil {
		return err
	}
	for _, table := range []string{"files_touched", "commands_run", "violations"} {
		if _, err = tx.Exec("DELETE FROM "+table+" WHERE run_id=?", c.RunID); err != nil {
			return err
		}
	}
	for _, f := range c.Files {
		if _, err = tx.Exec(`INSERT INTO files_touched(run_id,path,change_type) VALUES(?,?,?)`, c.RunID, f.Path, f.ChangeType); err != nil {
			return err
		}
	}
	for _, command := range c.Commands {
		if _, err = tx.Exec(`INSERT INTO commands_run(run_id,command,classification) VALUES(?,?,?)`, c.RunID, command.Command, command.Classification); err != nil {
			return err
		}
	}
	for _, detail := range c.Violations {
		if _, err = tx.Exec(`INSERT INTO violations(run_id,kind,detail) VALUES(?,?,?)`, c.RunID, c.FailureTaxonomy, detail); err != nil {
			return err
		}
	}
	// A SPEND_CAP refusal never launched the backend, so booking it as an
	// agent run/failure would corrupt the valid-output rates gov score/route
	// rank agents by — a halted day would pile fake failures onto whatever
	// agent the refused jobs happened to name.
	//
	// An infrastructure failure (Session 2: RATE_LIMIT, QUOTA_EXHAUSTED, ...)
	// likewise never produced work product the quality gate is measuring, so
	// it must not pollute agent_profiles either (rule 3: infra and quality are
	// separate metrics — a provider outage never lowers a quality score). The
	// infra failure is still recorded in runs (for visibility) and drives the
	// circuit breaker instead.
	if c.FailureTaxonomy != "SPEND_CAP" && !IsInfraFailure(c.FailureTaxonomy) {
		failure := c.Status != "APPROVED"
		if _, err = tx.Exec(`INSERT INTO agent_profiles(agent,job_type,runs,valid_outputs,failures,total_cost_usd) VALUES(?,?,?,?,?,?)
ON CONFLICT(agent,job_type) DO UPDATE SET runs=runs+1,valid_outputs=valid_outputs+excluded.valid_outputs,failures=failures+excluded.failures,total_cost_usd=total_cost_usd+excluded.total_cost_usd`,
			c.Agent, c.JobType, 1, boolInt(c.ValidOutput), boolInt(failure), c.CostUSD); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func ScoreAgents(home, jobType string) ([]AgentScore, error) {
	db, err := Open(home)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.Query(`SELECT agent,job_type,runs,valid_outputs,failures,total_cost_usd FROM agent_profiles WHERE job_type=? ORDER BY (1.0*valid_outputs/runs) DESC, failures ASC, agent ASC`, jobType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var scores []AgentScore
	for rows.Next() {
		var s AgentScore
		if err := rows.Scan(&s.Agent, &s.JobType, &s.Runs, &s.ValidOutputs, &s.Failures, &s.TotalCostUSD); err != nil {
			return nil, err
		}
		if s.Runs > 0 {
			s.ValidRate = float64(s.ValidOutputs) / float64(s.Runs)
		}
		if s.ValidOutputs > 0 {
			s.CostPerValidUSD = s.TotalCostUSD / float64(s.ValidOutputs)
		}
		scores = append(scores, s)
	}
	return scores, rows.Err()
}

func Failures(home string, limit int) ([]Failure, error) {
	if limit <= 0 {
		limit = 50
	}
	db, err := Open(home)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.Query(`SELECT id,job_id,COALESCE(agent,''),COALESCE(job_type,''),failure_taxonomy,message,created,COALESCE(repair_of,'') FROM runs WHERE failure_taxonomy<>'' ORDER BY created DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var failures []Failure
	for rows.Next() {
		var f Failure
		if err := rows.Scan(&f.RunID, &f.JobID, &f.Agent, &f.JobType, &f.Taxonomy, &f.Message, &f.Created, &f.RepairOf); err != nil {
			return nil, err
		}
		failures = append(failures, f)
	}
	return failures, rows.Err()
}

func CostPerValidOutput(home string) (CostSummary, error) {
	db, err := Open(home)
	if err != nil {
		return CostSummary{}, err
	}
	defer db.Close()
	var s CostSummary
	err = db.QueryRow(`SELECT COUNT(*),COALESCE(SUM(valid_output),0),COALESCE(SUM(cost_usd),0) FROM runs WHERE status<>'RUNNING'`).Scan(&s.Runs, &s.ValidOutputs, &s.TotalCostUSD)
	if s.ValidOutputs > 0 {
		s.CostPerValidUSD = s.TotalCostUSD / float64(s.ValidOutputs)
	}
	return s, err
}

func UsageSummaryFor(home, runID string) (UsageReport, error) {
	db, err := Open(home)
	if err != nil {
		return UsageReport{}, err
	}
	defer db.Close()
	report := UsageReport{RunID: runID}
	query := `SELECT COUNT(*),COALESCE(SUM(usage_available),0),COALESCE(SUM(input_tokens),0),COALESCE(SUM(output_tokens),0),COALESCE(SUM(cached_input_tokens+cache_creation_tokens),0),COALESCE(SUM(reasoning_tokens),0),COALESCE(SUM(total_tokens),0),COALESCE(SUM(tool_calls),0),COALESCE(SUM(transcript_bytes),0) FROM runs WHERE status<>'RUNNING'`
	args := []any{}
	if runID != "" {
		query += ` AND id=?`
		args = append(args, runID)
	}
	err = db.QueryRow(query, args...).Scan(&report.Runs, &report.MeasuredRuns, &report.InputTokens, &report.OutputTokens, &report.CachedTokens, &report.ReasoningTokens, &report.TotalTokens, &report.ToolCalls, &report.TranscriptBytes)
	return report, err
}

func (u UsageReport) String() string {
	return fmt.Sprintf("runs=%d measured=%d tokens=%d input=%d output=%d cached=%d reasoning=%d tool_calls=%d transcript_bytes=%d", u.Runs, u.MeasuredRuns, u.TotalTokens, u.InputTokens, u.OutputTokens, u.CachedTokens, u.ReasoningTokens, u.ToolCalls, u.TranscriptBytes)
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func (s AgentScore) String() string {
	return fmt.Sprintf("%s\t%s\t%d\t%d\t%d\t%.1f%%\t$%.4f", s.Agent, s.JobType, s.Runs, s.ValidOutputs, s.Failures, s.ValidRate*100, s.CostPerValidUSD)
}

func (f Failure) String() string {
	repairOf := f.RepairOf
	if repairOf == "" {
		repairOf = "-"
	}
	return fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s", f.RunID, f.Agent, f.JobType, f.Taxonomy, f.Message, repairOf)
}

func (s CostSummary) String() string {
	return fmt.Sprintf("runs=%d valid_outputs=%d total_cost_usd=%.4f cost_per_valid_output_usd=%.4f", s.Runs, s.ValidOutputs, s.TotalCostUSD, s.CostPerValidUSD)
}
