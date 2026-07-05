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
}

type CostSummary struct {
	Runs            int     `json:"runs"`
	ValidOutputs    int     `json:"valid_outputs"`
	TotalCostUSD    float64 `json:"total_cost_usd"`
	CostPerValidUSD float64 `json:"cost_per_valid_output_usd"`
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
	db, err := sql.Open("sqlite", filepath.Join(home, "ledger.db"))
	if err != nil {
		return nil, err
	}
	schema := `CREATE TABLE IF NOT EXISTS runs(
id TEXT PRIMARY KEY, job_id TEXT, job_type TEXT, agent TEXT, mode TEXT, status TEXT, root TEXT, worktree TEXT, branch TEXT,
contract_hash TEXT, base_head TEXT, approved_head TEXT, diff TEXT, transcript TEXT, message TEXT, commit_hash TEXT, created TEXT,
cost_usd REAL NOT NULL DEFAULT 0, valid_output INTEGER NOT NULL DEFAULT 0, failure_taxonomy TEXT NOT NULL DEFAULT '', result_json TEXT NOT NULL DEFAULT '', prompt_version TEXT NOT NULL DEFAULT '', envelope_json TEXT NOT NULL DEFAULT '', notes TEXT NOT NULL DEFAULT '',
input_tokens INTEGER NOT NULL DEFAULT 0, output_tokens INTEGER NOT NULL DEFAULT 0, cached_input_tokens INTEGER NOT NULL DEFAULT 0, cache_creation_tokens INTEGER NOT NULL DEFAULT 0, reasoning_tokens INTEGER NOT NULL DEFAULT 0, total_tokens INTEGER NOT NULL DEFAULT 0, usage_available INTEGER NOT NULL DEFAULT 0, tool_calls INTEGER NOT NULL DEFAULT 0, transcript_bytes INTEGER NOT NULL DEFAULT 0,
graph_provider TEXT NOT NULL DEFAULT '', graph_version TEXT NOT NULL DEFAULT '', graph_fingerprint TEXT NOT NULL DEFAULT '', graph_files INTEGER NOT NULL DEFAULT 0, graph_nodes INTEGER NOT NULL DEFAULT 0, graph_edges INTEGER NOT NULL DEFAULT 0, graph_db_bytes INTEGER NOT NULL DEFAULT 0);
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
CREATE TABLE IF NOT EXISTS parity_events(id INTEGER PRIMARY KEY AUTOINCREMENT, payload_hash TEXT, payload TEXT, go_decision TEXT, py_decision TEXT, matched INTEGER, py_unavailable INTEGER, created TEXT);`
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
	} {
		if _, alterErr := db.Exec("ALTER TABLE runs ADD COLUMN " + column); alterErr != nil && !strings.Contains(strings.ToLower(alterErr.Error()), "duplicate column") {
			db.Close()
			return nil, alterErr
		}
	}
	if _, err = db.Exec(`CREATE INDEX IF NOT EXISTS runs_key ON runs(contract_hash, approved_head, status);
CREATE INDEX IF NOT EXISTS runs_failure ON runs(failure_taxonomy, created);
CREATE INDEX IF NOT EXISTS files_run ON files_touched(run_id);
CREATE INDEX IF NOT EXISTS commands_run_id ON commands_run(run_id);`); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
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
	failure := c.Status != "APPROVED"
	if _, err = tx.Exec(`INSERT INTO agent_profiles(agent,job_type,runs,valid_outputs,failures,total_cost_usd) VALUES(?,?,?,?,?,?)
ON CONFLICT(agent,job_type) DO UPDATE SET runs=runs+1,valid_outputs=valid_outputs+excluded.valid_outputs,failures=failures+excluded.failures,total_cost_usd=total_cost_usd+excluded.total_cost_usd`,
		c.Agent, c.JobType, 1, boolInt(c.ValidOutput), boolInt(failure), c.CostUSD); err != nil {
		return err
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
	rows, err := db.Query(`SELECT id,job_id,COALESCE(agent,''),COALESCE(job_type,''),failure_taxonomy,message,created FROM runs WHERE failure_taxonomy<>'' ORDER BY created DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var failures []Failure
	for rows.Next() {
		var f Failure
		if err := rows.Scan(&f.RunID, &f.JobID, &f.Agent, &f.JobType, &f.Taxonomy, &f.Message, &f.Created); err != nil {
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
	return fmt.Sprintf("%s\t%s\t%s\t%s\t%s", f.RunID, f.Agent, f.JobType, f.Taxonomy, f.Message)
}

func (s CostSummary) String() string {
	return fmt.Sprintf("runs=%d valid_outputs=%d total_cost_usd=%.4f cost_per_valid_output_usd=%.4f", s.Runs, s.ValidOutputs, s.TotalCostUSD, s.CostPerValidUSD)
}
