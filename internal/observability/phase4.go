package observability

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type RouteCandidate struct {
	Agent       string
	JobType     string
	Runs        int
	Failures    int
	FailureRate float64
}

func RouteAgents(home, jobType string) ([]RouteCandidate, error) {
	db, err := Open(home)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.Query("SELECT agent,job_type,runs,failures FROM agent_profiles WHERE job_type=? AND runs>0 ORDER BY (1.0*failures/runs) ASC, valid_outputs DESC, total_cost_usd ASC, agent ASC", jobType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RouteCandidate
	for rows.Next() {
		var candidate RouteCandidate
		if err := rows.Scan(&candidate.Agent, &candidate.JobType, &candidate.Runs, &candidate.Failures); err != nil {
			return nil, err
		}
		candidate.FailureRate = float64(candidate.Failures) / float64(candidate.Runs)
		out = append(out, candidate)
	}
	return out, rows.Err()
}

func (candidate RouteCandidate) String() string {
	return fmt.Sprintf("%s\t%s\t%d\t%d\t%.1f%%", candidate.Agent, candidate.JobType, candidate.Runs, candidate.Failures, candidate.FailureRate*100)
}

type RepairPacket struct {
	RunID      string   `json:"run_id"`
	JobID      string   `json:"job_id"`
	Agent      string   `json:"agent"`
	JobType    string   `json:"job_type"`
	Taxonomy   string   `json:"taxonomy"`
	Message    string   `json:"message"`
	Violations []string `json:"violations"`
	Files      []string `json:"files"`
	Commands   []string `json:"commands"`
	Validators []string `json:"failed_validators"`
}

func GenerateRepairPacket(home, runID string) (RepairPacket, error) {
	db, err := Open(home)
	if err != nil {
		return RepairPacket{}, err
	}
	defer db.Close()
	var packet RepairPacket
	err = db.QueryRow("SELECT id,job_id,COALESCE(agent,''),COALESCE(job_type,''),failure_taxonomy,message FROM runs WHERE id=? AND failure_taxonomy<>''", runID).
		Scan(&packet.RunID, &packet.JobID, &packet.Agent, &packet.JobType, &packet.Taxonomy, &packet.Message)
	if err != nil {
		return RepairPacket{}, err
	}
	readStrings := func(query string, target *[]string) error {
		rows, err := db.Query(query, runID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var value string
			if err := rows.Scan(&value); err != nil {
				return err
			}
			*target = append(*target, value)
		}
		return rows.Err()
	}
	if err := readStrings("SELECT detail FROM violations WHERE run_id=? ORDER BY rowid LIMIT 20", &packet.Violations); err != nil {
		return RepairPacket{}, err
	}
	if err := readStrings("SELECT path || ':' || change_type FROM files_touched WHERE run_id=? ORDER BY path LIMIT 50", &packet.Files); err != nil {
		return RepairPacket{}, err
	}
	if err := readStrings("SELECT classification || ': ' || command FROM commands_run WHERE run_id=? ORDER BY rowid LIMIT 20", &packet.Commands); err != nil {
		return RepairPacket{}, err
	}
	if err := readStrings("SELECT command || ': exit=' || exit_code FROM validators WHERE run_id=? AND exit_code<>0 ORDER BY rowid LIMIT 20", &packet.Validators); err != nil {
		return RepairPacket{}, err
	}
	data, err := json.Marshal(packet)
	if err != nil {
		return RepairPacket{}, err
	}
	_, err = db.Exec("INSERT INTO repair_packets(run_id,taxonomy,packet_json,created) VALUES(?,?,?,?)", runID, packet.Taxonomy, string(data), time.Now().UTC().Format(time.RFC3339Nano))
	return packet, err
}

func ClassifyFailure(violations []string) string {
	lower := strings.ToLower(strings.Join(violations, "\n"))
	switch {
	case strings.Contains(lower, "scope-expansion tripwire"):
		return "UNAUTHORIZED_REFACTOR"
	case strings.Contains(lower, "out-of-worktree mutation"), strings.Contains(lower, "write outside"):
		return "SCOPE_DRIFT"
	case strings.Contains(lower, "canary mutation"), strings.Contains(lower, "protected path"), strings.Contains(lower, "forbidden path"):
		return "OVERWRITE_RISK"
	case strings.Contains(lower, "max_commands"):
		return "REPEATED_COMMAND_LOOP"
	case strings.Contains(lower, "validator failed"), strings.Contains(lower, "required file missing"):
		return "VALIDATION_FAILED"
	case strings.Contains(lower, "destructive command"), strings.Contains(lower, "forbidden command"):
		return "DESTRUCTIVE_COMMAND"
	case strings.Contains(lower, "max_"):
		return "BUDGET_EXCEEDED"
	case strings.Contains(lower, "agent"):
		return "AGENT_FAILURE"
	default:
		return "POLICY_VIOLATION"
	}
}

type EvalCase struct {
	Name             string
	Agent            string
	Mode             string
	JobType          string
	Violations       []string
	ExpectedTaxonomy string
	CostUSD          float64
}

type EvalResult struct {
	CaseName string
	Agent    string
	Mode     string
	Passed   bool
	Expected string
	Actual   string
}

type EvalScore struct {
	Agent    string
	Mode     string
	Runs     int
	Passed   int
	PassRate float64
	CostUSD  float64
}

func RunEvalSuite(home, dir string) ([]EvalResult, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var paths []string
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".json" {
			paths = append(paths, filepath.Join(dir, entry.Name()))
		}
	}
	sort.Strings(paths)
	suite, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	db, err := Open(home)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := tx.Exec("DELETE FROM eval_runs WHERE suite=?", suite); err != nil {
		return nil, err
	}
	var results []EvalResult
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var test EvalCase
		if err := json.Unmarshal(data, &test); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		actual := ClassifyFailure(test.Violations)
		result := EvalResult{CaseName: test.Name, Agent: test.Agent, Mode: test.Mode, Passed: actual == test.ExpectedTaxonomy, Expected: test.ExpectedTaxonomy, Actual: actual}
		results = append(results, result)
		if _, err := tx.Exec("INSERT INTO eval_runs(suite,case_name,agent,mode,job_type,passed,taxonomy,cost_usd,created) VALUES(?,?,?,?,?,?,?,?,?)",
			suite, test.Name, test.Agent, test.Mode, test.JobType, result.Passed, actual, test.CostUSD, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			return nil, err
		}
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("no JSON eval cases in %s", dir)
	}
	return results, tx.Commit()
}

func EvalScorecard(home string) ([]EvalScore, error) {
	db, err := Open(home)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.Query("SELECT agent,mode,COUNT(*),SUM(passed),COALESCE(SUM(cost_usd),0) FROM eval_runs GROUP BY agent,mode ORDER BY (1.0*SUM(passed)/COUNT(*)) DESC, agent,mode")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var scores []EvalScore
	for rows.Next() {
		var score EvalScore
		if err := rows.Scan(&score.Agent, &score.Mode, &score.Runs, &score.Passed, &score.CostUSD); err != nil {
			return nil, err
		}
		score.PassRate = float64(score.Passed) / float64(score.Runs)
		scores = append(scores, score)
	}
	return scores, rows.Err()
}

func (score EvalScore) String() string {
	return fmt.Sprintf("%s\t%s\t%d\t%d\t%.1f%%\t$%.4f", score.Agent, score.Mode, score.Runs, score.Passed, score.PassRate*100, score.CostUSD)
}
