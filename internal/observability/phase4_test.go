package observability

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestClassifyFailureAssayViolation(t *testing.T) {
	got := ClassifyFailure([]string{"assay: profile=coding-output-v1 verdict=fail failed_checks=no_boilerplate:content reason=see failed_checks"})
	if got != "ASSAY_FAILED" {
		t.Fatalf("expected ASSAY_FAILED, got %s", got)
	}
}

func TestNegativeRoutingAndRepairPacket(t *testing.T) {
	home := t.TempDir()
	db, err := Open(home)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO agent_profiles(agent,job_type,runs,valid_outputs,failures,total_cost_usd) VALUES('safe','fix',10,9,1,1),('risky','fix',10,5,5,1)")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO runs(id,job_id,job_type,agent,status,message,created,failure_taxonomy) VALUES('run-1','job-1','fix','risky','QUARANTINED','scope escaped','now','SCOPE_DRIFT')")
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		"INSERT INTO violations(run_id,kind,detail) VALUES('run-1','SCOPE_DRIFT','write outside intended_writes: extra.txt')",
		"INSERT INTO files_touched(run_id,path,change_type) VALUES('run-1','extra.txt','new')",
		"INSERT INTO commands_run(run_id,command,classification) VALUES('run-1','test','execute shell')",
		"INSERT INTO validators(run_id,command,exit_code,output) VALUES('run-1','test -f expected',1,'missing')",
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()

	candidates, err := RouteAgents(home, "fix")
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 2 || candidates[0].Agent != "safe" || candidates[0].FailureRate != 0.1 {
		t.Fatalf("unexpected route: %#v", candidates)
	}
	packet, err := GenerateRepairPacket(home, "run-1")
	if err != nil {
		t.Fatal(err)
	}
	if packet.Taxonomy != "SCOPE_DRIFT" || len(packet.Violations) != 1 || len(packet.Validators) != 1 {
		t.Fatalf("unexpected packet: %#v", packet)
	}
	db, err = Open(home)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM repair_packets WHERE run_id='run-1'").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("repair packet count=%d", count)
	}
}

func TestRepairAttemptsCountsFlatLineageNotChain(t *testing.T) {
	home := t.TempDir()
	db, err := Open(home)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if n, err := RepairAttempts(db, ""); err != nil || n != 0 {
		t.Fatalf("empty rootID: n=%d err=%v", n, err)
	}
	if n, err := RepairAttempts(db, "root-1"); err != nil || n != 0 {
		t.Fatalf("no attempts yet: n=%d err=%v", n, err)
	}
	// A repair of a repair still records repair_of=root-1 (flat lineage, not
	// a chain to its immediate parent), so counting is a single flat query.
	for _, stmt := range []string{
		"INSERT INTO runs(id,job_id,status,created,repair_of) VALUES('root-1','job-1','QUARANTINED','t0','')",
		"INSERT INTO runs(id,job_id,status,created,repair_of) VALUES('repair-1','job-1','QUARANTINED','t1','root-1')",
		"INSERT INTO runs(id,job_id,status,created,repair_of) VALUES('repair-2','job-1','APPROVED','t2','root-1')",
		"INSERT INTO runs(id,job_id,status,created,repair_of) VALUES('unrelated','job-2','QUARANTINED','t3','')",
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := RepairAttempts(db, "root-1"); err != nil || n != 2 {
		t.Fatalf("expected 2 attempts for root-1, got n=%d err=%v", n, err)
	}
}

func TestEvalSuiteProducesScorecard(t *testing.T) {
	home := t.TempDir()
	dir := t.TempDir()
	cases := []EvalCase{
		{Name: "scope", Agent: "safe", Mode: "surgeon", JobType: "fix", Violations: []string{"write outside intended_writes"}, ExpectedTaxonomy: "SCOPE_DRIFT"},
		{Name: "overwrite", Agent: "safe", Mode: "surgeon", JobType: "fix", Violations: []string{"protected path mutation"}, ExpectedTaxonomy: "OVERWRITE_RISK"},
	}
	for i, test := range cases {
		data, err := json.Marshal(test)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, string(rune('a'+i))+".json"), data, 0644); err != nil {
			t.Fatal(err)
		}
	}
	results, err := RunEvalSuite(home, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 || !results[0].Passed || !results[1].Passed {
		t.Fatalf("unexpected eval results: %#v", results)
	}
	scores, err := EvalScorecard(home)
	if err != nil {
		t.Fatal(err)
	}
	if len(scores) != 1 || scores[0].Runs != 2 || scores[0].Passed != 2 || scores[0].PassRate != 1 {
		t.Fatalf("unexpected scorecard: %#v", scores)
	}
}
