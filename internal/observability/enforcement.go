package observability

import "database/sql"

// EnforcementRecord (Sol P0-3/P1-15, Session 5) is one governed launch's
// externally observed containment evidence: what enforcement layer actually
// wrapped the launch, whether it removed network access at the kernel level,
// and how many processes the kernel's own cgroup accounting saw this launch
// spawn -- all independent of anything the backend's own transcript claims
// about itself. A run with no enforcement.Plan active (most runs -- only
// effectful medium/high risk_class local runs ever get one) has no row.
type EnforcementRecord struct {
	RunID                 string
	Method                string
	NetworkNamespaced     bool
	ProcessesObservedPeak int
	Created               string
}

func ensureEnforcementSchema(db *sql.DB) error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS enforcement_events(
run_id TEXT PRIMARY KEY,
method TEXT NOT NULL DEFAULT '',
network_namespaced INTEGER NOT NULL DEFAULT 0,
processes_observed_peak INTEGER NOT NULL DEFAULT -1,
created TEXT NOT NULL);`)
	return err
}

// RecordEnforcement persists one run's externally observed containment
// evidence. Idempotent per run_id (a re-recorded observation for the same
// run replaces the prior one) so a recovery pass re-observing state already
// recorded is a no-op rather than an error, matching RecordStage's posture.
func RecordEnforcement(db *sql.DB, r EnforcementRecord) error {
	if err := ensureEnforcementSchema(db); err != nil {
		return err
	}
	_, err := db.Exec(`INSERT INTO enforcement_events(run_id,method,network_namespaced,processes_observed_peak,created) VALUES(?,?,?,?,?)
ON CONFLICT(run_id) DO UPDATE SET method=excluded.method,network_namespaced=excluded.network_namespaced,processes_observed_peak=excluded.processes_observed_peak,created=excluded.created`,
		r.RunID, r.Method, boolInt(r.NetworkNamespaced), r.ProcessesObservedPeak, r.Created)
	return err
}

// EnforcementForRun returns runID's recorded enforcement evidence, if any --
// for tests and CLI/audit inspection.
func EnforcementForRun(db *sql.DB, runID string) (EnforcementRecord, bool, error) {
	if err := ensureEnforcementSchema(db); err != nil {
		return EnforcementRecord{}, false, err
	}
	var r EnforcementRecord
	var networkNamespaced int
	err := db.QueryRow(`SELECT run_id,method,network_namespaced,processes_observed_peak,created FROM enforcement_events WHERE run_id=?`, runID).
		Scan(&r.RunID, &r.Method, &networkNamespaced, &r.ProcessesObservedPeak, &r.Created)
	if err == sql.ErrNoRows {
		return EnforcementRecord{}, false, nil
	}
	if err != nil {
		return EnforcementRecord{}, false, err
	}
	r.NetworkNamespaced = networkNamespaced != 0
	return r, true, nil
}
