package observability

import (
	"database/sql"
	"encoding/json"
)

// EnforcementRecord is the kernel containment evidence for one governed
// launch. KernelReadEnvelope is the exact pre-resolved set admitted by
// Landlock; recording it makes broad-root regressions visible in evidence.
type EnforcementRecord struct {
	RunID                 string
	Method                string
	NetworkNamespaced     bool
	ProcessesObservedPeak int
	LandlockABI           int
	KernelReadEnvelope    []string
	Created               string
}

func ensureEnforcementSchema(db *sql.DB) error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS enforcement_events(
run_id TEXT PRIMARY KEY,
method TEXT NOT NULL DEFAULT '',
network_namespaced INTEGER NOT NULL DEFAULT 0,
processes_observed_peak INTEGER NOT NULL DEFAULT -1,
landlock_abi INTEGER NOT NULL DEFAULT 0,
kernel_read_envelope TEXT NOT NULL DEFAULT '[]',
created TEXT NOT NULL);`); err != nil {
		return err
	}
	// Existing ledgers predate S5 evidence fields. Duplicate-column errors are
	// harmless; check the live schema before altering to keep migration exact.
	rows, err := db.Query(`PRAGMA table_info(enforcement_events)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	cols := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, typ string
		var notnull, pk int
		var def any
		if err := rows.Scan(&cid, &name, &typ, &notnull, &def, &pk); err != nil {
			return err
		}
		cols[name] = true
	}
	if !cols["landlock_abi"] {
		if _, err := db.Exec(`ALTER TABLE enforcement_events ADD COLUMN landlock_abi INTEGER NOT NULL DEFAULT 0`); err != nil {
			return err
		}
	}
	if !cols["kernel_read_envelope"] {
		if _, err := db.Exec(`ALTER TABLE enforcement_events ADD COLUMN kernel_read_envelope TEXT NOT NULL DEFAULT '[]'`); err != nil {
			return err
		}
	}
	return nil
}

func RecordEnforcement(db *sql.DB, r EnforcementRecord) error {
	if err := ensureEnforcementSchema(db); err != nil {
		return err
	}
	envelope, err := json.Marshal(r.KernelReadEnvelope)
	if err != nil {
		return err
	}
	_, err = db.Exec(`INSERT INTO enforcement_events(run_id,method,network_namespaced,processes_observed_peak,landlock_abi,kernel_read_envelope,created) VALUES(?,?,?,?,?,?,?)
ON CONFLICT(run_id) DO UPDATE SET method=excluded.method,network_namespaced=excluded.network_namespaced,processes_observed_peak=excluded.processes_observed_peak,landlock_abi=excluded.landlock_abi,kernel_read_envelope=excluded.kernel_read_envelope,created=excluded.created`,
		r.RunID, r.Method, boolInt(r.NetworkNamespaced), r.ProcessesObservedPeak, r.LandlockABI, string(envelope), r.Created)
	return err
}

func EnforcementForRun(db *sql.DB, runID string) (EnforcementRecord, bool, error) {
	if err := ensureEnforcementSchema(db); err != nil {
		return EnforcementRecord{}, false, err
	}
	var r EnforcementRecord
	var networkNamespaced int
	var envelope string
	err := db.QueryRow(`SELECT run_id,method,network_namespaced,processes_observed_peak,landlock_abi,kernel_read_envelope,created FROM enforcement_events WHERE run_id=?`, runID).
		Scan(&r.RunID, &r.Method, &networkNamespaced, &r.ProcessesObservedPeak, &r.LandlockABI, &envelope, &r.Created)
	if err == sql.ErrNoRows {
		return EnforcementRecord{}, false, nil
	}
	if err != nil {
		return EnforcementRecord{}, false, err
	}
	r.NetworkNamespaced = networkNamespaced != 0
	if err := json.Unmarshal([]byte(envelope), &r.KernelReadEnvelope); err != nil {
		return EnforcementRecord{}, false, err
	}
	return r, true, nil
}
