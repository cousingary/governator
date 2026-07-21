package observability

import (
	"database/sql"
	"encoding/json"
	"strings"
)

// EnforcementRecord is the kernel containment evidence for one governed
// launch, split into three distinct evidence classes so no field's name
// implies stronger proof than the implementation gives it (Sol9 P1-5: the
// prior single-tier field set let "declared" and "observed" values share
// vocabulary, and ObservedNetworkAttempts carried a permanent sentinel -1
// that read as a real, if empty, observation instead of "not implemented"):
//
//   - declared authority: what the caller asked for (DeclaredNetworkPolicy,
//     DeclaredWriteRoots, DeclaredCredentialPolicy).
//   - applied enforcement: what the containment mechanism was actually
//     configured to enforce (EnforcedNetworkPolicy, NetworkDenialMechanism,
//     KernelReadEnvelope, LandlockABI).
//   - observed effects: what was actually witnessed after the fact
//     (ActualWriteSet, ProcessesObservedPeak, ObservedCredentialAccess,
//     OutputConsequence, NetworkAttemptObservation). A field in this class
//     that cannot yet be measured must say so explicitly (e.g.
//     NetworkAttemptObservation = "unavailable") rather than encode
//     "not implemented" as a value indistinguishable from a real zero.
type EnforcementRecord struct {
	RunID                     string
	Method                    string
	NetworkNamespaced         bool
	ProcessesObservedPeak     int
	LandlockABI               int
	KernelReadEnvelope        []string
	DeclaredNetworkPolicy     string
	EnforcedNetworkPolicy     string
	NetworkAttemptObservation string
	NetworkDenialMechanism    string
	DeclaredWriteRoots        []string
	ActualWriteSet            []string
	DeclaredCredentialPolicy  string
	ObservedCredentialAccess  string
	OutputConsequence         string
	// ConsumedArtifactBoundary is the mechanism actually used to make this
	// run's consumed artifacts read-only to the backend (Sol10 P0-1):
	// "landlock-mount-namespace-ro-bind" (local runner, host containment
	// active), "docker-ro-bind-mount" (docker runner), "mode-bits-degraded"
	// (host containment disabled by operator config -- a courtesy, not a
	// boundary), or "" when the run declared no consumed artifacts at all.
	// Applied enforcement evidence, like Method -- what was actually
	// configured, not merely requested.
	ConsumedArtifactBoundary string
	Created                  string
}

func ensureEnforcementSchema(db *sql.DB) error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS enforcement_events(
run_id TEXT PRIMARY KEY,
method TEXT NOT NULL DEFAULT '',
network_namespaced INTEGER NOT NULL DEFAULT 0,
processes_observed_peak INTEGER NOT NULL DEFAULT -1,
landlock_abi INTEGER NOT NULL DEFAULT 0,
kernel_read_envelope TEXT NOT NULL DEFAULT '[]',
declared_network_policy TEXT NOT NULL DEFAULT '',
enforced_network_policy TEXT NOT NULL DEFAULT '',
network_attempt_observation TEXT NOT NULL DEFAULT '',
network_denial_mechanism TEXT NOT NULL DEFAULT '',
declared_write_roots TEXT NOT NULL DEFAULT '[]',
actual_write_set TEXT NOT NULL DEFAULT '[]',
declared_credential_policy TEXT NOT NULL DEFAULT '',
observed_credential_access TEXT NOT NULL DEFAULT '',
output_consequence TEXT NOT NULL DEFAULT '',
consumed_artifact_boundary TEXT NOT NULL DEFAULT '',
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
	for _, stmt := range []string{
		`ALTER TABLE enforcement_events ADD COLUMN declared_network_policy TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE enforcement_events ADD COLUMN enforced_network_policy TEXT NOT NULL DEFAULT ''`,
		// Sol9 P1-5: observed_network_attempts (INTEGER, sentinel -1 forever)
		// replaced by two honest string fields -- rc2 ledgers keep the old
		// column as an unread vestige rather than attempting a destructive
		// SQLite column drop/rename mid-migration.
		`ALTER TABLE enforcement_events ADD COLUMN network_attempt_observation TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE enforcement_events ADD COLUMN network_denial_mechanism TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE enforcement_events ADD COLUMN declared_write_roots TEXT NOT NULL DEFAULT '[]'`,
		`ALTER TABLE enforcement_events ADD COLUMN actual_write_set TEXT NOT NULL DEFAULT '[]'`,
		// credential_exposure (mixed declared/observed semantics depending on
		// call site) split into its two evidence classes.
		`ALTER TABLE enforcement_events ADD COLUMN declared_credential_policy TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE enforcement_events ADD COLUMN observed_credential_access TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE enforcement_events ADD COLUMN output_consequence TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE enforcement_events ADD COLUMN consumed_artifact_boundary TEXT NOT NULL DEFAULT ''`,
	} {
		field := strings.Fields(stmt)[5]
		if cols[field] {
			continue
		}
		if _, err := db.Exec(stmt); err != nil {
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
	declaredWrites, err := json.Marshal(r.DeclaredWriteRoots)
	if err != nil {
		return err
	}
	actualWrites, err := json.Marshal(r.ActualWriteSet)
	if err != nil {
		return err
	}
	_, err = db.Exec(`INSERT INTO enforcement_events(run_id,method,network_namespaced,processes_observed_peak,landlock_abi,kernel_read_envelope,declared_network_policy,enforced_network_policy,network_attempt_observation,network_denial_mechanism,declared_write_roots,actual_write_set,declared_credential_policy,observed_credential_access,output_consequence,consumed_artifact_boundary,created) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(run_id) DO UPDATE SET method=excluded.method,network_namespaced=excluded.network_namespaced,processes_observed_peak=excluded.processes_observed_peak,landlock_abi=excluded.landlock_abi,kernel_read_envelope=excluded.kernel_read_envelope,declared_network_policy=excluded.declared_network_policy,enforced_network_policy=excluded.enforced_network_policy,network_attempt_observation=excluded.network_attempt_observation,network_denial_mechanism=excluded.network_denial_mechanism,declared_write_roots=excluded.declared_write_roots,actual_write_set=excluded.actual_write_set,declared_credential_policy=excluded.declared_credential_policy,observed_credential_access=excluded.observed_credential_access,output_consequence=excluded.output_consequence,consumed_artifact_boundary=excluded.consumed_artifact_boundary,created=excluded.created`,
		r.RunID, r.Method, boolInt(r.NetworkNamespaced), r.ProcessesObservedPeak, r.LandlockABI, string(envelope), r.DeclaredNetworkPolicy, r.EnforcedNetworkPolicy, r.NetworkAttemptObservation, r.NetworkDenialMechanism, string(declaredWrites), string(actualWrites), r.DeclaredCredentialPolicy, r.ObservedCredentialAccess, r.OutputConsequence, r.ConsumedArtifactBoundary, r.Created)
	return err
}

func EnforcementForRun(db *sql.DB, runID string) (EnforcementRecord, bool, error) {
	if err := ensureEnforcementSchema(db); err != nil {
		return EnforcementRecord{}, false, err
	}
	var r EnforcementRecord
	var networkNamespaced int
	var envelope, declaredWrites, actualWrites string
	err := db.QueryRow(`SELECT run_id,method,network_namespaced,processes_observed_peak,landlock_abi,kernel_read_envelope,declared_network_policy,enforced_network_policy,network_attempt_observation,network_denial_mechanism,declared_write_roots,actual_write_set,declared_credential_policy,observed_credential_access,output_consequence,consumed_artifact_boundary,created FROM enforcement_events WHERE run_id=?`, runID).
		Scan(&r.RunID, &r.Method, &networkNamespaced, &r.ProcessesObservedPeak, &r.LandlockABI, &envelope, &r.DeclaredNetworkPolicy, &r.EnforcedNetworkPolicy, &r.NetworkAttemptObservation, &r.NetworkDenialMechanism, &declaredWrites, &actualWrites, &r.DeclaredCredentialPolicy, &r.ObservedCredentialAccess, &r.OutputConsequence, &r.ConsumedArtifactBoundary, &r.Created)
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
	if err := json.Unmarshal([]byte(declaredWrites), &r.DeclaredWriteRoots); err != nil {
		return EnforcementRecord{}, false, err
	}
	if err := json.Unmarshal([]byte(actualWrites), &r.ActualWriteSet); err != nil {
		return EnforcementRecord{}, false, err
	}
	return r, true, nil
}
