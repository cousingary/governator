package observability

import "database/sql"

// EffectKind names one category of kernel-observed effect a governed launch
// can produce. Sol redteam v4 S9 asks for "a kernel-observed effect ledger
// for high-risk local jobs: file writes, process creation, network
// destinations, executable launches, mounts — compared against the
// transcript." EnforcementRecord (Session 5) already captures one summary
// row per run (method, network_namespaced, peak process count);
// EffectRecord generalizes that into a per-effect, per-run append log so
// each individual observation — which files actually changed on disk, which
// binary actually launched, whether egress was namespaced — is its own row,
// inspectable and comparable against the transcript's own claims
// independently of the others.
type EffectKind string

const (
	EffectFileWrite        EffectKind = "file_write"
	EffectProcessCreation  EffectKind = "process_creation"
	EffectNetwork          EffectKind = "network"
	EffectExecutableLaunch EffectKind = "executable_launch"
	EffectMount            EffectKind = "mount"
)

// EffectRecord is one kernel-observed effect. Detail is kind-specific JSON:
//   - file_write: not populated through this table — the files_touched
//     table (RecordCompletion, sourced from the same kernel-level workspace
//     snapshot diff this package's doc once proposed duplicating here) has
//     already ledgered exactly this, per run, since long before S9. Kept as
//     a defined EffectKind for completeness/documentation of the full set
//     S9 names, not because runtime.go writes it a second time here.
//   - process_creation: the containment package's ExtinctionProof JSON
//     (peak process count, extinction confirmation) — kernel cgroup
//     accounting, not the transcript's own process-count claims.
//   - network: {"namespaced": true|false} — whether this launch had egress
//     removed at the kernel level (internal/enforce), independent of
//     anything the backend claims about network calls it did or didn't make.
//   - executable_launch: the resolved BackendExecutionHandle identity
//     (canonical path, sha256, device+inode, owner/mode) — which exact
//     binary the kernel actually exec'd, from Sol redteam v4 S3.
//   - mount: not populated in this environment. Governator's local
//     containment is cgroup v2 + Landlock + a network namespace (S2/S5);
//     it does not currently construct a private mount namespace per run, so
//     there is nothing to kernel-observe here yet. Left as a defined kind
//     rather than omitted so a future mount-namespace session has a ledger
//     to write into instead of inventing a new one.
type EffectRecord struct {
	RunID   string
	Kind    EffectKind
	Detail  string
	Created string
}

func ensureEffectsSchema(db *sql.DB) error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS effect_events(
id INTEGER PRIMARY KEY AUTOINCREMENT,
run_id TEXT NOT NULL,
kind TEXT NOT NULL,
detail TEXT NOT NULL DEFAULT '',
created TEXT NOT NULL);`); err != nil {
		return err
	}
	_, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_effect_events_run ON effect_events(run_id);`)
	return err
}

// RecordEffects appends every record in one transaction. Like RecordArtifacts
// and RecordCompletion's Files/Commands, this is audit evidence recorded
// after the fact — callers treat a write failure as best-effort (durably
// queued via noteOperationalFailure, same as EnforcementRecord), never as a
// reason to change a run's already-decided outcome.
func RecordEffects(db *sql.DB, records []EffectRecord) error {
	if len(records) == 0 {
		return nil
	}
	if err := ensureEffectsSchema(db); err != nil {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, r := range records {
		if _, err := tx.Exec(`INSERT INTO effect_events(run_id,kind,detail,created) VALUES(?,?,?,?)`,
			r.RunID, string(r.Kind), r.Detail, r.Created); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// EffectsForRun returns every effect recorded for runID, oldest first — for
// `gov run inspect` and tests.
func EffectsForRun(db *sql.DB, runID string) ([]EffectRecord, error) {
	if err := ensureEffectsSchema(db); err != nil {
		return nil, err
	}
	rows, err := db.Query(`SELECT run_id,kind,detail,created FROM effect_events WHERE run_id=? ORDER BY id ASC`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EffectRecord
	for rows.Next() {
		var r EffectRecord
		var kind string
		if err := rows.Scan(&r.RunID, &kind, &r.Detail, &r.Created); err != nil {
			return nil, err
		}
		r.Kind = EffectKind(kind)
		out = append(out, r)
	}
	return out, rows.Err()
}
