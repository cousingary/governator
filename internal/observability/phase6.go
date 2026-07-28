package observability

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"time"
)

type ParityEvent struct {
	Payload            string
	PayloadHash        string
	GoDecision         string
	PythonDecision     string
	Match              bool
	PythonUnavailable  bool
	ShadowScriptPath   string
	ShadowScriptSHA256 string
	Created            string
}

type ParityReport struct {
	Total        int
	Matches      int
	Mismatches   int
	Unavailable  int
	CoverageDays float64
	Events       []ParityEvent
}

func RecordParity(home string, event ParityEvent) error {
	db, err := Open(home)
	if err != nil {
		return err
	}
	defer db.Close()
	if event.PayloadHash == "" {
		sum := sha256.Sum256([]byte(event.Payload))
		event.PayloadHash = hex.EncodeToString(sum[:])
	}
	if event.Created == "" {
		event.Created = time.Now().UTC().Format(time.RFC3339Nano)
	}
	_, err = db.Exec(`INSERT INTO parity_events(payload_hash,payload,go_decision,py_decision,matched,py_unavailable,shadow_script_path,shadow_script_sha256,created) VALUES(?,?,?,?,?,?,?,?,?)`,
		event.PayloadHash, event.Payload, event.GoDecision, event.PythonDecision, boolInt(event.Match), boolInt(event.PythonUnavailable), event.ShadowScriptPath, event.ShadowScriptSHA256, event.Created)
	return err
}

func ParitySummary(home string) (ParityReport, error) {
	db, err := Open(home)
	if err != nil {
		return ParityReport{}, err
	}
	defer db.Close()
	var report ParityReport
	var first, last sql.NullString
	err = db.QueryRow(`SELECT COUNT(*),COALESCE(SUM(matched),0),COALESCE(SUM(CASE WHEN matched=0 AND py_unavailable=0 THEN 1 ELSE 0 END),0),COALESCE(SUM(py_unavailable),0),MIN(created),MAX(created) FROM parity_events`).Scan(
		&report.Total, &report.Matches, &report.Mismatches, &report.Unavailable, &first, &last)
	if err != nil {
		return report, err
	}
	if first.Valid && last.Valid {
		a, aErr := time.Parse(time.RFC3339Nano, first.String)
		b, bErr := time.Parse(time.RFC3339Nano, last.String)
		if aErr == nil && bErr == nil {
			report.CoverageDays = b.Sub(a).Hours() / 24
		}
	}
	// govratchet:sql-time-allow(s4_semantics_review)
	rows, err := db.Query(`SELECT payload_hash,payload,go_decision,py_decision,matched,py_unavailable,shadow_script_path,shadow_script_sha256,created FROM parity_events WHERE matched=0 OR py_unavailable=1 ORDER BY created DESC`)
	if err != nil {
		return report, err
	}
	defer rows.Close()
	for rows.Next() {
		var event ParityEvent
		if err := rows.Scan(&event.PayloadHash, &event.Payload, &event.GoDecision, &event.PythonDecision, &event.Match, &event.PythonUnavailable, &event.ShadowScriptPath, &event.ShadowScriptSHA256, &event.Created); err != nil {
			return report, err
		}
		report.Events = append(report.Events, event)
	}
	return report, rows.Err()
}
