// Package attest binds native backend capability claims to the executable that
// will actually be launched. Static adapter capabilities are only expectations;
// high-risk local runs need a fresh ledgered attestation for the current
// binary hash/config/model before those native capabilities can satisfy
// containment.
package attest

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/cousingary/governator/internal/agents"
	"github.com/cousingary/governator/internal/config"
)

const ttl = 24 * time.Hour

// Attestation is the durable evidence stored in the Governator ledger. The ID
// is a SHA-256 over every trust-bearing field, so it is safe to feed into the
// ExecutionIdentity replay key.
type Attestation struct {
	ID               string `json:"id"`
	Backend          string `json:"backend"`
	AdapterVersion   string `json:"adapter_version"`
	ExecutablePath   string `json:"executable_path"`
	ExecutableSHA256 string `json:"executable_sha256"`
	VersionOutput    string `json:"version_output"`
	ModelID          string `json:"model_id"`
	ConfigHash       string `json:"config_hash"`
	SupportedFlags   bool   `json:"supported_flags"`
	SandboxProbe     bool   `json:"sandbox_probe"`
	NetworkProbe     bool   `json:"network_probe"`
	TranscriptProbe  bool   `json:"transcript_probe"`
	CreatedAt        string `json:"created_at"`
	ExpiresAt        string `json:"expires_at"`
}

func ensureSchema(db *sql.DB) error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS capability_attestations(
id TEXT PRIMARY KEY, backend TEXT NOT NULL, adapter_version TEXT NOT NULL DEFAULT '', executable_path TEXT NOT NULL,
executable_sha256 TEXT NOT NULL, version_output TEXT NOT NULL DEFAULT '', model_id TEXT NOT NULL DEFAULT '', config_hash TEXT NOT NULL DEFAULT '',
supported_flags INTEGER NOT NULL DEFAULT 0, sandbox_probe INTEGER NOT NULL DEFAULT 0, network_probe INTEGER NOT NULL DEFAULT 0, transcript_probe INTEGER NOT NULL DEFAULT 0,
created_at TEXT NOT NULL, expires_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS capability_attestations_lookup ON capability_attestations(backend, executable_path, executable_sha256, config_hash, model_id, created_at);`)
	return err
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func intBool(v int) bool { return v != 0 }

func expectedToken(backend string) string {
	switch backend {
	case "claude-code", "claude":
		return "claude"
	case "codex":
		return "codex"
	case "glm":
		return "glm"
	case "opencode":
		return "opencode"
	case "pi":
		return "pi"
	default:
		return backend
	}
}

// Generate probes the current configured executable and produces an
// attestation. The probes are intentionally conservative: a binary that cannot
// identify itself as the expected backend does not get to inherit native
// sandbox/network/transcript claims merely because it sits at backends.X.bin.
//
// Per Sol Finding 5: resolution (path/canonicalization/hash/version) is
// delegated entirely to agents.Resolve, the single canonical resolution
// implementation also used by execution identity and (via GenerateFromResolution
// below) attestation lookup — Generate no longer maintains its own separate
// LookPath/hash/version-probe logic that could drift from what identity.go or
// the actual launch observed.
func Generate(ctx context.Context, cfg config.Config, backend string) (Attestation, error) {
	agent, err := agents.New(backend)
	if err != nil {
		return Attestation{}, err
	}
	res, err := agents.Resolve(ctx, agent)
	if err != nil {
		return Attestation{}, err
	}
	return GenerateFromResolution(cfg, agent, res), nil
}

// GenerateFromResolution builds an attestation from a resolution already
// computed elsewhere in the current run, so a caller that resolved the
// backend once (Sol Finding 5) never triggers a second independent
// resolution just to mint an attestation.
func GenerateFromResolution(cfg config.Config, agent agents.Agent, res agents.Resolution) Attestation {
	matchesBackend := strings.Contains(strings.ToLower(res.VersionOutput), expectedToken(agent.Name()))
	cap := agent.Capabilities()
	supported := res.VersionOK && matchesBackend
	now := time.Now().UTC()
	a := Attestation{
		Backend:          agent.Name(),
		AdapterVersion:   res.AdapterVersion,
		ExecutablePath:   res.CanonicalPath,
		ExecutableSHA256: res.SHA256,
		VersionOutput:    res.VersionOutput,
		ModelID:          res.ModelID,
		ConfigHash:       cfg.Hash(),
		SupportedFlags:   supported,
		SandboxProbe:     !cap.NativeSandbox || supported,
		NetworkProbe:     !cap.NetworkControl || supported,
		TranscriptProbe:  cap.TranscriptFormat != "" && supported,
		CreatedAt:        now.Format(time.RFC3339Nano),
		ExpiresAt:        now.Add(ttl).Format(time.RFC3339Nano),
	}
	a.ID = a.computeID()
	return a
}

func (a Attestation) computeID() string {
	material := fmt.Sprintf("backend=%s\nadapter=%s\npath=%s\nsha=%s\nversion=%s\nmodel=%s\nconfig=%s\nflags=%t\nsandbox=%t\nnetwork=%t\ntranscript=%t\nexpires=%s\n",
		a.Backend, a.AdapterVersion, a.ExecutablePath, a.ExecutableSHA256, a.VersionOutput, a.ModelID, a.ConfigHash,
		a.SupportedFlags, a.SandboxProbe, a.NetworkProbe, a.TranscriptProbe, a.ExpiresAt)
	sum := sha256.Sum256([]byte(material))
	return hex.EncodeToString(sum[:])
}

// Store persists an attestation in the Governator ledger.
func Store(db *sql.DB, a Attestation) error {
	if err := ensureSchema(db); err != nil {
		return err
	}
	_, err := db.Exec(`INSERT INTO capability_attestations(id,backend,adapter_version,executable_path,executable_sha256,version_output,model_id,config_hash,supported_flags,sandbox_probe,network_probe,transcript_probe,created_at,expires_at)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, a.ID, a.Backend, a.AdapterVersion, a.ExecutablePath, a.ExecutableSHA256, a.VersionOutput, a.ModelID, a.ConfigHash, boolInt(a.SupportedFlags), boolInt(a.SandboxProbe), boolInt(a.NetworkProbe), boolInt(a.TranscriptProbe), a.CreatedAt, a.ExpiresAt)
	return err
}

// Current returns the latest attestation matching resolution's canonical
// path/hash, model and config hash for backend.
//
// Per Sol Finding 5: resolution must be the same PathResolution the caller
// already produced once for this run (e.g. via enforceContainment) — Current
// never independently re-resolves the configured binary, so a lookup here is
// guaranteed to be checking the exact file that will attest/launch, not a
// second, potentially different, PATH resolution taken moments apart.
func Current(db *sql.DB, cfg config.Config, agent agents.Agent, resolution agents.PathResolution) (Attestation, bool, error) {
	if err := ensureSchema(db); err != nil {
		return Attestation{}, false, err
	}
	row := db.QueryRow(`SELECT id,backend,adapter_version,executable_path,executable_sha256,version_output,model_id,config_hash,supported_flags,sandbox_probe,network_probe,transcript_probe,created_at,expires_at
FROM capability_attestations WHERE backend=? AND executable_path=? AND executable_sha256=? AND config_hash=? AND model_id=? ORDER BY created_at DESC LIMIT 1`, agent.Name(), resolution.CanonicalPath, resolution.SHA256, cfg.Hash(), agent.Name())
	var a Attestation
	var supported, sandbox, network, transcript int
	if err := row.Scan(&a.ID, &a.Backend, &a.AdapterVersion, &a.ExecutablePath, &a.ExecutableSHA256, &a.VersionOutput, &a.ModelID, &a.ConfigHash, &supported, &sandbox, &network, &transcript, &a.CreatedAt, &a.ExpiresAt); err != nil {
		if err == sql.ErrNoRows {
			return Attestation{}, false, nil
		}
		return Attestation{}, false, err
	}
	a.SupportedFlags, a.SandboxProbe, a.NetworkProbe, a.TranscriptProbe = intBool(supported), intBool(sandbox), intBool(network), intBool(transcript)
	return a, true, nil
}

// VerifyHighRiskNative returns the attestation ID that authorizes backend's
// native sandbox for a high-risk local run, or a fail-closed error. agent and
// resolution must be the same values the caller resolved once for this run
// (Sol Finding 5) — VerifyHighRiskNative performs no resolution of its own.
func VerifyHighRiskNative(db *sql.DB, cfg config.Config, agent agents.Agent, resolution agents.PathResolution) (string, error) {
	cap := agent.Capabilities()
	if !cap.NativeSandbox {
		return "", fmt.Errorf("backend %q does not declare a native sandbox capability", agent.Name())
	}
	a, ok, err := Current(db, cfg, agent, resolution)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("capability attestation required for high-risk local backend %q: run gov attest %s", agent.Name(), agent.Name())
	}
	expires, err := time.Parse(time.RFC3339Nano, a.ExpiresAt)
	if err != nil || !expires.After(time.Now().UTC()) {
		return "", fmt.Errorf("capability attestation for backend %q is stale or malformed", agent.Name())
	}
	if !a.SupportedFlags || !a.SandboxProbe || (cap.NetworkControl && !a.NetworkProbe) || !a.TranscriptProbe {
		return "", fmt.Errorf("capability attestation for backend %q failed required probes", agent.Name())
	}
	return a.ID, nil
}
