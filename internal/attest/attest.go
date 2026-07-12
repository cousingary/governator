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
	"os"
	"os/exec"
	"path/filepath"
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

func canonicalExecutable(bin string) (string, error) {
	if strings.TrimSpace(bin) == "" {
		return "", fmt.Errorf("empty backend executable")
	}
	path := bin
	if !filepath.IsAbs(path) {
		looked, err := exec.LookPath(path)
		if err != nil {
			return "", fmt.Errorf("look up backend executable %q: %w", bin, err)
		}
		path = looked
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if eval, err := filepath.EvalSymlinks(abs); err == nil {
		abs = eval
	}
	return abs, nil
}

func sha256File(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func versionOutput(ctx context.Context, path string) (string, bool) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "--version")
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if len(text) > 4096 {
		text = text[:4096]
	}
	return text, err == nil && ctx.Err() == nil
}

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

func adapterVersion(agent agents.Agent) string { return agent.Name() + "-adapter-v1" }

// Generate probes the current configured executable and produces an
// attestation. The probes are intentionally conservative: a binary that cannot
// identify itself as the expected backend does not get to inherit native
// sandbox/network/transcript claims merely because it sits at backends.X.bin.
func Generate(ctx context.Context, cfg config.Config, backend string) (Attestation, error) {
	agent, err := agents.New(backend)
	if err != nil {
		return Attestation{}, err
	}
	bin := config.BackendBin(agent.Name())
	path, err := canonicalExecutable(bin)
	if err != nil {
		return Attestation{}, err
	}
	sha, err := sha256File(path)
	if err != nil {
		return Attestation{}, fmt.Errorf("hash backend executable %s: %w", path, err)
	}
	version, versionOK := versionOutput(ctx, path)
	matchesBackend := strings.Contains(strings.ToLower(version), expectedToken(agent.Name()))
	cap := agent.Capabilities()
	supported := versionOK && matchesBackend
	now := time.Now().UTC()
	a := Attestation{
		Backend:          agent.Name(),
		AdapterVersion:   adapterVersion(agent),
		ExecutablePath:   path,
		ExecutableSHA256: sha,
		VersionOutput:    version,
		ModelID:          agent.Name(),
		ConfigHash:       cfg.Hash(),
		SupportedFlags:   supported,
		SandboxProbe:     !cap.NativeSandbox || supported,
		NetworkProbe:     !cap.NetworkControl || supported,
		TranscriptProbe:  cap.TranscriptFormat != "" && supported,
		CreatedAt:        now.Format(time.RFC3339Nano),
		ExpiresAt:        now.Add(ttl).Format(time.RFC3339Nano),
	}
	a.ID = a.computeID()
	return a, nil
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

// Current returns the latest attestation matching the current executable hash,
// model and config hash for backend.
func Current(db *sql.DB, cfg config.Config, backend string) (Attestation, bool, error) {
	if err := ensureSchema(db); err != nil {
		return Attestation{}, false, err
	}
	agent, err := agents.New(backend)
	if err != nil {
		return Attestation{}, false, err
	}
	path, err := canonicalExecutable(config.BackendBin(agent.Name()))
	if err != nil {
		return Attestation{}, false, err
	}
	sha, err := sha256File(path)
	if err != nil {
		return Attestation{}, false, err
	}
	row := db.QueryRow(`SELECT id,backend,adapter_version,executable_path,executable_sha256,version_output,model_id,config_hash,supported_flags,sandbox_probe,network_probe,transcript_probe,created_at,expires_at
FROM capability_attestations WHERE backend=? AND executable_path=? AND executable_sha256=? AND config_hash=? AND model_id=? ORDER BY created_at DESC LIMIT 1`, agent.Name(), path, sha, cfg.Hash(), agent.Name())
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
// native sandbox for a high-risk local run, or a fail-closed error.
func VerifyHighRiskNative(db *sql.DB, cfg config.Config, backend string) (string, error) {
	agent, err := agents.New(backend)
	if err != nil {
		return "", err
	}
	cap := agent.Capabilities()
	if !cap.NativeSandbox {
		return "", fmt.Errorf("backend %q does not declare a native sandbox capability", agent.Name())
	}
	a, ok, err := Current(db, cfg, agent.Name())
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
