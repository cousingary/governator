package agents

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/cousingary/governator/internal/config"
	"github.com/cousingary/governator/internal/controllerenv"
)

// PathResolution is the identity-bearing subset of canonical backend
// resolution: everything needed to know exactly which file on disk a
// configured backend name refers to, without executing it.
//
// Per Sol Finding 5: a bare name (backends.pi.bin: pi) was previously hashed
// as the literal string "pi" instead of being resolved through PATH first,
// producing an "unreadable:pi" sentinel that never changed when the real
// executable was swapped — replay and attestation both trusted a value that
// bore no relationship to what would actually launch. ResolvePath closes that
// gap: it resolves the configured name through PATH exactly once, canonicalizes
// symlinks, and hashes the real file. Every trust-bearing consumer
// (attestation, execution identity, replay, the actual launch, audit output)
// must be built from the same PathResolution/Resolution value for a given
// run — never re-resolve independently at a later call site.
type PathResolution struct {
	Backend       string // agent.Name()
	Requested     string // as configured (config.BackendBin(name)); bare name or absolute path
	ResolvedPath  string // PATH-resolved absolute path (exec.LookPath), before symlink evaluation
	CanonicalPath string // symlink-resolved absolute path; the file actually hashed and launched
	FileIdentity  string // platform file identity (device/inode on Unix); diagnostic, "path=..." fallback
	SHA256        string // content hash of CanonicalPath
}

// Resolution is the full canonical resolution record: PathResolution plus the
// executable's self-reported version output and adapter/model identity.
// Building it runs a bounded "--version" probe, so callers that only need
// path/hash identity (execution identity, replay, launch, attestation lookup)
// should use ResolvePath instead and reserve Resolve for flows that need
// version evidence (fresh attestation generation).
type Resolution struct {
	PathResolution
	VersionOutput  string
	VersionOK      bool
	AdapterID      string
	AdapterVersion string
	ModelID        string
}

// ResolvePath resolves agent's configured backend binary exactly once into
// its canonical, content-addressed identity. A binary that cannot be found on
// PATH, or whose content cannot be read, fails closed with an error — never a
// sentinel value that silently keeps matching across a swap.
func ResolvePath(agent Agent) (PathResolution, error) {
	requested := config.BackendBin(agent.Name())
	if strings.TrimSpace(requested) == "" {
		return PathResolution{}, fmt.Errorf("resolve backend %q: empty executable configured", agent.Name())
	}
	resolvedPath := requested
	if !filepath.IsAbs(resolvedPath) {
		looked, err := exec.LookPath(resolvedPath)
		if err != nil {
			return PathResolution{}, fmt.Errorf("resolve backend %q: look up executable %q: %w", agent.Name(), requested, err)
		}
		resolvedPath = looked
	}
	abs, err := filepath.Abs(resolvedPath)
	if err != nil {
		return PathResolution{}, fmt.Errorf("resolve backend %q: %w", agent.Name(), err)
	}
	canonical := abs
	if eval, err := filepath.EvalSymlinks(abs); err == nil {
		canonical = eval
	}
	sha, err := sha256File(canonical)
	if err != nil {
		return PathResolution{}, fmt.Errorf("resolve backend %q: hash executable %s: %w", agent.Name(), canonical, err)
	}
	return PathResolution{
		Backend:       agent.Name(),
		Requested:     requested,
		ResolvedPath:  abs,
		CanonicalPath: canonical,
		FileIdentity:  fileIdentity(canonical),
		SHA256:        sha,
	}, nil
}

// Resolve extends ResolvePath with a bounded "--version" probe and static
// adapter/model identity, producing the full record required to generate a
// fresh capability attestation.
func Resolve(ctx context.Context, agent Agent) (Resolution, error) {
	pr, err := ResolvePath(agent)
	if err != nil {
		return Resolution{}, err
	}
	version, ok := probeVersion(ctx, pr.CanonicalPath)
	return Resolution{
		PathResolution: pr,
		VersionOutput:  version,
		VersionOK:      ok,
		AdapterID:      agent.Name(),
		AdapterVersion: agent.Name() + "-adapter-v1",
		ModelID:        agent.Name(),
	}, nil
}

func sha256File(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// versionProbeTimeout must cover a cold Node/Bun CLI start, not just an exec.
// Measured 2026-07-13: `pi --version` takes ~8.8s on this machine, so the old
// 3s budget marked pi's version probe failed, which zeroed SupportedFlags,
// which made pi permanently unattestable (RequiredProbesPassed requires it).
const versionProbeTimeout = 30 * time.Second

func probeVersion(ctx context.Context, path string) (string, bool) {
	probeCtx, cancel := context.WithTimeout(ctx, versionProbeTimeout)
	defer cancel()
	// A disposable scratch cwd, never whatever directory the caller happens
	// to be in: this executes path with --version, and a backend that
	// doesn't special-case that flag (or a hostile one that ignores it
	// entirely) must not be able to write anywhere real.
	scratch, err := os.MkdirTemp("", "gov-resolve-probe-")
	if err != nil {
		return "", false
	}
	defer os.RemoveAll(scratch)
	cmd := exec.CommandContext(probeCtx, path, "--version") // govratchet:exec-allow(diagnostic_only)
	cmd.Env = controllerenv.Base()
	cmd.Dir = scratch
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if len(text) > 4096 {
		text = text[:4096]
	}
	return text, err == nil && probeCtx.Err() == nil
}

// fileIdentity returns the platform file identity (device/inode on Unix) for
// path, mirroring the internal/runtime canonicalLockIdentity convention.
// Falls back to the bare path when the platform doesn't expose a Stat_t (e.g.
// Windows) or the file can't be stat'd.
func fileIdentity(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return "path=" + path
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return fmt.Sprintf("dev=%d ino=%d path=%s", st.Dev, st.Ino, path)
	}
	return "path=" + path
}
