package assay

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/cousingary/governator/internal/gitplumb"
	"github.com/cousingary/governator/internal/toolregistry"
)

// environmentProbeTimeout bounds every local subprocess this file runs (git
// rev-parse, python --version). These are diagnostic metadata, never gating,
// so a hung probe must never be able to stall an evaluation.
const environmentProbeTimeout = 5 * time.Second

// Environment captures identifying metadata about the Assayer checkout and
// the python interpreter Evaluate used, so an evaluation's ledger row can be
// traced back to exactly which code produced its verdict (plan v1.4 Session
// 2 item 3: "record in every evaluation: Assayer commit ..., profile hash,
// validator versions, Python environment"). Every field is best-effort:
// evaluation itself must never hinge on this metadata being available, so
// any lookup that fails leaves its field empty rather than propagating an
// error up through Evaluate.
type Environment struct {
	// AssayerCommit is `git rev-parse HEAD` inside cfg.Repo when it is a real
	// git checkout, or the contents of a PINNED_COMMIT marker file at the
	// root of cfg.Repo when it isn't (the plan's "fixture version pin" case
	// — see internal/assay/testdata/assayer_fixture/PINNED_COMMIT). Empty
	// when neither is available.
	AssayerCommit string
	// ProfileHash is a sha256 hex digest of assayer/profiles.py's bytes at
	// cfg.Repo: a content-addressed proxy for "which profile definitions
	// were in effect" that needs no change to Assayer's own wire protocol
	// (cli.py's evaluate response never carries this field).
	ProfileHash string
	// ValidatorsHash is the equivalent digest of assayer/checks.py — the
	// module that implements every individual check ("validator" in the
	// plan's wording).
	ValidatorsHash string
	// PythonVersion is `<python> --version`'s combined stdout+stderr,
	// trimmed (Python 2 prints its version to stderr; Python 3 to stdout).
	PythonVersion string
}

// DescribeEnvironment computes Environment for cfg. It performs only local,
// read-only, offline operations (a git rev-parse, two file reads, one
// --version invocation) — no network, matching the rest of this package's
// no-network rule. internal/runtime's runAssayStep calls this once per
// evaluation so every assay_evaluations row (pass, fail, error, AND skipped)
// carries the same fingerprint. An unconfigured cfg (no Repo) returns a
// zero-value Environment: there is nothing to describe.
func DescribeEnvironment(cfg Config) Environment {
	if !cfg.Configured() {
		return Environment{}
	}
	return Environment{
		AssayerCommit:  assayerCommit(cfg.Repo),
		ProfileHash:    fileSHA256(filepath.Join(cfg.Repo, "assayer", "profiles.py")),
		ValidatorsHash: fileSHA256(filepath.Join(cfg.Repo, "assayer", "checks.py")),
		PythonVersion:  pythonVersion(cfg.Python),
	}
}

func assayerCommit(repo string) string {
	// `git -C repo` walks UP to the nearest enclosing .git if repo itself
	// isn't a git root (e.g. our fixture, checked into governator's own
	// repo) — that would silently report governator's commit as "the
	// Assayer commit," which is worse than no signal at all. Only trust git
	// when repo directly owns a .git entry (a real clone, or a worktree/
	// submodule pointer file — both live directly at the repo root).
	if _, err := os.Stat(filepath.Join(repo, ".git")); err == nil {
		// Session 2 (post-v4 hardening plan item C): route through the same
		// trusted-tool registry resolution every other git invocation in
		// this codebase uses, rather than a bare "git" argv0 -- this probe
		// is best-effort diagnostic metadata (see the doc comment above), so
		// an unresolvable/untrusted git just leaves AssayerCommit empty,
		// same as any other failure here.
		if gitPath, gerr := gitplumb.TrustedGitPath(); gerr == nil {
			ctx, cancel := context.WithTimeout(context.Background(), environmentProbeTimeout)
			defer cancel()
			cmd := exec.CommandContext(ctx, gitPath, "-C", repo, "rev-parse", "HEAD")
			var out bytes.Buffer
			cmd.Stdout = &out
			if err := cmd.Run(); err == nil {
				if commit := strings.TrimSpace(out.String()); commit != "" {
					return commit
				}
			}
		}
	}
	// Not a git checkout: fall back to the fixture version pin, if the repo
	// ships one.
	pinned, err := os.ReadFile(filepath.Join(repo, "PINNED_COMMIT"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(pinned))
}

func fileSHA256(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func pythonVersion(python string) string {
	python = strings.TrimSpace(python)
	if python == "" {
		python = "python3"
	}
	// Session 2 (post-v4 hardening plan item C): resolve+verify through the
	// trusted-tool registry; best-effort like the rest of this file, so an
	// unresolvable/untrusted python3 just leaves PythonVersion empty.
	identity, ierr := toolregistry.ResolveTrusted("python3", python)
	if ierr != nil {
		return ""
	}
	python = identity.CanonicalPath
	ctx, cancel := context.WithTimeout(context.Background(), environmentProbeTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, python, "--version")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return ""
	}
	return strings.TrimSpace(out.String())
}
