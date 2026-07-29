// Package integrationharness is the shared setup machinery for the
// integration test tier introduced by Sol14 P0-2 (rc7 Session 5).
//
// Before this package, internal/assay's package-wide TestMain unconditionally
// set enforce.ForceUnsupported = true, had no build constraint, and therefore
// compiled into `go test -tags integration` too -- making the sole
// integration-tagged test always skip behind a package-level `ok` line. The
// release reported a mandatory integration success having exercised nothing.
//
// Each integration-tier package now owns a //go:build integration TestMain
// that delegates to Setup (this package). Setup resolves the exact
// rc-candidate `gov` binary (received from the release via
// GOV_INTEGRATION_GOV_BIN, or built locally for standalone runs), points
// enforce.SelfExeOverride at it, enrolls the trusted unshare primitive, and
// FAIL-CLOSES -- never skips -- when strong external enforcement cannot be
// established on the host. The fail-closed path and the evidence record are
// shared here precisely because they are security-relevant: a per-package
// copy could drift and silently weaken one tier's gate relative to the
// other. A host that cannot provide enforcement produces a blocking gap
// recorded honestly into the evidence file (rule 11), never a synthesized
// attestation and never a green tier derived from a skip.
package integrationharness

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/cousingary/governator/internal/enforce"
	"github.com/cousingary/governator/internal/toolregistry"
)

// GovBinEnv is the environment variable the release pipeline sets to the
// exact rc-candidate `gov` binary path, so every integration package's
// TestMain shares one build and the release records the exact binary
// identity. When unset (a standalone `go test -tags integration` run) Setup
// builds ./cmd/gov itself, mirroring internal/redteam's govBinary helper.
const GovBinEnv = "GOV_INTEGRATION_GOV_BIN"

// EvidenceOutEnv is the environment variable naming the directory Setup writes
// its machine-readable harness evidence into, one file per integration
// package (<dir>/<pkgName>.json). Using a directory rather than a single
// file means the assay package (which records the Assayer identity) and the
// contextgraph package (which records "n/a") each keep their own record --
// a single shared path would have the second package's TestMain overwrite
// the first's, losing the Assayer commit S6 must bind to the release. The
// release gate and test-summary.json read the directory back to bind the
// integration tier to the exact Governator binary, proven sandbox
// mechanism, and Assayer source each package recorded.
const EvidenceOutEnv = "GOV_INTEGRATION_EVIDENCE_OUT"

var (
	govBinOnce sync.Once
	govBinPath string
	govBinErr  error
)

// Evidence is the machine-readable record Setup writes to EvidenceOutEnv.
// S6 extends the assayer binding to require the exact released Assayer
// checkout; S5 records whatever the tier actually used -- honestly, never
// over-claimed.
type Evidence struct {
	GovernorBinarySHA256 string `json:"governor_binary_sha256"`
	GovernorBinarySource string `json:"governor_binary_source"`
	EnforceSupported     bool   `json:"enforce_supported"`
	SandboxMechanism     string `json:"sandbox_mechanism"`
	AssayerSource        string `json:"assayer_source"`
	AssayerCommit        string `json:"assayer_commit"`
	RecordedAt           string `json:"recorded_at"`
	FailClosedReason     string `json:"fail_closed_reason,omitempty"`
}

// ResolveGovBinary returns the rc-candidate `gov` binary path the
// integration tier will re-exec into as `gov __sandbox_exec`. See GovBinEnv.
func ResolveGovBinary() (path, source string, err error) {
	if env := os.Getenv(GovBinEnv); env != "" {
		return env, "env", nil
	}
	govBinOnce.Do(func() {
		_, thisFile, _, _ := runtime.Caller(0)
		// this package lives at internal/integrationharness; repo root is
		// two parents up from it.
		repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")
		dir, mkErr := os.MkdirTemp("", "gov-integration-bin")
		if mkErr != nil {
			govBinErr = mkErr
			return
		}
		out := filepath.Join(dir, "gov")
		cmd := exec.Command("go", "build", "-buildvcs=false", "-o", out, "./cmd/gov")
		cmd.Dir = repoRoot
		if combined, runErr := cmd.CombinedOutput(); runErr != nil {
			govBinErr = fmt.Errorf("%w: %s", runErr, combined)
			return
		}
		govBinPath = out
	})
	return govBinPath, "built", govBinErr
}

// VerifyELF confirms path is a real ELF executable on Linux before it is
// handed to SelfExeOverride, so a misconfigured GovBinEnv fails loudly here
// rather than producing an opaque exec failure deep inside the first
// sandboxed launch. No-op off Linux.
func VerifyELF(path string) error {
	if runtime.GOOS != "linux" {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var magic [4]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil {
		return err
	}
	if magic != [4]byte{0x7f, 'E', 'L', 'F'} {
		return fmt.Errorf("integration gov binary %s is not an ELF executable", path)
	}
	return nil
}

// SHA256File returns the hex sha256 of path's contents.
func SHA256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	sum := sha256.New()
	if _, err := io.Copy(sum, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(sum.Sum(nil)), nil
}

// EnrollUnshare registers the host's unshare(1) as a trusted controller tool
// so enforce.Supported()'s ResolveTrusted("unshare") probe succeeds. No-op
// when unshare is absent (Supported then fails closed in Setup).
func EnrollUnshare() {
	p, err := exec.LookPath("unshare")
	if err != nil {
		return
	}
	if canonical, cerr := filepath.EvalSymlinks(p); cerr == nil {
		p = canonical
	}
	if _, err := toolregistry.Enroll("unshare", p); err != nil {
		fmt.Fprintf(os.Stderr, "integrationharness: enroll unshare failed: %v\n", err)
	}
}

func writeEvidence(pkgName string, ev Evidence) {
	dir := os.Getenv(EvidenceOutEnv)
	if dir == "" {
		return
	}
	// Per-package file: assay and contextgraph both delegate to Setup, so a
	// single shared path would have one overwrite the other. pkgName keeps
	// each package's record distinct (and lets the gate require each package
	// that ran also recorded evidence).
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "integrationharness: create evidence dir %s: %v\n", dir, err)
		return
	}
	ev.RecordedAt = time.Now().UTC().Format(time.RFC3339Nano)
	b, err := json.MarshalIndent(ev, "", "  ")
	if err != nil {
		return
	}
	b = append(b, '\n')
	_ = os.WriteFile(filepath.Join(dir, pkgName+".json"), b, 0o644)
}

// Setup resolves & verifies the `gov` binary, points
// enforce.SelfExeOverride at it, enrolls unshare, and returns the exit code
// an integration-tier TestMain should pass to os.Exit. `run` is the
// test-binary's m.Run (so this package need not import testing). When
// enforcement cannot be established, Setup fail-closes: it writes the
// blocking gap to the evidence file and returns 1 without invoking run --
// never a skip, never a synthesized pass. pkgName names the calling package
// so its evidence record is filed distinctly (see EvidenceOutEnv).
// assayerSource/assayerCommit let the caller record honestly which Assayer
// the tier ran against.
func Setup(run func() int, pkgName, assayerSource, assayerCommit string) int {
	govPath, govSource, err := ResolveGovBinary()
	if err != nil {
		fmt.Fprintf(os.Stderr, "integration: resolve gov binary: %v\n", err)
		writeEvidence(pkgName, Evidence{GovernorBinarySource: govSource, AssayerSource: assayerSource, AssayerCommit: assayerCommit, FailClosedReason: fmt.Sprintf("resolve gov binary: %v", err)})
		return 1
	}
	if err := VerifyELF(govPath); err != nil {
		fmt.Fprintf(os.Stderr, "integration: gov binary verification: %v\n", err)
		writeEvidence(pkgName, Evidence{GovernorBinarySource: govSource, AssayerSource: assayerSource, AssayerCommit: assayerCommit, FailClosedReason: fmt.Sprintf("gov binary verification: %v", err)})
		return 1
	}
	govSHA, _ := SHA256File(govPath)

	enforce.SelfExeOverride = govPath
	defer func() { enforce.SelfExeOverride = "" }()
	EnrollUnshare()

	if !enforce.Supported() {
		reason := errors.New("external enforcement unavailable on this host (Landlock LSM ABI>=3 + trusted unshare required)")
		fmt.Fprintf(os.Stderr, "integration: FAIL-CLOSED: %v\n", reason)
		writeEvidence(pkgName, Evidence{
			GovernorBinarySHA256: govSHA,
			GovernorBinarySource: govSource,
			EnforceSupported:     false,
			SandboxMechanism:     "unavailable",
			AssayerSource:        assayerSource,
			AssayerCommit:        assayerCommit,
			FailClosedReason:     reason.Error(),
		})
		return 1
	}

	writeEvidence(pkgName, Evidence{
		GovernorBinarySHA256: govSHA,
		GovernorBinarySource: govSource,
		EnforceSupported:     true,
		SandboxMechanism:     "landlock+unshare (enforce.Supported)",
		AssayerSource:        assayerSource,
		AssayerCommit:        assayerCommit,
	})
	return run()
}
