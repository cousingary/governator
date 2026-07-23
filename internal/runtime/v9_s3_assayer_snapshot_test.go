//go:build redteam

// v9_s3_assayer_snapshot_test.go is Sol redteam v9's rc3 Session 3 corpus
// (agents/governator-sol-upgrade9-rc3-plan.md Session 3,
// agents/governator-sol-upgrade9.md P0-4): "report cases 13-20" (cases 17
// and 18 live in identity_test.go, next to the sibling
// TestResolvedAssayerEnvironmentHashBinds* tests they extend).
//
// P0-4 was that Governator hashed the Assayer repo tree before replay, but
// assay.Evaluate then reloaded the trusted-tool registry, re-resolved
// python, sealed only cli.py, and set PYTHONPATH to the LIVE (mutable)
// Assayer checkout -- so a concurrent edit to checks.py/profiles.py, or a
// same-name python3 registry rotation, between replay-identity calculation
// and subprocess launch changed which bytes actually produced the verdict,
// while the ledgered identity still recorded the pre-edit state. The fix
// builds one immutable *assay.Snapshot before replay and threads it
// through every Evaluate call in the transaction; Evaluate itself never
// reloads the registry, re-resolves python, or reads from cfg.Repo again.
package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/cousingary/governator/internal/assay"
	"github.com/cousingary/governator/internal/contracts"
	"github.com/cousingary/governator/internal/enforce"
	"github.com/cousingary/governator/internal/toolregistry"
)

// copyAssayerFixture copies the real, checked-in, functioning Assayer
// fixture (internal/assay/testdata/assayer_fixture: cli.py + assayer/
// package, pinned to a real commit) into a fresh writable directory so
// each test mutates its own private copy without touching the shared
// testdata tree or other tests.
func copyAssayerFixture(t *testing.T) string {
	t.Helper()
	src, err := filepath.Abs(filepath.Join("..", "assay", "testdata", "assayer_fixture"))
	if err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	walkErr := filepath.Walk(src, func(path string, info os.FileInfo, werr error) error {
		if werr != nil {
			return werr
		}
		rel, rerr := filepath.Rel(src, path)
		if rerr != nil {
			return rerr
		}
		if rel == "." {
			return nil
		}
		if info.IsDir() {
			if info.Name() == "__pycache__" {
				return filepath.SkipDir
			}
			return os.MkdirAll(filepath.Join(dst, rel), 0755)
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		return os.WriteFile(filepath.Join(dst, rel), data, 0644)
	})
	if walkErr != nil {
		t.Fatalf("copy assayer fixture: %v", walkErr)
	}
	return dst
}

// gitTrackedAssayerFixture is copyAssayerFixture plus a real git commit, so
// a later uncommitted edit is genuinely "dirty" (BuildSnapshot's
// snapshotDirty probe is a no-op on a non-git directory).
func gitTrackedAssayerFixture(t *testing.T) string {
	t.Helper()
	dir := copyAssayerFixture(t)
	git(t, dir, "init", "-b", "main")
	git(t, dir, "config", "user.email", "redteam@example.invalid")
	git(t, dir, "config", "user.name", "Governator Redteam")
	git(t, dir, "add", ".")
	git(t, dir, "commit", "-m", "seed")
	return dir
}

// v9s3Artifact writes one artifact file whose content passes the real
// fixture's coding-output-v1 profile (same shape as internal/assay's own
// writeArtifact/baseRequest fixtures).
func v9s3Artifact(t *testing.T, dir string) (path, sha string) {
	t.Helper()
	content := `{"content":"This is a real, sufficiently long piece of generated content for the check."}`
	path = filepath.Join(dir, "artifact.json")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(content))
	return path, hex.EncodeToString(sum[:])
}

func v9s3BaseRequest(sha string) assay.Request {
	payload, _ := json.Marshal(map[string]any{
		"content": "This is a real, sufficiently long piece of generated content for the check.",
	})
	return assay.Request{
		RunID: "v9s3", AttemptID: "v9s3", JobID: "v9s3", ContractHash: "deadbeef",
		JobType: "coding", Backend: "claude-code",
		ArtifactName: "output", ArtifactSHA256: sha, Payload: payload,
		CheckProfile: "coding-output-v1", PolicyVersion: "test-v1",
	}
}

// mutateChecksToBreak/mutateProfilesToBreak overwrite the named module with
// invalid Python syntax -- guaranteed to crash cli.py's own `from assayer
// import ...` at process start if these bytes are ever actually imported,
// so "the verdict didn't change" is a strong, unambiguous signal that the
// mutated bytes were never read.
func mutateChecksToBreak(t *testing.T, repo string) {
	t.Helper()
	p := filepath.Join(repo, "assayer", "checks.py")
	if err := os.WriteFile(p, []byte("this is not valid python syntax !!! ###\n"), 0644); err != nil {
		t.Fatal(err)
	}
}

func mutateProfilesToBreak(t *testing.T, repo string) {
	t.Helper()
	p := filepath.Join(repo, "assayer", "profiles.py")
	if err := os.WriteFile(p, []byte("this is not valid python syntax !!! ###\n"), 0644); err != nil {
		t.Fatal(err)
	}
}

// withRealSandbox wires enforce.SelfExeOverride to a real compiled `gov`
// binary (govTestBinary) so assay.Evaluate's stage.Executor can construct a
// genuinely enforced launch plan from this plain `go test` process --
// without this, enforce.Supported() is false (a bare test binary cannot
// self-reexec as `gov __sandbox_exec`) and stage.Executor refuses to run at
// all ("no externally enforced sandbox available"), rather than silently
// falling back to an unsandboxed exec.
func withRealSandbox(t *testing.T) {
	t.Helper()
	if enforce.SelfExeOverride == "" {
		enforce.SelfExeOverride = govTestBinary(t)
		t.Cleanup(func() { enforce.SelfExeOverride = "" })
	}
	if !enforce.Supported() {
		t.Skip("this host cannot provide external enforcement (Landlock/unshare unavailable)")
	}
}

// TestV9Case13ChecksPyMutationAfterSnapshotHasNoEffect is Sol9 P0-4 report
// case 13: mutating assayer/checks.py in the live Assayer checkout AFTER a
// Snapshot has already been built for this transaction must have zero
// effect on that transaction's verdict -- Evaluate executes only the
// snapshot's frozen copy, never rereads cfg.Repo.
func TestV9Case13ChecksPyMutationAfterSnapshotHasNoEffect(t *testing.T) {
	withRealSandbox(t)

	repo := copyAssayerFixture(t)
	registry, err := toolregistry.Load()
	if err != nil {
		t.Fatal(err)
	}
	snap, err := assay.BuildSnapshot(registry, assay.Config{Repo: repo, Python: "python3"})
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	defer snap.Close()

	dir := t.TempDir()
	path, sha := v9s3Artifact(t, dir)
	req := v9s3BaseRequest(sha)
	cfg := assay.Config{Repo: repo, Python: "python3"}

	before := assay.Evaluate(context.Background(), cfg, req, path, snap)
	if before.Verdict != assay.VerdictPass {
		t.Fatalf("expected pass verdict before mutation, got %+v", before)
	}

	mutateChecksToBreak(t, repo)

	after := assay.Evaluate(context.Background(), cfg, req, path, snap)
	if after.Verdict != assay.VerdictPass {
		t.Fatalf("mutating checks.py after the snapshot was built changed this transaction's verdict: before=%+v after=%+v", before, after)
	}
}

// TestV9Case14ProfilesPyMutationAfterSnapshotHasNoEffect is Sol9 P0-4 report
// case 14: the profiles.py twin of case 13.
func TestV9Case14ProfilesPyMutationAfterSnapshotHasNoEffect(t *testing.T) {
	withRealSandbox(t)

	repo := copyAssayerFixture(t)
	registry, err := toolregistry.Load()
	if err != nil {
		t.Fatal(err)
	}
	snap, err := assay.BuildSnapshot(registry, assay.Config{Repo: repo, Python: "python3"})
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	defer snap.Close()

	dir := t.TempDir()
	path, sha := v9s3Artifact(t, dir)
	req := v9s3BaseRequest(sha)
	cfg := assay.Config{Repo: repo, Python: "python3"}

	before := assay.Evaluate(context.Background(), cfg, req, path, snap)
	if before.Verdict != assay.VerdictPass {
		t.Fatalf("expected pass verdict before mutation, got %+v", before)
	}

	mutateProfilesToBreak(t, repo)

	after := assay.Evaluate(context.Background(), cfg, req, path, snap)
	if after.Verdict != assay.VerdictPass {
		t.Fatalf("mutating profiles.py after the snapshot was built changed this transaction's verdict: before=%+v after=%+v", before, after)
	}
}

// TestV9Case15PythonRegistryRotationAfterSnapshotHasNoEffect is Sol9 P0-4
// report case 15: rotating the trusted-tool registry's "python3" entry to a
// different (broken) object AFTER a Snapshot already resolved and HELD the
// real interpreter must not change what that transaction executes --
// Evaluate launches through snap.Python's already-open, already-verified
// descriptor, never by re-resolving the name.
func TestV9Case15PythonRegistryRotationAfterSnapshotHasNoEffect(t *testing.T) {
	withRealSandbox(t)

	toolsReg := filepath.Join(t.TempDir(), "tools.yaml")
	t.Setenv("GOV_TOOLREGISTRY_FILE", toolsReg)
	// The network-denied enforcement plan resolves unshare/bash through this
	// same registry, not just the primary python3 executable -- an isolated
	// registry starts with none of the default entries' paths filled in.
	for _, name := range []string{"git", "bash", "unshare", "python3"} {
		bin, err := exec.LookPath(name)
		if err != nil {
			if name == "python3" {
				t.Skip("python3 not available")
			}
			t.Fatal(err)
		}
		if _, err := toolregistry.Enroll(name, bin); err != nil {
			t.Fatal(err)
		}
	}

	repo := copyAssayerFixture(t)
	registry, err := toolregistry.Load()
	if err != nil {
		t.Fatal(err)
	}
	snap, err := assay.BuildSnapshot(registry, assay.Config{Repo: repo, Python: "python3"})
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	defer snap.Close()

	// Rotate "python3" to a broken stub AFTER the snapshot already resolved
	// and held the real interpreter's descriptor.
	brokenPython := filepath.Join(t.TempDir(), "fake-python3")
	if err := os.WriteFile(brokenPython, []byte("#!/bin/sh\nexit 7\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := toolregistry.Enroll("python3", brokenPython); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	path, sha := v9s3Artifact(t, dir)
	req := v9s3BaseRequest(sha)

	v := assay.Evaluate(context.Background(), assay.Config{Repo: repo, Python: "python3"}, req, path, snap)
	if v.Verdict != assay.VerdictPass {
		t.Fatalf("expected the frozen snapshot to still execute via the pre-rotation python handle, got %+v", v)
	}

	// Control: a FRESH snapshot build attempted AFTER the rotation resolves
	// the now-current (broken) registry entry and must actually fail --
	// proving the rotation really would have mattered without the freeze.
	//
	// Sol10 P0-5: BuildSnapshot itself now resolves and runs an isolated
	// stdlib probe through the held python handle (buildRuntimeManifest),
	// so a broken interpreter fails closed here, at construction time,
	// rather than only later inside Evaluate's subprocess launch -- an
	// earlier, stronger failure mode than this test originally exercised,
	// but the same underlying point: without the freeze already in place
	// (snap, built above, before the rotation), the rotated registry entry
	// would have broken this transaction.
	registryAfter, err := toolregistry.Load()
	if err != nil {
		t.Fatal(err)
	}
	freshSnap, ferr := assay.BuildSnapshot(registryAfter, assay.Config{Repo: repo, Python: "python3"})
	if ferr == nil {
		freshSnap.Close()
		t.Fatal("expected building a fresh snapshot after the python3 rotation to fail closed (broken interpreter can't pass the frozen runtime-manifest probe)")
	}
}

// TestV9Case16SnapshotReadRootsExcludeLiveRepoUnderRealLandlock is Sol9
// P0-4 report case 16: even a hostile cli.py that hardcodes the ORIGINAL
// live repo's absolute path (not merely relying on relative paths that the
// copy mechanism alone would already defeat) must be denied by real
// Landlock enforcement when it tries to read outside the snapshot package
// -- ReadRoots is exactly snap.Runtime.StdlibReadRoots (python's own
// stdlib), never cfg.Repo. Sol11 P0-6: the package itself (snap.Package) is
// no longer even a candidate for a Landlock ReadRoot at all -- it's a
// sealed memfd inherited as an already-open descriptor, never reached
// through path-based Landlock rules in the first place.
func TestV9Case16SnapshotReadRootsExcludeLiveRepoUnderRealLandlock(t *testing.T) {
	// Piggyback fixture()'s enforce.SelfExeOverride/govTestBinary setup --
	// this case needs the real external sandbox, not the
	// ForceUnsupported=true shortcut the other cases in this file use.
	fixture(t)
	if !enforce.Supported() {
		t.Skip("this host cannot provide external enforcement (Landlock/unshare unavailable)")
	}

	toolsReg := filepath.Join(t.TempDir(), "tools.yaml")
	t.Setenv("GOV_TOOLREGISTRY_FILE", toolsReg)
	for _, name := range []string{"git", "bash", "python3"} {
		bin, err := exec.LookPath(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := toolregistry.Enroll(name, bin); err != nil {
			t.Fatal(err)
		}
	}
	if unsharePath, err := exec.LookPath("unshare"); err == nil {
		if _, err := toolregistry.Enroll("unshare", unsharePath); err != nil {
			t.Fatal(err)
		}
	}

	// The "live" Assayer checkout, containing a secret file OUTSIDE
	// anything BuildSnapshot ever copies (it only copies cli.py +
	// assayer/*.py). The hostile cli.py below tries to read the secret
	// back via its ORIGINAL absolute path, proving denial is enforced by
	// Landlock, not merely an accident of what the copy included.
	liveRepo := t.TempDir()
	secretPath := filepath.Join(liveRepo, "secret.txt")
	if err := os.WriteFile(secretPath, []byte("CANARY-SECRET-MUST-NOT-LEAK"), 0644); err != nil {
		t.Fatal(err)
	}
	hostileCLI := `import json
try:
    with open(` + strconv.Quote(secretPath) + `) as f:
        leaked = f.read()
except Exception:
    leaked = None
print(json.dumps({
    "verdict": "pass" if leaked is None else "fail",
    "failed_checks": [] if leaked is None else ["leaked:" + leaked],
    "had_error": False, "evaluation_id": "e", "trace_id": None,
    "quarantine_id": "", "checks_result_hash": "h", "profile_definition_hash": "p",
    "validator_implementation_hash": "vi", "validator_config_hash": "vc",
    "policy_version": "v1",
}))
`
	if err := os.WriteFile(filepath.Join(liveRepo, "cli.py"), []byte(hostileCLI), 0644); err != nil {
		t.Fatal(err)
	}

	registry, err := toolregistry.Load()
	if err != nil {
		t.Fatal(err)
	}
	snap, err := assay.BuildSnapshot(registry, assay.Config{Repo: liveRepo, Python: "python3"})
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	defer snap.Close()

	dir := t.TempDir()
	path, sha := v9s3Artifact(t, dir)
	req := v9s3BaseRequest(sha)

	v := assay.Evaluate(context.Background(), assay.Config{Repo: liveRepo, Python: "python3"}, req, path, snap)
	if strings.Contains(strings.Join(v.FailedChecks, ","), "CANARY-SECRET-MUST-NOT-LEAK") {
		t.Fatalf("secret leaked into verdict: %+v", v)
	}
	if v.Verdict != assay.VerdictPass {
		t.Fatalf("expected the read at the secret's original absolute path to be denied by Landlock (open() raising -> verdict pass), got %+v", v)
	}
}

// TestV9Case19DirtyAssayerCheckoutDisablesStrictReplay is Sol9 P0-4 report
// case 19 / work item 4: a snapshot built from an Assayer checkout with
// uncommitted changes cannot be reproduced against a specific commit by a
// later audit, so strict replay must be disabled for that transaction even
// though the run itself executes and approves normally.
func TestV9Case19DirtyAssayerCheckoutDisablesStrictReplay(t *testing.T) {
	root, _, _, _ := replayEnv(t)

	toolsReg := filepath.Join(t.TempDir(), "tools.yaml")
	t.Setenv("GOV_TOOLREGISTRY_FILE", toolsReg)
	for _, name := range []string{"git", "bash", "unshare", "test", "python3"} {
		bin, err := exec.LookPath(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := toolregistry.Enroll(name, bin); err != nil {
			t.Fatal(err)
		}
	}

	// identity.StrictReplayEligible also requires Provider+ModelRevision on
	// the backend's config entry (see identity_test.go's
	// TestReplayPositiveIdenticalEnvironmentReplays) -- without this, every
	// run is already StrictReplayEligible=false for an unrelated reason and
	// dirtying the Assayer checkout would prove nothing.
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(configPath, []byte("backends:\n  claude-code:\n    provider: test-provider\n    model_revision: test-rev-v1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_CONFIG", configPath)

	assayerRepo := gitTrackedAssayerFixture(t)
	t.Setenv("GOV_ASSAY_REPO", assayerRepo)
	t.Setenv("GOV_ASSAY_PYTHON", "python3")

	c := contract(root)
	c.Success.ValidatorSpecs = []contracts.ValidatorSpec{{Command: "test -f output/result.txt", Tools: []string{"test"}}}
	c.Assay = &contracts.Assay{Profile: "coding-output-v1", Enforcement: "advisory"}

	r1, err := New().Run(context.Background(), c)
	if err != nil {
		t.Fatalf("first run: %v", err)
	}
	if r1.Status != "APPROVED" {
		t.Fatalf("first run: %s: %s", r1.Status, r1.Message)
	}

	checksPath := filepath.Join(assayerRepo, "assayer", "checks.py")
	original, err := os.ReadFile(checksPath)
	if err != nil {
		t.Fatal(err)
	}
	// Uncommitted edit -- dirty -- made AFTER the first (clean) approval.
	if err := os.WriteFile(checksPath, append(append([]byte{}, original...), []byte("\n# uncommitted local edit\n")...), 0644); err != nil {
		t.Fatal(err)
	}

	r2, err := New().Run(context.Background(), c)
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if r2.Replayed {
		t.Fatalf("a dirty Assayer checkout must disable strict replay, but the second run replayed r1 (r1.ID=%s r2.ID=%s)", r1.ID, r2.ID)
	}
	if r2.ID == r1.ID {
		t.Fatal("expected a fresh run ID for the second (non-replayed) run, got the same ID as the first")
	}
}

// TestV9Case20FreshSnapshotAfterMutationReflectsNewBytes is Sol9 P0-4
// report case 20: the immutability proven by cases 13/14 is scoped to an
// already-built transaction's snapshot, not "Assayer changes are silently
// inert forever" -- a NEW snapshot built after a legitimate edit must
// actually reflect it (a different tree hash, and a verdict that reacts to
// the new bytes).
func TestV9Case20FreshSnapshotAfterMutationReflectsNewBytes(t *testing.T) {
	withRealSandbox(t)

	repo := copyAssayerFixture(t)
	registry, err := toolregistry.Load()
	if err != nil {
		t.Fatal(err)
	}
	before, err := assay.BuildSnapshot(registry, assay.Config{Repo: repo, Python: "python3"})
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	defer before.Close()

	mutateChecksToBreak(t, repo)

	after, err := assay.BuildSnapshot(registry, assay.Config{Repo: repo, Python: "python3"})
	if err != nil {
		t.Fatalf("build snapshot after mutation: %v", err)
	}
	defer after.Close()

	if before.PackageHash == after.PackageHash {
		t.Fatal("a fresh snapshot built after mutating checks.py has the same package hash as the pre-mutation snapshot -- the fix must not freeze Assayer forever, only per already-built transaction")
	}

	dir := t.TempDir()
	path, sha := v9s3Artifact(t, dir)
	req := v9s3BaseRequest(sha)
	v := assay.Evaluate(context.Background(), assay.Config{Repo: repo, Python: "python3"}, req, path, after)
	if v.Verdict == assay.VerdictPass {
		t.Fatalf("expected the fresh post-mutation snapshot to actually execute the broken checks.py (a non-pass verdict), got %+v", v)
	}
}
