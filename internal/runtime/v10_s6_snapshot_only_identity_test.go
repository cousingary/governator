//go:build redteam

// v10_s6_snapshot_only_identity_test.go implements Sol10 P0-6's mandatory
// red-team corpus (agents/governator-sol-upgrade10.md "P0-6: Assayer
// identity still combines frozen and live state",
// agents/governator-sol-upgrade10-rc4-plan.md Session 6, manifest cases
// 128-130 / report cases 23, 24, 29).
//
// The pre-fix defect: resolvedAssayerEnvironmentHash/resolvedAssayerParticipants
// took a frozen *assay.Snapshot as an argument but then ALSO re-walked the
// live Assayer repo tree (assayerRepoTreeHash), re-resolved python3 through
// the trusted-tool registry (resolvedAssayerPython), and called
// assay.DescribeEnvironment -- all live reads performed AFTER the snapshot
// was already built. So the identity ledgered for a transaction described a
// hybrid of the snapshot actually executed plus whatever the live
// checkout/registry happened to be at the moment identity was computed, not
// the identity of any single executable transaction. The fix
// (internal/assay/snapshot.go's SnapshotIdentity) makes the frozen Snapshot
// the ONE and ONLY source of Assayer transaction identity: once built,
// resolvedAssayerEnvironmentHash/resolvedAssayerParticipants read only
// snap.Identity plus this transaction's own already-fixed cfg/contract
// arguments -- never cfg.Repo, never the trusted-tool registry -- again.
//
// Cases 23/24 deliberately test the two functions directly (not the full
// New().Run() pipeline): the defect and its fix live entirely inside these
// two pure functions, so driving them directly proves the property without
// depending on this host also providing external Landlock/unshare
// enforcement the full pipeline needs. Execution-side immutability (the
// same live-repo mutation has no effect on what assay.Evaluate actually
// runs) is already proven end to end by v9_s3_assayer_snapshot_test.go's
// TestV9Case13ChecksPyMutationAfterSnapshotHasNoEffect/
// TestV9Case14ProfilesPyMutationAfterSnapshotHasNoEffect -- these cases are
// this session's identity-side counterpart to that same invariant.
package runtime

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/cousingary/governator/internal/config"
	"github.com/cousingary/governator/internal/contracts"
	"github.com/cousingary/governator/internal/toolregistry"
)

// TestV10Case23LiveAssayerRepositoryChangeAfterSnapshotHasNoEffect proves
// report case 23: once a Snapshot has been built for this transaction,
// mutating the LIVE Assayer checkout it was built from -- cli.py,
// checks.py, profiles.py, and the dependency lock, every file the pre-fix
// code re-hashed live -- has zero effect on this transaction's identity.
func TestV10Case23LiveAssayerRepositoryChangeAfterSnapshotHasNoEffect(t *testing.T) {
	repo := writeAssayerIdentityFixture(t)
	snap := buildIdentityTestSnapshot(t, repo)

	cfg := config.BuiltIn()
	cfg.Assay.Repo = repo
	c := contracts.Contract{}

	beforeHash := resolvedAssayerEnvironmentHash(cfg, c, snap)
	beforeParts := resolvedAssayerParticipants(cfg.Assay, "env-hash", snap)

	if err := os.WriteFile(filepath.Join(repo, "cli.py"), []byte("print('mutated-after-snapshot')\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "assayer", "checks.py"), []byte("CHECKS = {'mutated': True}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "assayer", "profiles.py"), []byte("PROFILES = {'mutated': True}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "requirements-lock.txt"), []byte("package==999.0\n"), 0644); err != nil {
		t.Fatal(err)
	}

	afterHash := resolvedAssayerEnvironmentHash(cfg, c, snap)
	afterParts := resolvedAssayerParticipants(cfg.Assay, "env-hash", snap)

	if beforeHash != afterHash {
		t.Fatalf("mutating the live Assayer checkout after the snapshot was built changed the environment hash: before=%s after=%s", beforeHash, afterHash)
	}
	if !reflect.DeepEqual(beforeParts, afterParts) {
		t.Fatalf("mutating the live Assayer checkout after the snapshot was built changed the assayer participant identities: before=%+v after=%+v", beforeParts, afterParts)
	}
}

// TestV10Case24PythonRegistryChangeAfterSnapshotHasNoEffect is case 23's
// python3-registry twin (report case 24): rotating the trusted-tool
// registry's "python3" entry to a different (broken) object AFTER a
// Snapshot already resolved and held the real interpreter's identity must
// have zero effect on this transaction's identity -- the frozen
// snap.Identity.PythonIdentity is never re-resolved.
func TestV10Case24PythonRegistryChangeAfterSnapshotHasNoEffect(t *testing.T) {
	toolsReg := filepath.Join(t.TempDir(), "tools.yaml")
	t.Setenv("GOV_TOOLREGISTRY_FILE", toolsReg)

	realPython, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	if _, err := toolregistry.Enroll("python3", realPython); err != nil {
		t.Fatal(err)
	}

	repo := writeAssayerIdentityFixture(t)
	snap := buildIdentityTestSnapshot(t, repo)

	cfg := config.BuiltIn()
	cfg.Assay.Repo = repo
	c := contracts.Contract{}

	beforeHash := resolvedAssayerEnvironmentHash(cfg, c, snap)
	beforeParts := resolvedAssayerParticipants(cfg.Assay, "env-hash", snap)

	// Rotate "python3" to a completely different (broken) object AFTER the
	// snapshot already resolved and held the real interpreter.
	brokenPython := filepath.Join(t.TempDir(), "fake-python3")
	if err := os.WriteFile(brokenPython, []byte("#!/bin/sh\nexit 7\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := toolregistry.Enroll("python3", brokenPython); err != nil {
		t.Fatal(err)
	}

	afterHash := resolvedAssayerEnvironmentHash(cfg, c, snap)
	afterParts := resolvedAssayerParticipants(cfg.Assay, "env-hash", snap)

	if beforeHash != afterHash {
		t.Fatalf("rotating the python3 registry entry after the snapshot was built changed the environment hash: before=%s after=%s", beforeHash, afterHash)
	}
	if !reflect.DeepEqual(beforeParts, afterParts) {
		t.Fatalf("rotating the python3 registry entry after the snapshot was built changed the assayer participant identities: before=%+v after=%+v", beforeParts, afterParts)
	}
}

// TestV10Case29SnapshotIdentityDerivesSolelyFromFrozenObjects is report
// case 29: the strongest possible proof that
// resolvedAssayerEnvironmentHash/resolvedAssayerParticipants derive SOLELY
// from the frozen Snapshot (plus this transaction's own already-fixed
// cfg/contract arguments) and never touch the live filesystem again --
// deleting the live Assayer checkout entirely, after the snapshot is built,
// must leave both functions' output completely unchanged (and must not
// error), since neither has any legitimate reason left to read cfg.Repo at
// all once snap is non-nil.
func TestV10Case29SnapshotIdentityDerivesSolelyFromFrozenObjects(t *testing.T) {
	repo := writeAssayerIdentityFixture(t)
	snap := buildIdentityTestSnapshot(t, repo)

	cfg := config.BuiltIn()
	cfg.Assay.Repo = repo
	c := contracts.Contract{}

	beforeHash := resolvedAssayerEnvironmentHash(cfg, c, snap)
	beforeParts := resolvedAssayerParticipants(cfg.Assay, "env-hash", snap)

	if err := os.RemoveAll(repo); err != nil {
		t.Fatal(err)
	}

	afterHash := resolvedAssayerEnvironmentHash(cfg, c, snap)
	afterParts := resolvedAssayerParticipants(cfg.Assay, "env-hash", snap)

	if beforeHash != afterHash {
		t.Fatalf("deleting the live Assayer checkout entirely changed the environment hash: before=%s after=%s -- identity must derive solely from the frozen snapshot", beforeHash, afterHash)
	}
	if !reflect.DeepEqual(beforeParts, afterParts) {
		t.Fatalf("deleting the live Assayer checkout entirely changed the assayer participant identities: before=%+v after=%+v", beforeParts, afterParts)
	}
}
