//go:build redteam

// v7_s6_strict_replay_test.go implements Sol redteam v7 corpus cases 25-28
// (agents/governator-sol-upgrade7-plan.md Session 6, "ExecutionIdentityV2
// from one immutable transaction snapshot"). internal/runtime/runtime.go's
// runOnce (~line 2866-2879) only ATTEMPTS a replay lookup when
// identity.StrictReplayEligible is true -- which requires (a) the backend's
// Provider+ModelRevision to be declared (agents.BackendIdentity.Known())
// and (b) every contract validator to be a structured ValidatorSpec, never
// a legacy Validators string (a legacy validator's exact tools/scripts
// aren't resolved into a trackable participant, so validateParticipants
// correctly refuses to call the identity "strict"). baseContract() (this
// corpus's shared fixture) deliberately uses legacy string Validators, so
// EVERY test built on it has StrictReplayEligible permanently false --
// meaning "run twice, assert !Replayed" proves nothing there: replay was
// never going to happen either way, regardless of what changed between the
// two runs. Every test in this file instead builds a genuinely strict-
// replay-eligible contract and proves each case's specific target field is
// what breaks replay -- not just that replay never happens under
// baseContract()'s shape -- via a three-run structure: run 1 establishes an
// approval, run 2 (byte-for-byte identical) must ACTUALLY replay (proving
// the mechanism engages at all under this contract shape), and only then
// does run 3 (after changing exactly the target field) get asserted as
// NOT replayed.
package redteam

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cousingary/governator/internal/contracts"
	"github.com/cousingary/governator/internal/enforce"
	govruntime "github.com/cousingary/governator/internal/runtime"
	"github.com/cousingary/governator/internal/toolregistry"
)

// runStrictReplayDirect calls govruntime.New().RunWithAutoRepair directly
// (mirroring TestV6Case30's pattern) rather than the shared runGoverned
// harness helper -- runGoverned's runGovernedAllowError unconditionally
// calls enrollRealControllerTools on every invocation, which re-enrolls
// git/bash from their real system paths and would silently clobber a
// test's own git/bash re-enrollment (cases 27/28's whole point) right
// before each run.
func runStrictReplayDirect(t *testing.T, home, bin string, c contracts.Contract) govruntime.RunRecord {
	t.Helper()
	t.Setenv("GOV_HOME", home)
	t.Setenv("GOV_CLAUDE_BIN", bin)
	rec, err := govruntime.New().RunWithAutoRepair(context.Background(), c)
	if err != nil {
		t.Fatalf("RunWithAutoRepair: %v", err)
	}
	return rec
}

// runStrictReplayDirectBaseline is runStrictReplayBaseline's sibling for
// callers that must use runStrictReplayDirect instead of runGoverned.
func runStrictReplayDirectBaseline(t *testing.T, home, bin string, c contracts.Contract) {
	t.Helper()
	r1 := runStrictReplayDirect(t, home, bin, c)
	if r1.Status != "APPROVED" {
		t.Fatalf("baseline run 1 expected APPROVED, got status=%s message=%s", r1.Status, r1.Message)
	}
	r2 := runStrictReplayDirect(t, home, bin, c)
	if !r2.Replayed {
		t.Fatalf("baseline run 2 (byte-for-byte identical to run 1) did not replay -- strict replay never engages under this contract shape, so this test cannot prove anything about the specific field it changes next (status=%s message=%s)", r2.Status, r2.Message)
	}
}

// strictReplayConfig writes a GOV_CONFIG pointing at a config.yaml that
// declares Provider+ModelRevision for the claude-code backend --
// agents.BackendIdentity.Known() requires both, and neither is set by any
// built-in default (config.BuiltIn's Backends map only declares Bin).
func strictReplayConfig(t *testing.T) {
	t.Helper()
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	data := "backends:\n  claude-code:\n    provider: test-provider\n    model_revision: test-rev-v1\n"
	if err := os.WriteFile(configPath, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_CONFIG", configPath)
}

// strictReplayEnrollControllerTools enrolls git/bash/unshare (like
// s6EnrollControllerTools) plus "test", the one external tool
// strictReplayContract's ValidatorSpec declares.
func strictReplayEnrollControllerTools(t *testing.T) {
	t.Helper()
	s6EnrollControllerTools(t)
	testPath, err := exec.LookPath("test")
	if err != nil {
		testPath = "/usr/bin/test"
	}
	if _, err := toolregistry.Enroll("test", testPath); err != nil {
		t.Fatal(err)
	}
	if pythonPath, err := exec.LookPath("python3"); err == nil {
		if _, err := toolregistry.Enroll("python3", pythonPath); err != nil {
			t.Fatal(err)
		}
	}
	// s6EnrollControllerTools only enrolls git/bash -- baseContract forbids
	// network, which (per TestV6Case1) makes the externally enforced
	// sandbox mandatory regardless of risk_class, and that sandbox's
	// PID-namespace fallback resolves "unshare" through the trusted
	// registry the same way containment.NewScope does everywhere else.
	if unshare, lerr := exec.LookPath("unshare"); lerr == nil {
		if canonical, everr := filepath.EvalSymlinks(unshare); everr == nil {
			unshare = canonical
		}
		if _, err := toolregistry.Enroll("unshare", unshare); err != nil {
			t.Fatal(err)
		}
	}
}

// strictReplayContract is baseContract with its success validator declared
// as a structured ValidatorSpec (tool-tracked) instead of a legacy string,
// the one change needed to make identity.StrictReplayEligible reachable
// (still subject to the backend identity also being Known(), which
// strictReplayConfig separately provides).
func strictReplayContract(root string) contracts.Contract {
	c := baseContract(root)
	c.Success.Validators = []string{"test -f output/result.txt"}
	c.Success.ValidatorSpecs = []contracts.ValidatorSpec{
		{Command: "test -f output/result.txt", Tools: []string{"test"}},
	}
	return c
}

func writeMinimalAssayerRepo(t *testing.T, repo string) {
	t.Helper()
	for rel, body := range map[string]string{
		"PINNED_COMMIT":       "commit-v1\n",
		"cli.py":              "print('assayer cli')\n",
		"assayer/__init__.py": "__version__ = '0.0-test'\n",
		"assayer/checks.py":   "CHECKS = ['v1']\n",
		"assayer/profiles.py": "PROFILES = {'coding-output-v1': {'checks': ['v1']}}\n",
	} {
		path := filepath.Join(repo, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
}

// runStrictReplayTwiceUnchanged runs c through the real runtime engine
// twice with no changes at all between the two calls and fails the test
// unless run 2 genuinely replays -- the shared proof-of-mechanism every
// case in this file relies on before trusting its own "change X, no longer
// replays" assertion.
func runStrictReplayBaseline(t *testing.T, home, bin string, c contracts.Contract) {
	t.Helper()
	r1 := runGoverned(t, home, bin, c)
	if r1.Status != "APPROVED" {
		t.Fatalf("baseline run 1 expected APPROVED, got status=%s message=%s", r1.Status, r1.Message)
	}
	r2 := runGoverned(t, home, bin, c)
	if !r2.Replayed {
		t.Fatalf("baseline run 2 (byte-for-byte identical to run 1) did not replay -- strict replay never engages under this contract shape, so this test cannot prove anything about the specific field it changes next (status=%s message=%s)", r2.Status, r2.Message)
	}
}

// TestV7Case17ValidatorInterpreterChangeInvalidatesReplay proves
// internal/runtime/identity.go's resolveValidatorToolset resolves every
// declared ValidatorSpec.Tools entry through the tool registry
// (CanonicalPath/SHA256/Device/Inode) into ValidatorToolsetHash, which
// feeds both ExecutionIdentity.Hash() directly and, via
// resolvedParticipants' validator_tools/validator_scripts entries, the
// participants map -- so re-enrolling the validator's declared "test" tool
// at a different verified path (a fresh copy of the same binary, a
// different device/inode even though the content is byte-identical)
// invalidates replay, mirroring case 27/28's proof for the git/bash
// controller participants.
func TestV7Case17ValidatorInterpreterChangeInvalidatesReplay(t *testing.T) {
	strictReplayConfig(t)
	root := fixtureRepo(t)
	home := t.TempDir()

	registryFile := filepath.Join(t.TempDir(), "tools.yaml")
	t.Setenv("GOV_TOOLREGISTRY_FILE", registryFile)
	s6EnrollControllerTools(t)
	if unshare, lerr := exec.LookPath("unshare"); lerr == nil {
		if canonical, everr := filepath.EvalSymlinks(unshare); everr == nil {
			unshare = canonical
		}
		if _, err := toolregistry.Enroll("unshare", unshare); err != nil {
			t.Fatal(err)
		}
	}

	testPath, err := exec.LookPath("test")
	if err != nil {
		testPath = "/usr/bin/test"
	}
	testCopyA := copyToNewInode(t, testPath)
	if _, err := toolregistry.Enroll("test", testCopyA); err != nil {
		t.Fatal(err)
	}

	c := strictReplayContract(root)
	bin := fakeBackend(t, standardBackendBody(""))

	runStrictReplayBaseline(t, home, bin, c)

	testCopyB := copyToNewInode(t, testPath)
	if _, err := toolregistry.Enroll("test", testCopyB); err != nil {
		t.Fatal(err)
	}

	r3 := runGoverned(t, home, bin, c)
	if r3.Replayed {
		t.Fatal("run 3 replayed a stale approval after the validator's declared \"test\" tool was re-enrolled at a different verified path -- replay identity does not bind the resolved validator toolset")
	}
}

// TestV7Case18ValidatorScriptBytesChangeInvalidatesReplay proves
// resolveValidatorToolset also hashes each ValidatorSpec.Files entry's
// content directly (hashFileContent, relative to the contract's workspace
// root), so a validator script's bytes changing -- even though the
// resolved "test" tool identity, the command text, and the contract hash
// are all unchanged -- still invalidates replay.
func TestV7Case18ValidatorScriptBytesChangeInvalidatesReplay(t *testing.T) {
	strictReplayConfig(t)
	root := fixtureRepo(t)
	home := t.TempDir()

	registryFile := filepath.Join(t.TempDir(), "tools.yaml")
	t.Setenv("GOV_TOOLREGISTRY_FILE", registryFile)
	strictReplayEnrollControllerTools(t)

	scriptPath := filepath.Join(root, "validator.sh")
	if err := os.WriteFile(scriptPath, []byte("#!/bin/sh\ntest -f output/result.txt\n"), 0755); err != nil {
		t.Fatal(err)
	}
	git(t, root, "add", ".")
	git(t, root, "commit", "-m", "add validator script")

	c := strictReplayContract(root)
	c.Success.ValidatorSpecs[0].Files = []string{"validator.sh"}

	bin := fakeBackend(t, standardBackendBody(""))

	runStrictReplayBaseline(t, home, bin, c)

	if err := os.WriteFile(scriptPath, []byte("#!/bin/sh\ntest -f output/result.txt # tampered\n"), 0755); err != nil {
		t.Fatal(err)
	}
	git(t, root, "add", ".")
	git(t, root, "commit", "-m", "tamper validator script")

	r3 := runGoverned(t, home, bin, c)
	if r3.Replayed {
		t.Fatal("run 3 replayed a stale approval after the validator's declared script file (validator.sh) content changed -- replay identity does not bind the validator's declared file bytes")
	}
}

// TestV7Case21RTKMinimalismAnnotationChangeInvalidatesReplay proves
// runtime.go's runOnce folds tokenoptimizer.PromptAnnotation() and
// minimalism.PromptAnnotation() into compiledPromptForIdentity (and hence
// ExactPromptHash / CompiledPromptHash) -- both driven purely by
// config.Config (cfg.RTK.Mode, cfg.Minimalism.Mode), read fresh via
// config.LoadStrict on every run (no caching). Uses minimalism.Mode as the
// lever (RTK.Mode's "auto"/"required" states additionally require an "rtk"
// binary on PATH, which a bare test sandbox may not have): changing
// GOV_CONFIG's minimalism.mode between run 1 and run 3 changes the
// model-visible minimalism annotation text with the contract, backend, and
// every other input held fixed, and must invalidate replay.
func TestV7Case21RTKMinimalismAnnotationChangeInvalidatesReplay(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	writeConfig := func(minimalismMode string) {
		data := "backends:\n  claude-code:\n    provider: test-provider\n    model_revision: test-rev-v1\nminimalism:\n  mode: " + minimalismMode + "\n"
		if err := os.WriteFile(configPath, []byte(data), 0644); err != nil {
			t.Fatal(err)
		}
	}
	writeConfig("off")
	t.Setenv("GOV_CONFIG", configPath)

	root := fixtureRepo(t)
	home := t.TempDir()

	registryFile := filepath.Join(t.TempDir(), "tools.yaml")
	t.Setenv("GOV_TOOLREGISTRY_FILE", registryFile)
	strictReplayEnrollControllerTools(t)

	c := strictReplayContract(root)
	bin := fakeBackend(t, standardBackendBody(""))

	runStrictReplayBaseline(t, home, bin, c)

	writeConfig("lite")

	r3 := runGoverned(t, home, bin, c)
	if r3.Replayed {
		t.Fatal("run 3 replayed a stale approval after config.yaml's minimalism.mode changed from \"off\" to \"lite\" -- the model-visible minimalism annotation changed but replay identity did not invalidate")
	}
}

// TestV7Case30UnknownRequiredIdentityDisablesStrictReplay proves
// identity_v2.go's validateParticipants (which requires every
// participantRoles entry to be either Known or NotApplicable) and
// runtime.go's handling of its error -- setting
// identity.StrictReplayEligible=false and StrictReplayDisabledReason --
// combine with replayMatch's own identityHash=="" short-circuit (identity.go
// replayMatch returns ("", nil) without ever querying the database when the
// hash is blank) to make an unknown required identity structurally unable
// to replay, not merely "hash differently": two runs that are unknown for
// the exact same reason never even reach a Hash() comparison, closing RB5's
// "an unknown sentinel can let two unknown environments compare equal" gap
// at the lookup layer rather than relying on the hash of the word "unknown"
// happening to differ. Uses baseContract's legacy string Validators (not
// strictReplayContract's ValidatorSpecs) as the lever: runtime.go's runOnce
// explicitly marks validator_tools/validator_scripts Known:false whenever a
// contract has legacy Validators with no ValidatorSpecs (line ~2859), which
// is exactly a "required identity stays unknown" condition -- deliberately
// paired with strictReplayConfig's declared backend identity, so backend
// unknown-ness cannot be what's disabling replay here.
func TestV7Case30UnknownRequiredIdentityDisablesStrictReplay(t *testing.T) {
	strictReplayConfig(t)
	root := fixtureRepo(t)
	home := t.TempDir()

	registryFile := filepath.Join(t.TempDir(), "tools.yaml")
	t.Setenv("GOV_TOOLREGISTRY_FILE", registryFile)
	strictReplayEnrollControllerTools(t)

	c := baseContract(root)
	bin := fakeBackend(t, standardBackendBody(""))

	r1 := runGoverned(t, home, bin, c)
	if r1.Status != "APPROVED" {
		t.Fatalf("run 1 expected APPROVED, got status=%s message=%s", r1.Status, r1.Message)
	}
	if r1.Replayed {
		t.Fatal("run 1 (first ever run) reported Replayed=true")
	}

	r2 := runGoverned(t, home, bin, c)
	if r2.Replayed {
		t.Fatal("run 2, byte-for-byte identical to run 1, reported Replayed=true even though the contract's legacy string validators leave validator_tools/validator_scripts identity permanently unknown -- an unknown required identity must disable strict replay, never compare equal to another unknown run")
	}
	if r2.Status != "APPROVED" {
		t.Fatalf("run 2 expected a fresh APPROVED (non-replayed) outcome, got status=%s message=%s", r2.Status, r2.Message)
	}
}

// TestV7Case24ProtectedManifestChangeBetweenLoadAndHashInvalidatesReplay
// proves environment.go's buildRunEnvironment parses the protected-path
// manifest exactly once per run (env.ProtectedPatterns), and runtime.go's
// identity.ProtectedManifestHash = hashJSON(env.ProtectedPatterns) hashes
// that already-frozen slice rather than re-reading the manifest file --
// closing RB5's "the protected manifest is frozen for enforcement then
// re-read for hashing" TOCTOU. Proof: since GOV_CONFIG's protected_manifest
// path is itself read fresh (config.LoadStrict has no caching, same as case
// 21's minimalism lever), a manifest content change between run 1 and run 3
// is picked up by run 3's own buildRunEnvironment call and correctly
// invalidates replay -- the frozen-hash property matters *within* a single
// run (enforcement and identity agree on one snapshot), not across runs,
// where a manifest change legitimately must produce a new identity.
func TestV7Case24ProtectedManifestChangeBetweenLoadAndHashInvalidatesReplay(t *testing.T) {
	manifestPath := filepath.Join(t.TempDir(), "protected-paths.txt")
	if err := os.WriteFile(manifestPath, []byte("secret1.txt\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// config.applyEnv's CLAUDE_HARNESS_STATE branch would otherwise silently
	// redirect cfg.ProtectedManifest away from this test's YAML-declared
	// path whenever the ambient shell has that variable set (as this build
	// host's own governed-harness environment does) -- GOV_PROTECTED_MANIFEST
	// is checked first in applyEnv's firstEnv(...) call, so setting it here
	// pins the manifest path this test actually controls.
	t.Setenv("GOV_PROTECTED_MANIFEST", manifestPath)

	configPath := filepath.Join(t.TempDir(), "config.yaml")
	data := "backends:\n  claude-code:\n    provider: test-provider\n    model_revision: test-rev-v1\n"
	if err := os.WriteFile(configPath, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_CONFIG", configPath)

	root := fixtureRepo(t)
	home := t.TempDir()

	registryFile := filepath.Join(t.TempDir(), "tools.yaml")
	t.Setenv("GOV_TOOLREGISTRY_FILE", registryFile)
	strictReplayEnrollControllerTools(t)

	c := strictReplayContract(root)
	bin := fakeBackend(t, standardBackendBody(""))

	runStrictReplayBaseline(t, home, bin, c)

	if err := os.WriteFile(manifestPath, []byte("secret1.txt\nsecret2.txt\n"), 0644); err != nil {
		t.Fatal(err)
	}

	r3 := runGoverned(t, home, bin, c)
	if r3.Replayed {
		t.Fatal("run 3 replayed a stale approval after the protected-path manifest content changed -- replay identity does not bind the frozen protected-pattern list")
	}
}

// TestV7Case22GraphSnapshotChangeBetweenInspectionAndPrepInvalidatesReplay
// proves two things together: (1) structurally, runtime.go's runOnce
// queries the graph provider exactly ONCE per run
// (contextgraph.CurrentWithStatus, assigned to preReplayGraph) and reuses
// that single in-memory Snapshot both for the replay-identity hash
// (graphSnapshotHash := hashJSON(preReplayGraph)) and for what the run
// actually consumes (graphSnapshot := preReplayGraph -- "Consume the exact
// frozen graph snapshot represented by replay identity", runtime.go's own
// comment there); contextgraph.PrepareWithStatus, the old second-call shape
// RB5 describes (CurrentWithStatus(root) pre-replay vs
// PrepareWithStatus(worktree) at execution, which could observe two
// different graph states), is not called anywhere in internal/runtime
// (verified by source search) -- so there is no second call left to
// diverge from the first. (2) black-box: with only one call site, the
// snapshot's own CONTENT must still be bound into replay identity, proven
// the same way case 25/26 prove Assayer content changes invalidate replay:
// the fake codegraph provider reads (read-only, no write -- consistent with
// scopedCommandOutput's readOnly enforce.Plan for this stage) a marker file
// inside the workspace root and reports its content as fileCount, so
// changing that marker between run 1 and run 3 -- same provider binary,
// same registered identity, only the underlying repo content differs --
// must invalidate replay via GraphSnapshotHash.
func TestV7Case22GraphSnapshotChangeBetweenInspectionAndPrepInvalidatesReplay(t *testing.T) {
	root := fixtureRepo(t)
	home := t.TempDir()

	markerPath := filepath.Join(root, "graph-marker.txt")
	if err := os.WriteFile(markerPath, []byte("1"), 0644); err != nil {
		t.Fatal(err)
	}
	git(t, root, "add", ".")
	git(t, root, "commit", "-m", "add graph marker")

	statusBody := "\t\tdata, rerr := os.ReadFile(" + fmt.Sprintf("%q", markerPath) + ")\n" +
		"\t\tcount := \"0\"\n" +
		"\t\tif rerr == nil {\n" +
		"\t\t\tcount = strings.TrimSpace(string(data))\n" +
		"\t\t}\n" +
		"\t\tfmt.Printf(\"{\\\"version\\\":\\\"1.0.0\\\",\\\"initialized\\\":true,\\\"projectPath\\\":\\\"\\\",\\\"indexPath\\\":\\\"\\\",\\\"fileCount\\\":%s,\\\"nodeCount\\\":1,\\\"edgeCount\\\":1,\\\"dbSizeBytes\\\":1}\\n\", count)\n" +
		"\t\treturn\n"
	provider := buildFakeCodegraphBinary(t, "\n\t\"strings\"", statusBody, "")

	registryFile := filepath.Join(t.TempDir(), "tools.yaml")
	t.Setenv("GOV_TOOLREGISTRY_FILE", registryFile)
	s6EnrollControllerTools(t)
	if _, err := toolregistry.Enroll("codegraph", provider); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_GRAPH_MODE", "auto")
	t.Setenv("GOV_GRAPH_PROVIDER", "codegraph")
	t.Setenv("GOV_GRAPH_BIN", provider)

	c := baseContract(root)
	bin := fakeBackend(t, standardBackendBody(""))

	r1 := runGoverned(t, home, bin, c)
	if r1.Status != "APPROVED" {
		t.Fatalf("run 1 expected APPROVED, got status=%s message=%s", r1.Status, r1.Message)
	}
	if r1.Graph.FileCount != 1 {
		t.Fatalf("run 1's graph snapshot fileCount=%d, expected 1 (from the marker file) -- the fake provider may not have been invoked at all", r1.Graph.FileCount)
	}

	if err := os.WriteFile(markerPath, []byte("2"), 0644); err != nil {
		t.Fatal(err)
	}
	git(t, root, "add", ".")
	git(t, root, "commit", "-m", "change graph marker")

	r3 := runGoverned(t, home, bin, c)
	if r3.Replayed {
		t.Fatal("run 3 replayed a stale approval after the graph provider's underlying repo content changed (marker file 1 -> 2, same provider identity) -- replay identity does not bind the graph snapshot's own content")
	}
	if r3.Graph.FileCount != 2 {
		t.Fatalf("run 3's graph snapshot fileCount=%d, expected 2 -- the recorded/executed snapshot does not reflect the same content that (correctly) invalidated replay, meaning identity and execution may be looking at two different snapshots", r3.Graph.FileCount)
	}
}

// TestV7Case23ConsumedArtifactChangeBetweenHashAndStagingInvalidatesReplay
// proves artifacts.go's consumedArtifactIdentities reads each consumed
// artifact's bytes exactly ONCE, sealing them into stagedArtifact.data
// (comment: "the sealed content captured before replay lookup ... never
// serialized into identity; SHA256 and Bytes bind it there"), and that
// data is what flows -- via newTransactionSnapshot's own defensive copy --
// all the way to stageConsumedArtifacts, which writes the SEALED bytes and
// only self-checks them against the SHA256/Bytes captured at read time
// (sha256.Sum256(artifact.data) != artifact.SHA256 => hard error). There is
// no second read of the ledger file's path between hashing and staging for
// a TOCTOU window to exist in -- so the only way "the consumed artifact
// changed between hash and staging" can matter is if the ledger file was
// already tampered with BEFORE consumedArtifactIdentities's own read, which
// its actualSHA-vs-ledger-recorded-sha check (artifacts.go line ~78) must
// catch and fail closed on, rather than silently sealing and staging
// content that doesn't match what the producer's run actually recorded.
// Reuses TestV6Case22's producer/consumer contract shapes (this file's own
// package), but instead of a legitimate producer re-run, directly
// overwrites the ledger-stored artifact file's bytes on disk -- simulating
// an attacker with write access to $GOV_HOME/artifacts between production
// and consumption -- and asserts the consumer run refuses rather than
// silently staging the tampered bytes.
func TestV7Case23ConsumedArtifactChangeBetweenHashAndStagingInvalidatesReplay(t *testing.T) {
	root := fixtureRepo(t)
	home := t.TempDir()

	registryFile := filepath.Join(t.TempDir(), "tools.yaml")
	t.Setenv("GOV_TOOLREGISTRY_FILE", registryFile)
	strictReplayEnrollControllerTools(t)

	producer := contracts.Contract{
		Task: "producer", JobID: "v7-case23-producer", JobType: "test", Agent: "claude-code", Mode: contracts.ModeSurgeon,
		Workspace:   contracts.Workspace{Root: root, Worktree: "auto"},
		Allowed:     contracts.Permissions{Read: []string{"**"}, Write: []string{"output/**", ".governator/artifacts/**"}, Execute: []string{"test"}},
		Forbidden:   contracts.Forbidden{Paths: []string{".git/**"}, Commands: []string{"rm -rf"}, Behaviors: []string{"network"}},
		Budget:      contracts.Budget{MaxMinutes: 1, MaxCommands: 5, MaxFilesChanged: 5, MaxLinesChanged: 20, MaxNewFiles: 5, MaxDeleted: 0},
		Preflight:   contracts.Preflight{IntendedWrites: []string{"output/**", ".governator/artifacts/**"}},
		Success:     contracts.Success{RequiredFiles: []string{"output/result.txt"}, Validators: []string{"test -f output/result.txt"}},
		Produces:    []contracts.ArtifactSpec{{Name: "art", Path: ".governator/artifacts/art.txt", MaxBytes: 1024}},
		OnViolation: "quarantine",
		Local:       &contracts.LocalRunnerConfig{ReadRoots: shellReadRootsForFixtures()},
	}
	producerBin := fakeBackend(t, `mkdir -p .governator/artifacts
printf '%s' 'v1' > .governator/artifacts/art.txt
mkdir -p output
printf 'ok\n' > output/result.txt
printf '{"status":"complete","files_changed":["output/result.txt",".governator/artifacts/art.txt"],"commands_run":0,"validation":{"self_checked":true},"violations":[],"blockers":[],"next_recommended_action":"none"}\n' > RESULT.json
printf '{"type":"result","total_cost_usd":0.25}\n'
`)
	p1 := runGoverned(t, home, producerBin, producer)
	if p1.Status != "APPROVED" {
		t.Fatalf("producer expected APPROVED, got status=%s message=%s", p1.Status, p1.Message)
	}

	// Locate the ledger's stored copy of the artifact and tamper with it
	// directly, bypassing any governed run -- the attacker model this case
	// targets.
	matches, err := filepath.Glob(filepath.Join(home, "artifacts", "*", ".governator", "artifacts", "art.txt"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("expected exactly one ledger artifact file, found %v (err=%v)", matches, err)
	}
	// Same length as the original "v1" so the ledger's recorded byte COUNT
	// still matches (isolating this test to the SHA256 comparison
	// specifically, rather than the separate size check artifacts.go also
	// performs -- both are valid fail-closed outcomes of the same
	// tamper-detection property, but only a content swap of equal length
	// proves the hash check itself, not just a length check).
	if err := os.WriteFile(matches[0], []byte("v2"), 0644); err != nil {
		t.Fatal(err)
	}

	consumer := contracts.Contract{
		Task: "consumer", JobID: "v7-case23-consumer", JobType: "test", Agent: "claude-code", Mode: contracts.ModeSurgeon,
		Workspace:       contracts.Workspace{Root: root, Worktree: "auto"},
		Allowed:         contracts.Permissions{Read: []string{"**"}, Write: []string{"output/**"}, Execute: []string{"test"}},
		Forbidden:       contracts.Forbidden{Paths: []string{".git/**"}, Commands: []string{"rm -rf"}, Behaviors: []string{"network"}},
		Budget:          contracts.Budget{MaxMinutes: 1, MaxCommands: 5, MaxFilesChanged: 5, MaxLinesChanged: 20, MaxNewFiles: 5, MaxDeleted: 0},
		Preflight:       contracts.Preflight{IntendedWrites: []string{"output/**"}},
		Success:         contracts.Success{RequiredFiles: []string{"output/result.txt"}, Validators: []string{"test -f output/result.txt"}},
		Consumes:        []string{"art"},
		ArtifactSources: map[string]string{"art": "v7-case23-producer"},
		OnViolation:     "quarantine",
		Local:           &contracts.LocalRunnerConfig{ReadRoots: shellReadRootsForFixtures()},
	}
	consumerBin := fakeBackend(t, `mkdir -p output
cat .governator/consumed/art > output/result.txt
printf '{"status":"complete","files_changed":["output/result.txt"],"commands_run":0,"validation":{"self_checked":true},"violations":[],"blockers":[],"next_recommended_action":"none"}\n' > RESULT.json
printf '{"type":"result","total_cost_usd":0.25}\n'
`)

	_, cerr := runGovernedAllowError(t, home, consumerBin, consumer)
	if cerr == nil {
		t.Fatal("consumer run succeeded after the ledger-stored artifact was tampered with on disk -- consumedArtifactIdentities's sha256 mismatch check did not fail closed")
	}
	if !strings.Contains(cerr.Error(), "sha256 mismatch") {
		t.Fatalf("consumer run failed for an unexpected reason (want a sha256-mismatch failure): %v", cerr)
	}
}

// TestV7Case29ModelVisibleCanaryChangeInvalidatesReplay proves RB5's
// "a random per-run canary makes the prompt differ every run" defect is
// closed structurally, not merely hashed-around: runtime.go's runOnce
// (line ~2838) appends only a STATIC instruction sentence to
// compiledPromptForIdentity -- "Controller canary: .governator-canary must
// remain byte-for-byte unchanged. Touching it quarantines the run." -- the
// canary's actual per-run random VALUE (the run ID written to the
// .governator-canary FILE, runtime.go line ~2942) is never interpolated
// into that sentence or into any other model-visible text (verified by
// source read: no %s/Sprintf touches this string, no run ID concatenation
// exists in the compiled-prompt path). Governator's tamper detection for
// that file works entirely out-of-band, via the post-run
// workBefore/workAfter fingerprint diff (runtime.go line ~3246), never by
// showing the model its expected value. Because of this, there is no lever
// a black-box fixture can pull to change "the canary" the model sees
// between two runs without literally patching the Go source -- the
// contract-level mechanism this case's real security boundary rests on is
// schema.go's Contract.Validate(), which HARD REQUIRES
// EffectiveCanaryPolicy() == "exclude_random_bytes_from_model" for every
// contract (schema.go line ~867) and structurally forbids any contract from
// declaring otherwise. This test proves that boundary black-box: a contract
// that tries to declare a different canary policy (an operator or an
// attacker with contract-authoring access attempting to reintroduce a
// random model-visible canary) is rejected before any workspace, backend,
// or replay decision -- exactly the failure mode this corpus case exists to
// prevent, closed at the earliest possible gate rather than relying on
// prompt-hash comparison to catch it after the fact.
func TestV7Case29ModelVisibleCanaryChangeInvalidatesReplay(t *testing.T) {
	root := fixtureRepo(t)
	home := t.TempDir()

	registryFile := filepath.Join(t.TempDir(), "tools.yaml")
	t.Setenv("GOV_TOOLREGISTRY_FILE", registryFile)
	strictReplayEnrollControllerTools(t)

	c := baseContract(root)
	c.Replay = &contracts.ReplayPolicy{CanaryPolicy: "include_random_bytes_in_model_prompt"}
	bin := fakeBackend(t, standardBackendBody(""))

	_, err := runGovernedAllowError(t, home, bin, c)
	if err == nil {
		t.Fatal("a contract declaring a canary_policy other than exclude_random_bytes_from_model was accepted -- a random model-visible canary could reach the model, breaking replay integrity every run")
	}
	if !strings.Contains(err.Error(), "canary_policy") {
		t.Fatalf("run failed for an unexpected reason (want a canary_policy validation failure): %v", err)
	}

	// The safe default (no Replay block at all, exactly what every other
	// case in this corpus uses via baseContract/strictReplayContract) must
	// keep working -- this policy is a floor, not a trap that blocks
	// ordinary contracts.
	c.Replay = nil
	r1 := runGoverned(t, home, bin, c)
	if r1.Status != "APPROVED" {
		t.Fatalf("run with default (nil) canary policy expected APPROVED, got status=%s message=%s", r1.Status, r1.Message)
	}
}

// TestV7Case25AssayerCommitChangeInvalidatesReplay proves a new commit at
// GOV_ASSAY_REPO invalidates replay for a contract that actually declares
// an assay block. Sol10 P0-6 narrowed resolvedAssayerEnvironmentHash to
// derive solely from the frozen *assay.Snapshot built for THIS
// transaction (internal/assay/snapshot.go's SnapshotIdentity.GitCommit,
// resolved once per BuildSnapshot call) -- and runtime.go only builds that
// snapshot when the contract itself declares c.Assay (Session 6's fix:
// binding identity to the bridge-level repo regardless of whether this
// contract even uses assay was exactly the "hybrid identity" over-breadth
// the report flagged). So this contract must set c.Assay, or no snapshot
// is ever built and there is nothing for a commit change to invalidate.
func TestV7Case25AssayerCommitChangeInvalidatesReplay(t *testing.T) {
	strictReplayConfig(t)
	root := fixtureRepo(t)
	home := t.TempDir()

	registryFile := filepath.Join(t.TempDir(), "tools.yaml")
	t.Setenv("GOV_TOOLREGISTRY_FILE", registryFile)
	strictReplayEnrollControllerTools(t)

	assayRepo := t.TempDir()
	writeMinimalAssayerRepo(t, assayRepo)
	gitEnv := append(os.Environ(), "GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.com", "GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.com")
	for _, args := range [][]string{{"init"}, {"add", "."}, {"commit", "-m", "v1"}} {
		cmd := exec.Command("git", append([]string{"-C", assayRepo}, args...)...)
		cmd.Env = gitEnv
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	t.Setenv("GOV_ASSAY_REPO", assayRepo)

	c := strictReplayContract(root)
	// advisory: writeMinimalAssayerRepo's cli.py doesn't implement a real
	// `evaluate` subcommand, so Evaluate will return a VerdictError -- fine
	// under advisory (assay.Blocks only blocks under "blocking"
	// enforcement), and this case cares only about identity binding the
	// snapshot, not about a real passing verdict.
	c.Assay = &contracts.Assay{Profile: "coding-output-v1", Enforcement: "advisory"}
	bin := fakeBackend(t, standardBackendBody(""))

	runStrictReplayBaseline(t, home, bin, c)

	cmd := exec.Command("git", "-C", assayRepo, "commit", "--allow-empty", "-m", "v2")
	cmd.Env = gitEnv
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git commit --allow-empty: %v: %s", err, out)
	}

	r3 := runGoverned(t, home, bin, c)
	if r3.Replayed {
		t.Fatal("run 3 replayed a stale approval after the Assayer checkout's commit (.git/HEAD) changed -- replay identity does not bind the Assayer commit")
	}
}

// TestV7Case26AssayerProfileChangeInvalidatesReplay is Case 25's sibling:
// the frozen snapshot's ProfileHash (assayer/profiles.py's content at copy
// time) also invalidates replay when it changes, even though GOV_ASSAY_REPO's
// path and .git/HEAD are unchanged. Like Case 25, c.Assay must be declared
// so BuildSnapshot actually runs for this transaction (Sol10 P0-6).
func TestV7Case26AssayerProfileChangeInvalidatesReplay(t *testing.T) {
	strictReplayConfig(t)
	root := fixtureRepo(t)
	home := t.TempDir()

	registryFile := filepath.Join(t.TempDir(), "tools.yaml")
	t.Setenv("GOV_TOOLREGISTRY_FILE", registryFile)
	strictReplayEnrollControllerTools(t)

	assayRepo := t.TempDir()
	writeMinimalAssayerRepo(t, assayRepo)
	profilePath := filepath.Join(assayRepo, "assayer", "profiles.py")
	t.Setenv("GOV_ASSAY_REPO", assayRepo)

	c := strictReplayContract(root)
	c.Assay = &contracts.Assay{Profile: "coding-output-v1", Enforcement: "advisory"}
	bin := fakeBackend(t, standardBackendBody(""))

	runStrictReplayBaseline(t, home, bin, c)

	if err := os.WriteFile(profilePath, []byte("PROFILES = {'coding-output-v1': {'checks': ['v1', 'v2-new-check']}}\n"), 0644); err != nil {
		t.Fatal(err)
	}

	r3 := runGoverned(t, home, bin, c)
	if r3.Replayed {
		t.Fatal("run 3 replayed a stale approval after the Assayer profile definition (assayer/profiles.py) changed -- replay identity does not bind the Assayer profile bytes")
	}
}

// copyToNewInode writes src's bytes to a brand-new file (a fresh device/
// inode even when the content is byte-identical to a prior copy) so two
// successive enrollments of "the same" tool can still be distinguished by
// identity, exactly as internal/runtime/identity_v2.go's
// participantFromRegistry folds Device/Inode into each participant's
// ExecutableIdentity.
func copyToNewInode(t *testing.T, src string) string {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), filepath.Base(src))
	if err := os.WriteFile(dst, data, 0755); err != nil {
		t.Fatal(err)
	}
	return dst
}

// TestV7Case27GitIdentityChangeInvalidatesReplay proves the registered
// "git" participant's resolved identity (internal/runtime/identity_v2.go's
// participantFromRegistry, folded into ExecutionIdentity.Participants) is
// bound into replay: re-enrolling git at a different verified path (a fresh
// copy of the same real binary -- a different device/inode even though the
// content is identical) must invalidate replay.
func TestV7Case27GitIdentityChangeInvalidatesReplay(t *testing.T) {
	strictReplayConfig(t)
	enforce.SelfExeOverride = govBinary(t)
	defer func() { enforce.SelfExeOverride = "" }()

	root := fixtureRepo(t)
	home := t.TempDir()

	registryFile := filepath.Join(t.TempDir(), "tools.yaml")
	t.Setenv("GOV_TOOLREGISTRY_FILE", registryFile)
	strictReplayEnrollControllerTools(t)

	gitPath, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not available")
	}
	gitCopyA := copyToNewInode(t, gitPath)
	if _, err := toolregistry.Enroll("git", gitCopyA); err != nil {
		t.Fatal(err)
	}

	c := strictReplayContract(root)
	bin := fakeBackend(t, standardBackendBody(""))

	runStrictReplayDirectBaseline(t, home, bin, c)

	gitCopyB := copyToNewInode(t, gitPath)
	if _, err := toolregistry.Enroll("git", gitCopyB); err != nil {
		t.Fatal(err)
	}

	r3 := runStrictReplayDirect(t, home, bin, c)
	if r3.Replayed {
		t.Fatal("run 3 replayed a stale approval after the registered git binary was re-enrolled at a different verified path -- replay identity does not bind the resolved git participant identity")
	}
}

// TestV7Case28BashIdentityChangeInvalidatesReplay is Case 27's sibling for
// the registered "bash" (shell) participant.
func TestV7Case28BashIdentityChangeInvalidatesReplay(t *testing.T) {
	strictReplayConfig(t)
	enforce.SelfExeOverride = govBinary(t)
	defer func() { enforce.SelfExeOverride = "" }()

	root := fixtureRepo(t)
	home := t.TempDir()

	registryFile := filepath.Join(t.TempDir(), "tools.yaml")
	t.Setenv("GOV_TOOLREGISTRY_FILE", registryFile)
	strictReplayEnrollControllerTools(t)

	bashPath, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	bashCopyA := copyToNewInode(t, bashPath)
	if _, err := toolregistry.Enroll("bash", bashCopyA); err != nil {
		t.Fatal(err)
	}

	c := strictReplayContract(root)
	bin := fakeBackend(t, standardBackendBody(""))

	runStrictReplayDirectBaseline(t, home, bin, c)

	bashCopyB := copyToNewInode(t, bashPath)
	if _, err := toolregistry.Enroll("bash", bashCopyB); err != nil {
		t.Fatal(err)
	}

	r3 := runStrictReplayDirect(t, home, bin, c)
	if r3.Replayed {
		t.Fatal("run 3 replayed a stale approval after the registered bash binary was re-enrolled at a different verified path -- replay identity does not bind the resolved shell participant identity")
	}
}
