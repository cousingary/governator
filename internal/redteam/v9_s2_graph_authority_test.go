//go:build redteam

// v9_s2_graph_authority_test.go is Sol redteam v9's rc3 Session 2 corpus
// (agents/governator-sol-upgrade9-rc3-plan.md Session 2,
// agents/governator-sol-upgrade9.md P0-3): "report cases 7-12".
//
// P0-3 was that internal/contextgraph.scopedCommandOutput declared
// project-read-only authority (no write roots) for every graph-provider
// invocation, including init/sync -- which write
// <project>/.codegraph/codegraph.db -- so init/sync failed under real
// Landlock enforcement (or silently degraded in "auto" mode); and that the
// same function reloaded the trusted-tool registry and re-resolved the
// provider on every invocation without requiring the newly resolved
// identity to equal the status frozen before replay, letting a same-name
// provider rotation change what actually executes.
//
// TestV9Case7/8 prove init/sync now succeed under real Landlock enforcement
// with exactly a .codegraph write root. TestV9Case9/10 prove provider
// identity is pinned across a frozen Status/Registry, not re-trusted by
// name. TestV9Case11/12 prove a provider that tries to write outside
// .codegraph (a mutating op) or at all (a read-only op) is denied.
package redteam

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/cousingary/governator/internal/config"
	"github.com/cousingary/governator/internal/contextgraph"
	"github.com/cousingary/governator/internal/controllerenv"
	"github.com/cousingary/governator/internal/enforce"
	"github.com/cousingary/governator/internal/toolregistry"
)

// buildGraphCommandBinary compiles a tiny real ELF binary standing in for a
// governed graph-provider tool, with a caller-supplied Go statement body per
// subcommand this corpus needs (version/status/init/sync) -- an extension of
// harness_test.go's buildFakeCodegraphBinary, which only covers
// version/status, for this file's init/sync fixtures. projectArg() mirrors
// how graph.go's scopedCommandOutput actually invokes the real codegraph
// CLI: version/init/sync/status all pass the project path as the final
// argument, but Query passes it via --path with a distinct final argument
// (the search term), so every fixture body resolves the project the same
// way a real provider would have to.
func buildGraphCommandBinary(t *testing.T, cases map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, "main.go")
	var body strings.Builder
	for _, cmd := range []string{"version", "status", "init", "sync", "query"} {
		stmt, ok := cases[cmd]
		if !ok {
			continue
		}
		body.WriteString("\tcase \"" + cmd + "\":\n" + stmt + "\n")
	}
	source := `package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

func projectArg() string {
	for i, a := range os.Args {
		if a == "--path" && i+1 < len(os.Args) {
			return os.Args[i+1]
		}
	}
	return os.Args[len(os.Args)-1]
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("{}")
		return
	}
	switch os.Args[1] {
` + body.String() + `	default:
		fmt.Println("{}")
	}
}
`
	if err := os.WriteFile(src, []byte(source), 0644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "codegraph")
	cmd := exec.Command("go", "build", "-buildvcs=false", "-o", out, src)
	cmd.Dir = dir
	if combined, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build fake codegraph binary: %v: %s", err, combined)
	}
	return out
}

// graphVersionStatement emits a fixed version string.
func graphVersionStatement(version string) string {
	return `		fmt.Println(` + strconv.Quote(version) + `)`
}

// graphStatusStatement reports initialized=true once
// .codegraph/codegraph.db exists, matching how a real codegraph reports
// status after init/sync actually ran.
func graphStatusStatement() string {
	return `		project := projectArg()
		db := filepath.Join(project, ".codegraph", "codegraph.db")
		initialized := false
		if _, statErr := os.Stat(db); statErr == nil {
			initialized = true
		}
		out, _ := json.Marshal(map[string]any{
			"version":     "1.0.0",
			"initialized": initialized,
			"projectPath": project,
			"indexPath":   db,
			"fileCount":   1,
			"nodeCount":   1,
			"edgeCount":   1,
			"dbSizeBytes": 1,
		})
		fmt.Println(string(out))`
}

// graphWriteDBStatement is a legitimate init/sync: write exactly
// .codegraph/codegraph.db with content, nothing else.
func graphWriteDBStatement(content string) string {
	return `		project := projectArg()
		dir := filepath.Join(project, ".codegraph")
		_ = os.MkdirAll(dir, 0o755)
		_ = os.WriteFile(filepath.Join(dir, "codegraph.db"), []byte(` + strconv.Quote(content) + `), 0o644)`
}

// graphWriteDBAndEscapeStatement is graphWriteDBStatement plus a hostile
// write outside .codegraph, for the write-root-scoping denial case.
func graphWriteDBAndEscapeStatement(content string) string {
	return graphWriteDBStatement(content) + `
		_ = os.WriteFile(filepath.Join(project, "escaped-outside-codegraph.txt"), []byte("escaped"), 0o644)`
}

// graphStatusEscapeStatement is a read-only "status" invocation that also
// tries to write into the project, for the read-only-authority denial case.
func graphStatusEscapeStatement() string {
	return `		project := projectArg()
		_ = os.WriteFile(filepath.Join(project, "escaped-from-readonly-op.txt"), []byte("escaped"), 0o644)
		out, _ := json.Marshal(map[string]any{"initialized": false})
		fmt.Println(string(out))`
}

// graphAuthoritySkipIfUnsupported is this file's shared preflight: every
// case here needs a real Landlock/unshare-backed launch, not a fixture
// substitute (Sol's own report was reproduced against a real host).
func graphAuthoritySkipIfUnsupported(t *testing.T) {
	t.Helper()
	enforce.SelfExeOverride = govBinary(t)
	t.Cleanup(func() { enforce.SelfExeOverride = "" })
	if !enforce.Supported() {
		t.Skip("this host cannot provide externally enforced containment (Landlock ABI/unshare unavailable) -- nothing to exercise")
	}
}

// graphAuthorityIsolatedRegistry gives the test a disposable trusted-tool
// registry with the standard controller tools (git/bash/unshare/
// systemd-run) enrolled, mirroring TestV9Case2's setup.
func graphAuthorityIsolatedRegistry(t *testing.T) {
	t.Helper()
	registryFile := filepath.Join(t.TempDir(), "tools.yaml")
	t.Setenv("GOV_TOOLREGISTRY_FILE", registryFile)
	enrollRealControllerTools(t)
}

// TestV9Case7GraphInitSucceedsUnderActiveLandlock is report case 7: a
// project with no existing .codegraph must actually initialize under real
// Landlock enforcement now that PrepareWithStatus precreates and grants
// exactly the .codegraph directory as a write root, instead of the
// project-read-only authority that made init fail (or "auto" mode silently
// degrade) before this session.
func TestV9Case7GraphInitSucceedsUnderActiveLandlock(t *testing.T) {
	graphAuthoritySkipIfUnsupported(t)
	graphAuthorityIsolatedRegistry(t)

	root := fixtureRepo(t)
	bin := buildGraphCommandBinary(t, map[string]string{
		"version": graphVersionStatement("codegraph 1.0.0"),
		"status":  graphStatusStatement(),
		"init":    graphWriteDBStatement("graph-init-content"),
	})
	if _, err := toolregistry.Enroll("codegraph", bin); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_GRAPH_MODE", "required")
	t.Setenv("GOV_GRAPH_PROVIDER", "codegraph")
	t.Setenv("GOV_GRAPH_BIN", bin)

	snapshot, err := contextgraph.Prepare(context.Background(), root)
	if err != nil {
		t.Fatalf("graph init under active Landlock failed: %v (snapshot=%+v)", err, snapshot)
	}
	if !snapshot.Available || !snapshot.Refreshed {
		t.Fatalf("snapshot not marked available/refreshed: %+v", snapshot)
	}
	data, rerr := os.ReadFile(filepath.Join(root, ".codegraph", "codegraph.db"))
	if rerr != nil {
		t.Fatalf("expected codegraph.db to exist after init: %v", rerr)
	}
	if string(data) != "graph-init-content" {
		t.Fatalf("codegraph.db content = %q, want graph-init-content", data)
	}
}

// TestV9Case8GraphSyncSucceedsUnderActiveLandlock is report case 8: a
// project with an existing (stale) .codegraph/codegraph.db must be
// re-synced under real Landlock enforcement, and PriorGraphFingerprint must
// capture the pre-mutation content distinctly from the post-mutation
// Fingerprint (work item: "fingerprint .codegraph before/after").
func TestV9Case8GraphSyncSucceedsUnderActiveLandlock(t *testing.T) {
	graphAuthoritySkipIfUnsupported(t)
	graphAuthorityIsolatedRegistry(t)

	root := fixtureRepo(t)
	preDir := filepath.Join(root, ".codegraph")
	if err := os.MkdirAll(preDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(preDir, "codegraph.db"), []byte("graph-stale-content"), 0o644); err != nil {
		t.Fatal(err)
	}

	bin := buildGraphCommandBinary(t, map[string]string{
		"version": graphVersionStatement("codegraph 1.0.0"),
		"status":  graphStatusStatement(),
		"sync":    graphWriteDBStatement("graph-synced-content"),
	})
	if _, err := toolregistry.Enroll("codegraph", bin); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_GRAPH_MODE", "required")
	t.Setenv("GOV_GRAPH_PROVIDER", "codegraph")
	t.Setenv("GOV_GRAPH_BIN", bin)

	snapshot, err := contextgraph.Prepare(context.Background(), root)
	if err != nil {
		t.Fatalf("graph sync under active Landlock failed: %v (snapshot=%+v)", err, snapshot)
	}
	if !snapshot.Available || !snapshot.Refreshed {
		t.Fatalf("snapshot not marked available/refreshed: %+v", snapshot)
	}
	data, rerr := os.ReadFile(filepath.Join(root, ".codegraph", "codegraph.db"))
	if rerr != nil {
		t.Fatalf("expected codegraph.db to exist after sync: %v", rerr)
	}
	if string(data) != "graph-synced-content" {
		t.Fatalf("codegraph.db content = %q, want graph-synced-content", data)
	}
	if snapshot.PriorGraphFingerprint == "" || snapshot.PriorGraphFingerprint == snapshot.Fingerprint {
		t.Fatalf("expected a distinct PriorGraphFingerprint capturing pre-sync content: prior=%q fingerprint=%q", snapshot.PriorGraphFingerprint, snapshot.Fingerprint)
	}
}

// TestV9Case9GraphProviderRotatedAfterFreezeCannotExecute is report case 9:
// a registered "codegraph" provider rotated (same name, different verified
// object) after Status was resolved (its identity frozen into
// status.IdentityID) must be rejected on the next invocation, not silently
// executed under the old, no-longer-current identity's authority.
func TestV9Case9GraphProviderRotatedAfterFreezeCannotExecute(t *testing.T) {
	graphAuthoritySkipIfUnsupported(t)
	graphAuthorityIsolatedRegistry(t)

	providerA := buildGraphCommandBinary(t, map[string]string{
		"version": graphVersionStatement("codegraph provider-a"),
		"status":  graphStatusStatement(),
	})
	providerB := buildGraphCommandBinary(t, map[string]string{
		"version": graphVersionStatement("codegraph provider-b"),
		"status":  graphStatusStatement(),
	})
	if _, err := toolregistry.Enroll("codegraph", providerA); err != nil {
		t.Fatal(err)
	}
	// Loaded AFTER providerA is enrolled, so this Registry snapshot actually
	// contains it.
	registry, err := toolregistry.Load()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_GRAPH_MODE", "required")
	t.Setenv("GOV_GRAPH_PROVIDER", "codegraph")
	t.Setenv("GOV_GRAPH_BIN", providerA)
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	status, err := contextgraph.ResolveConfigWithRegistry(cfg, registry)
	if err != nil {
		t.Fatal(err)
	}
	if status.IdentityID == "" {
		t.Fatal("expected a pinned provider identity after resolution")
	}

	// Rotation: enroll a different verified object under the same name
	// AFTER status's identity was frozen.
	if _, err := toolregistry.Enroll("codegraph", providerB); err != nil {
		t.Fatal(err)
	}

	if _, err := contextgraph.Version(context.Background(), status); err == nil || !strings.Contains(err.Error(), "identity changed since resolution") {
		t.Fatalf("expected an identity-changed rejection after provider rotation, got err=%v", err)
	}
}

// TestV9Case10FrozenRegistryObjectImmuneToOnDiskRegistryChange is report
// case 10: once a run environment has frozen a *toolregistry.Registry
// (buildRunEnvironment, called once at the top of runOnce), an unrelated
// on-disk registry mutation mid-transaction must not change what a later
// graph invocation in that same transaction executes -- CurrentWithStatus/
// PrepareWithStatus must keep using the frozen Registry object, never
// reload it (Sol v9 P0-3: "Do not reload the registry inside graph
// execution").
func TestV9Case10FrozenRegistryObjectImmuneToOnDiskRegistryChange(t *testing.T) {
	graphAuthoritySkipIfUnsupported(t)
	graphAuthorityIsolatedRegistry(t)

	root := fixtureRepo(t)
	providerA := buildGraphCommandBinary(t, map[string]string{
		"version": graphVersionStatement("codegraph 1.0.0"),
		"status":  graphStatusStatement(),
	})
	if _, err := toolregistry.Enroll("codegraph", providerA); err != nil {
		t.Fatal(err)
	}

	// Frozen BEFORE the on-disk mutation below -- mirrors
	// buildRunEnvironment's one-time toolregistry.Load().
	registry, err := toolregistry.Load()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_GRAPH_MODE", "required")
	t.Setenv("GOV_GRAPH_PROVIDER", "codegraph")
	t.Setenv("GOV_GRAPH_BIN", providerA)
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	status, err := contextgraph.ResolveConfigWithRegistry(cfg, registry)
	if err != nil {
		t.Fatal(err)
	}

	// An unrelated actor (operator `gov tools enroll`, or same-uid hostile
	// process) rotates the registry ON DISK while this "transaction" is
	// in-flight. The already-loaded registry object must not observe it.
	providerB := buildGraphCommandBinary(t, map[string]string{
		"version": graphVersionStatement("codegraph 2.0.0"),
		"status":  graphStatusStatement(),
	})
	if _, err := toolregistry.Enroll("codegraph", providerB); err != nil {
		t.Fatal(err)
	}

	snapshot, err := contextgraph.CurrentWithStatus(context.Background(), root, status, registry, controllerenv.Freeze())
	if err != nil {
		t.Fatalf("frozen-registry execution failed after an unrelated on-disk registry change: %v", err)
	}
	if snapshot.Version != "codegraph 1.0.0" {
		t.Fatalf("frozen registry executed the rotated provider instead of the one frozen at construction: version=%q", snapshot.Version)
	}
}

// TestV9Case11GraphProviderWriteOutsideCodegraphDenied is report case 11: a
// mutating (init) invocation's write authority is exactly the precreated
// .codegraph directory -- a provider that also writes elsewhere in the
// project must have that second write denied under real Landlock
// enforcement, regardless of whether the legitimate .codegraph write
// succeeds.
func TestV9Case11GraphProviderWriteOutsideCodegraphDenied(t *testing.T) {
	graphAuthoritySkipIfUnsupported(t)
	graphAuthorityIsolatedRegistry(t)

	root := fixtureRepo(t)
	bin := buildGraphCommandBinary(t, map[string]string{
		"version": graphVersionStatement("codegraph 1.0.0"),
		"status":  graphStatusStatement(),
		"init":    graphWriteDBAndEscapeStatement("graph-init-content"),
	})
	if _, err := toolregistry.Enroll("codegraph", bin); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_GRAPH_MODE", "auto")
	t.Setenv("GOV_GRAPH_PROVIDER", "codegraph")
	t.Setenv("GOV_GRAPH_BIN", bin)

	_, _ = contextgraph.Prepare(context.Background(), root)

	if _, err := os.Stat(filepath.Join(root, "escaped-outside-codegraph.txt")); err == nil {
		t.Fatal("graph provider wrote outside .codegraph during init and the write was not denied")
	}
	// The legitimate write must still have succeeded -- proving write
	// authority is exactly .codegraph, not that init is broken outright
	// (which would make the escape assertion above vacuous).
	if _, err := os.Stat(filepath.Join(root, ".codegraph", "codegraph.db")); err != nil {
		t.Fatalf("expected the legitimate .codegraph write to succeed alongside the denied escape: %v", err)
	}
}

// TestV9Case12GraphReadOnlyOperationWriteDenied is report case 12: a
// read-only invocation (status, reached via Current -- version/status only,
// no init/sync) gets no write roots at all; any write attempt, even inside
// the project directory it is allowed to read, must be denied.
func TestV9Case12GraphReadOnlyOperationWriteDenied(t *testing.T) {
	graphAuthoritySkipIfUnsupported(t)
	graphAuthorityIsolatedRegistry(t)

	root := fixtureRepo(t)
	bin := buildGraphCommandBinary(t, map[string]string{
		"version": graphVersionStatement("codegraph 1.0.0"),
		"status":  graphStatusEscapeStatement(),
	})
	if _, err := toolregistry.Enroll("codegraph", bin); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_GRAPH_MODE", "auto")
	t.Setenv("GOV_GRAPH_PROVIDER", "codegraph")
	t.Setenv("GOV_GRAPH_BIN", bin)

	_, _ = contextgraph.Current(root)

	if _, err := os.Stat(filepath.Join(root, "escaped-from-readonly-op.txt")); err == nil {
		t.Fatal("read-only graph operation (status) wrote into the project and the write was not denied")
	}
}
