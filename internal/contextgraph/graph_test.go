package contextgraph

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cousingary/governator/internal/enforce"
	"github.com/cousingary/governator/internal/toolregistry"
)

func secureGraphTempDir(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(home, ".gov-contextgraph-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func requireExternalSandbox(t *testing.T) {
	t.Helper()
	if enforce.SelfExeOverride == "" {
		t.Skip("contextgraph stage tests require a real gov sandbox harness")
	}
	if unsharePath, err := exec.LookPath("unshare"); err == nil {
		_, _ = toolregistry.Enroll("unshare", unsharePath)
	}
	if !enforce.Supported() {
		t.Skip("external sandbox unavailable on this host")
	}
}

func graphEnv(t *testing.T, mode, bin string) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("GOV_CONFIG", "")
	t.Setenv("GOV_GRAPH_MODE", mode)
	t.Setenv("GOV_GRAPH_PROVIDER", "codegraph")
	t.Setenv("GOV_GRAPH_BIN", bin)
}

// trustCodegraph registers "codegraph" as a trusted controller tool for
// this test (Sol S4 / P0-5: Resolve now refuses to run any provider absent
// an explicit trust declaration — see toolregistry). Tests exercising a
// deliberately untrusted/unregistered provider (report attack 9) must NOT
// call this.
//
// Sol14 P0-2 (rc7 Session 5): this deliberately switches to a FRESH
// registry (an empty tools.yaml) to prove the trust decision is isolated
// -- but that fresh registry also drops the unshare enrollment the real
// Landlock+netns sandbox needs to wrap the launch. In the unit tier that
// never mattered (these tests skipped before a sandbox was ever built); in
// the integration tier the sandboxed codegraph launch fails to resolve
// unshare and refuses. Re-enroll unshare into the same fresh registry so
// the isolated trust decision and the real sandbox coexist.
func trustCodegraph(t *testing.T, bin string) {
	t.Helper()
	reg := filepath.Join(t.TempDir(), "tools.yaml")
	t.Setenv("GOV_TOOLREGISTRY_FILE", reg)
	if _, err := toolregistry.Enroll("codegraph", bin); err != nil {
		t.Fatal(err)
	}
	if unsharePath, err := exec.LookPath("unshare"); err == nil {
		if canonical, cerr := filepath.EvalSymlinks(unsharePath); cerr == nil {
			unsharePath = canonical
		}
		if _, err := toolregistry.Enroll("unshare", unsharePath); err != nil {
			t.Fatal(err)
		}
	}
}

// buildCodegraphELF compiles a tiny real ELF binary standing in for a
// governed graph-provider tool. A compiled binary's own exactReadClosure is
// self-sufficient under Governator's Landlock sandbox, unlike a #!/bin/sh
// script whose /bin/sh interpreter is not in the executable's read closure
// (enforce.exactReadClosure derives a closure only for ELF objects) -- which
// is exactly how a production graph-provider tool (a real compiled binary)
// is shaped, and the same approach the redteam corpus's
// buildFakeCodegraphBinary takes (internal/redteam/harness_test.go).
//
// Sol14 P0-2 (rc7 Session 5): these three stage tests previously skipped in
// the unit tier and never exercised the real sandbox; once the integration
// tier actually built the sandbox, the shell-script fixtures failed with
// "exec sandboxed executable: permission denied" because Landlock denied
// the script's interpreter. An ELF stub fixes that without changing what
// each test asserts (it still verifies Governator's parsing of codegraph's
// protocol output). broken drives the TestPrepareAutoDegradesOnProviderFailure
// shape: version still succeeds (printing "codegraph broken"), but every
// mutating/diagnostic command writes "build-failed" to stderr and exits 2.
func buildCodegraphELF(t *testing.T, broken bool) string {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, "main.go")
	out := filepath.Join(secureGraphTempDir(t), "codegraph")
	versionLine := "codegraph 0.24.0"
	if broken {
		versionLine = "codegraph broken"
	}
	source := `package main

import (
	"fmt"
	"os"
	"path/filepath"
)

const versionLine = "` + versionLine + `"
const broken = ` + fmt.Sprintf("%v", broken) + `

func fail() {
	fmt.Fprintln(os.Stderr, "build-failed")
	os.Exit(2)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("{}")
		return
	}
	sub := os.Args[1]
	project := os.Args[len(os.Args)-1]
	switch sub {
	case "version":
		fmt.Println(versionLine)
	case "init", "sync":
		if broken {
			fail()
		}
		graphDir := filepath.Join(project, ".codegraph")
		if err := os.MkdirAll(graphDir, 0o700); err != nil {
			fail()
		}
		if err := os.WriteFile(filepath.Join(graphDir, "codegraph.db"), []byte("deterministic graph db"), 0o600); err != nil {
			fail()
		}
	case "status":
		if broken {
			fail()
		}
		fmt.Printf("{\"initialized\":true,\"projectPath\":%q,\"indexPath\":%q,\"fileCount\":51,\"nodeCount\":689,\"edgeCount\":1579,\"dbSizeBytes\":22}\n", project, filepath.Join(project, ".codegraph"))
	case "query":
		if broken {
			fail()
		}
		fmt.Println("[{\"name\":\"RunRecord\",\"kind\":\"struct\"}]")
	default:
		os.Exit(1)
	}
}
`
	if err := os.WriteFile(src, []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	build := exec.Command("go", "build", "-buildvcs=false", "-o", out, src)
	if combined, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build codegraph elf: %v: %s", err, combined)
	}
	return out
}

func TestResolveAutoMissing(t *testing.T) {
	graphEnv(t, "auto", "codegraph-not-present")
	t.Setenv("PATH", t.TempDir())
	status, err := Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if status.Enabled {
		t.Fatalf("unexpected status: %+v", status)
	}
}

func TestResolveRequiredMissingFails(t *testing.T) {
	graphEnv(t, "required", "codegraph-not-present")
	t.Setenv("PATH", t.TempDir())
	if _, err := Resolve(); err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("error=%v", err)
	}
}

func TestInspectCodeGraphStatus(t *testing.T) {
	bin := buildCodegraphELF(t, false)
	graphEnv(t, "required", bin)
	requireExternalSandbox(t)
	trustCodegraph(t, bin)
	status, err := Resolve()
	if err != nil {
		t.Fatal(err)
	}
	version, err := Version(context.Background(), status)
	if err != nil || version != "codegraph 0.24.0" {
		t.Fatalf("version=%q err=%v", version, err)
	}
	stats, err := Inspect(context.Background(), status, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !stats.Initialized || stats.FileCount != 51 || stats.NodeCount != 689 || stats.EdgeCount != 1579 {
		t.Fatalf("stats=%+v", stats)
	}
}

func TestPrepareBuildsFingerprintAndQueries(t *testing.T) {
	bin := buildCodegraphELF(t, false)
	graphEnv(t, "required", bin)
	requireExternalSandbox(t)
	trustCodegraph(t, bin)
	project := t.TempDir()

	snapshot, err := Prepare(context.Background(), project)
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.Available || !snapshot.Refreshed || len(snapshot.Fingerprint) != 64 {
		t.Fatalf("snapshot=%+v", snapshot)
	}
	if snapshot.FileCount != 51 || snapshot.NodeCount != 689 || snapshot.EdgeCount != 1579 {
		t.Fatalf("snapshot stats=%+v", snapshot)
	}
	if snapshot.IndexPath != filepath.Join(project, ".codegraph", "codegraph.db") {
		t.Fatalf("index path=%q", snapshot.IndexPath)
	}
	output, err := Query(context.Background(), snapshot, "RunRecord", 5)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(output), "RunRecord") {
		t.Fatalf("query output=%s", output)
	}
	patterns := CommandPatterns(snapshot)
	annotation := PromptAnnotation(snapshot)
	if len(patterns) != 4 || !strings.Contains(annotation, snapshot.Fingerprint) || !strings.Contains(annotation, "Before broad grep") {
		t.Fatalf("patterns=%v annotation=%q", patterns, annotation)
	}
}

func TestPrepareAutoDegradesOnProviderFailure(t *testing.T) {
	bin := buildCodegraphELF(t, true)
	graphEnv(t, "auto", bin)
	requireExternalSandbox(t)
	trustCodegraph(t, bin)
	snapshot, err := Prepare(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Available || !strings.Contains(snapshot.Warning, "build-failed") {
		t.Fatalf("snapshot=%+v", snapshot)
	}
}
