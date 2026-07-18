package contextgraph

import (
	"context"
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
func trustCodegraph(t *testing.T, bin string) {
	t.Helper()
	reg := filepath.Join(t.TempDir(), "tools.yaml")
	t.Setenv("GOV_TOOLREGISTRY_FILE", reg)
	if _, err := toolregistry.Enroll("codegraph", bin); err != nil {
		t.Fatal(err)
	}
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
	bin := filepath.Join(secureGraphTempDir(t), "codegraph")
	script := `#!/bin/sh
if [ "$1" = version ]; then echo 'codegraph 0.24.0'; exit 0; fi
if [ "$1" = status ]; then echo '{"version":"0.24.0","initialized":true,"fileCount":51,"nodeCount":689,"edgeCount":1579,"dbSizeBytes":1765376,"languages":["go"]}'; exit 0; fi
exit 1
`
	if err := os.WriteFile(bin, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
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
	bin := filepath.Join(secureGraphTempDir(t), "codegraph")
	script := `#!/bin/sh
for arg in "$@"; do project="$arg"; done
case "$1" in
  version)
    echo 'codegraph 0.24.0'
    ;;
  init|sync)
    mkdir -p "$project/.codegraph"
    printf 'deterministic graph db' > "$project/.codegraph/codegraph.db"
    ;;
  status)
    if [ -f "$project/.codegraph/codegraph.db" ]; then
      printf '{"initialized":true,"projectPath":"%s","indexPath":"%s/.codegraph","fileCount":51,"nodeCount":689,"edgeCount":1579,"dbSizeBytes":22}\n' "$project" "$project"
    else
      printf '{"initialized":false}\n'
    fi
    ;;
  query)
    printf '[{"name":"RunRecord","kind":"struct"}]\n'
    ;;
  *) exit 1 ;;
esac
`
	if err := os.WriteFile(bin, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
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
	bin := filepath.Join(secureGraphTempDir(t), "codegraph")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nif [ \"$1\" = version ]; then echo 'codegraph broken'; exit 0; fi\necho build-failed >&2\nexit 2\n"), 0755); err != nil {
		t.Fatal(err)
	}
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
