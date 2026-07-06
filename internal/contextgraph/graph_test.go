package contextgraph

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func graphEnv(t *testing.T, mode, bin string) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("GOV_CONFIG", "")
	t.Setenv("GOV_GRAPH_MODE", mode)
	t.Setenv("GOV_GRAPH_PROVIDER", "codegraph")
	t.Setenv("GOV_GRAPH_BIN", bin)
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
	bin := filepath.Join(t.TempDir(), "codegraph")
	script := `#!/bin/sh
if [ "$1" = version ]; then echo 'codegraph 0.24.0'; exit 0; fi
if [ "$1" = status ]; then echo '{"version":"0.24.0","initialized":true,"fileCount":51,"nodeCount":689,"edgeCount":1579,"dbSizeBytes":1765376,"languages":["go"]}'; exit 0; fi
exit 1
`
	if err := os.WriteFile(bin, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	graphEnv(t, "required", bin)
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
	bin := filepath.Join(t.TempDir(), "codegraph")
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
	bin := filepath.Join(t.TempDir(), "codegraph")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nif [ \"$1\" = version ]; then echo 'codegraph broken'; exit 0; fi\necho build-failed >&2\nexit 2\n"), 0755); err != nil {
		t.Fatal(err)
	}
	graphEnv(t, "auto", bin)
	snapshot, err := Prepare(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Available || !strings.Contains(snapshot.Warning, "build-failed") {
		t.Fatalf("snapshot=%+v", snapshot)
	}
}
