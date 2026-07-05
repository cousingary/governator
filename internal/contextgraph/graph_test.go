package contextgraph

import (
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
	version, err := Version(status)
	if err != nil || version != "codegraph 0.24.0" {
		t.Fatalf("version=%q err=%v", version, err)
	}
	stats, err := Inspect(status, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !stats.Initialized || stats.FileCount != 51 || stats.NodeCount != 689 || stats.EdgeCount != 1579 {
		t.Fatalf("stats=%+v", stats)
	}
}
