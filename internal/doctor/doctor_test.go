package doctor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cousingary/governator/internal/observability"
)

func TestBackendHelpArgs(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want string
	}{
		{name: "root help", want: "--help"},
		{name: "subcommand help", in: []string{"run"}, want: "run --help"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := backendHelpArgs(test.in)
			if strings.Join(got, " ") != test.want {
				t.Fatalf("backendHelpArgs(%q) = %q, want %q", test.in, got, test.want)
			}
			if len(test.in) > 0 && test.in[0] != "run" {
				t.Fatalf("backendHelpArgs mutated its input: %q", test.in)
			}
		})
	}
}

func TestBackendFlagDriftFails(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("GOV_CONFIG", "")
	fake := filepath.Join(t.TempDir(), "opencode")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nprintf '%s\\n' '--format'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_OPENCODE_BIN", fake)

	check := checkBackendFlags("opencode", "opencode", []string{"run"}, []string{"--format", "--dir"})
	if check.Status != StatusFail {
		t.Fatalf("status = %s, want %s: %s", check.Status, StatusFail, check.Detail)
	}
	if !strings.Contains(check.Detail, "--dir") {
		t.Fatalf("missing drift detail: %s", check.Detail)
	}
}

func TestContextGraphCheckReportsStats(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("GOV_CONFIG", "")
	fake := filepath.Join(t.TempDir(), "codegraph")
	script := `#!/bin/sh
if [ "$1" = version ]; then
  echo 'codegraph 0.24.0'
  exit 0
fi
if [ "$1" = status ]; then
  printf '%s\n' '{"initialized":true,"fileCount":51,"nodeCount":689,"edgeCount":1579,"dbSizeBytes":1765376,"indexPath":"/tmp/project/.codegraph/codegraph.db"}'
  exit 0
fi
exit 1
`
	if err := os.WriteFile(fake, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_GRAPH_MODE", "required")
	t.Setenv("GOV_GRAPH_PROVIDER", "codegraph")
	t.Setenv("GOV_GRAPH_BIN", fake)

	check := checkContextGraph()
	if check.Status != StatusOK {
		t.Fatalf("status = %s, want %s: %s", check.Status, StatusOK, check.Detail)
	}
	for _, want := range []string{"codegraph 0.24.0", "files=51", "nodes=689", "edges=1579", "db_bytes=1765376"} {
		if !strings.Contains(check.Detail, want) {
			t.Fatalf("detail %q missing %q", check.Detail, want)
		}
	}
}

func TestContextGraphCheckWarnsWhenAutoBinaryMissing(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("GOV_CONFIG", "")
	t.Setenv("GOV_GRAPH_MODE", "auto")
	t.Setenv("GOV_GRAPH_PROVIDER", "codegraph")
	t.Setenv("GOV_GRAPH_BIN", filepath.Join(t.TempDir(), "missing-codegraph"))

	check := checkContextGraph()
	if check.Status != StatusWarn || check.Required {
		t.Fatalf("check = %+v, want optional warning", check)
	}
	if !strings.Contains(check.Detail, "structural context inactive") {
		t.Fatalf("unexpected detail: %s", check.Detail)
	}
}

// TestGovernedRunsCheckWarnsWhenLedgerEmpty pins the doctor advisory added
// 2026-07-06: a clean bill of health from the presence checks above must not
// be read as proof RTK/graph are saving tokens, since neither is exercised
// outside `gov run`'s backend-invocation path. A freshly opened ledger with
// zero runs is exactly the state this repo was in before that date.
func TestGovernedRunsCheckWarnsWhenLedgerEmpty(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("GOV_CONFIG", "")
	t.Setenv("GOV_LEDGER_DIR", home)

	db, err := observability.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()

	check := checkGovernedRuns()
	if check.Status != StatusWarn || check.Required {
		t.Fatalf("check = %+v, want optional warning", check)
	}
	if !strings.Contains(check.Detail, "0 governed runs") {
		t.Fatalf("unexpected detail: %s", check.Detail)
	}
}

// TestGovernedRunsCheckReportsCountWhenPopulated asserts the OK branch once
// the ledger holds at least one real run.
func TestGovernedRunsCheckReportsCountWhenPopulated(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("GOV_CONFIG", "")
	t.Setenv("GOV_LEDGER_DIR", home)

	db, err := observability.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO runs(id, job_id, status, created, total_tokens, usage_available) VALUES (?, ?, ?, ?, ?, ?)`,
		"test-run-1", "test-job", "APPROVED", "2026-07-06T00:00:00Z", 1234, 1)
	db.Close()
	if err != nil {
		t.Fatal(err)
	}

	check := checkGovernedRuns()
	if check.Status != StatusOK {
		t.Fatalf("status = %s, want %s: %s", check.Status, StatusOK, check.Detail)
	}
	if !strings.Contains(check.Detail, "1 run(s)") || !strings.Contains(check.Detail, "1234 total tokens") {
		t.Fatalf("unexpected detail: %s", check.Detail)
	}
}
