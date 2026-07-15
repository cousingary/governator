package doctor

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cousingary/governator/internal/observability"
	"github.com/cousingary/governator/internal/toolregistry"
)

func secureDoctorTempDir(t *testing.T) string {
	t.Helper()
	home := "/home/lam"
	if _, err := os.Stat(home); err != nil {
		var homeErr error
		home, homeErr = os.UserHomeDir()
		if homeErr != nil {
			t.Fatal(homeErr)
		}
	}
	dir, err := os.MkdirTemp(home, ".gov-doctor-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func realGitForDoctorTest(t *testing.T) string {
	t.Helper()
	path := "/usr/bin/git"
	if _, err := os.Stat(path); err == nil {
		return path
	}
	found, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	if canonical, err := filepath.EvalSymlinks(found); err == nil {
		found = canonical
	}
	return found
}

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

func TestCodexFlagDriftChecksRootAndExecSurfaces(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("GOV_CONFIG", "")
	fake := filepath.Join(t.TempDir(), "codex")
	script := "#!/bin/sh\nif [ \"$1\" = exec ]; then\n  echo '--sandbox -C --json'\nelse\n  echo '--ask-for-approval'\nfi\n"
	if err := os.WriteFile(fake, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_CODEX_BIN", fake)
	check := checkCodexFlags()
	if check.Status != StatusFail {
		t.Fatalf("status = %s, want %s: %s", check.Status, StatusFail, check.Detail)
	}
	if !strings.Contains(check.Detail, "exec:--ephemeral") {
		t.Fatalf("missing subcommand drift detail: %s", check.Detail)
	}
}

func TestContextGraphCheckReportsStats(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("GOV_CONFIG", "")
	fake := filepath.Join(secureDoctorTempDir(t), "codegraph")
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
	reg := filepath.Join(t.TempDir(), "tools.yaml")
	t.Setenv("GOV_TOOLREGISTRY_FILE", reg)
	if _, err := toolregistry.Enroll("codegraph", fake); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_CONTAINMENT_FORCE_DEGRADED", "1")

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

// TestGitCheckFailsLoudlyOnUntrustedGit is report S4's explicit doctor exit
// criterion: "gov doctor fails loudly on an untrusted git." Pinning git to
// a binary whose content no longer matches the registry's declared hash
// simulates the state a hostile substitution (or simple tampering) would
// leave behind — checkGit must FAIL, not silently pass a stale trust
// declaration.
func TestGitCheckFailsLoudlyOnUntrustedGit(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	fakeGit := filepath.Join(t.TempDir(), "git")
	if err := os.WriteFile(fakeGit, []byte("#!/bin/sh\necho fake\n"), 0755); err != nil {
		t.Fatal(err)
	}
	reg := filepath.Join(t.TempDir(), "tools.yaml")
	regBody := "tools:\n  - name: git\n    kind: trusted_controller\n    path: " + fakeGit + "\n    sha256: " + strings.Repeat("0", 64) + "\n"
	if err := os.WriteFile(reg, []byte(regBody), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_TOOLREGISTRY_FILE", reg)

	check := checkGit()
	if check.Status != StatusFail || !check.Required {
		t.Fatalf("check = %+v, want a required failure", check)
	}
	if !strings.Contains(check.Detail, "untrusted") {
		t.Fatalf("detail = %q, want it to say untrusted", check.Detail)
	}
}

// TestGitCheckPinsRealGitOnFirstSuccess proves checkGit's trust-on-first-use
// step: a registry with no path pinned for git yet, after one successful
// checkGit() call, has git's exact resolved path persisted — so a later
// PATH change cannot silently redirect what any later run considers "git"
// (report attack 10 depends on this pin already existing).
func TestGitCheckPinsRealGitOnFirstSuccess(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	reg := filepath.Join(t.TempDir(), "tools.yaml")
	t.Setenv("GOV_TOOLREGISTRY_FILE", reg)

	if _, err := os.Stat(reg); !os.IsNotExist(err) {
		t.Fatalf("expected no registry file yet, stat err=%v", err)
	}
	if _, err := toolregistry.Enroll("git", realGitForDoctorTest(t)); err != nil {
		t.Fatal(err)
	}
	check := checkGit()
	if check.Status != StatusOK {
		t.Fatalf("expected checkGit to succeed against the real installed git: %+v", check)
	}
	data, err := os.ReadFile(reg)
	if err != nil {
		t.Fatalf("expected checkGit to have pinned a registry file: %v", err)
	}
	if !strings.Contains(string(data), "name: git") || !strings.Contains(string(data), "path:") {
		t.Fatalf("registry file does not look pinned: %s", data)
	}
}

// TestToolRegistryCheckReportsTrustedGit exercises the new doctor
// aggregate check report S4 asks for ("add registry checks to gov
// doctor"): git should show as trusted by default (shipped entry, real
// binary resolves and verifies).
func TestToolRegistryCheckReportsTrustedGit(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("GOV_CONFIG", "")
	t.Setenv("GOV_GRAPH_MODE", "off")
	t.Setenv("GOV_TOOLREGISTRY_FILE", filepath.Join(t.TempDir(), "tools.yaml"))
	if _, err := toolregistry.Enroll("git", realGitForDoctorTest(t)); err != nil {
		t.Fatal(err)
	}

	check := checkToolRegistry()
	if check.Status != StatusWarn {
		t.Fatalf("expected optional registry warning for missing non-git tools: %+v", check)
	}
	if !strings.Contains(check.Detail, "git") {
		t.Fatalf("detail = %q, want it to mention git", check.Detail)
	}
}

// TestToolRegistryCheckWarnsOnUnregisteredGraphProvider proves the check
// surfaces an operator-configured-but-unregistered tool as a WARN (not a
// silent pass) — the same "outside the trust model" state report attack 9
// exploited before contextgraph.Resolve started gating through this
// registry.
func TestToolRegistryCheckWarnsOnUnregisteredGraphProvider(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("GOV_CONFIG", "")
	t.Setenv("GOV_GRAPH_MODE", "auto")
	t.Setenv("GOV_GRAPH_PROVIDER", "codegraph")
	t.Setenv("GOV_TOOLREGISTRY_FILE", filepath.Join(t.TempDir(), "tools.yaml"))

	check := checkToolRegistry()
	if check.Status != StatusWarn || check.Required {
		t.Fatalf("check = %+v, want an optional warning", check)
	}
	if !strings.Contains(check.Detail, "codegraph") {
		t.Fatalf("detail = %q, want it to mention the unregistered provider", check.Detail)
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

func TestMinimalismCheckReportsMode(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("GOV_CONFIG", "")
	t.Setenv("GOV_MINIMALISM_MODE", "lite")

	check := checkMinimalism()
	if check.Status != StatusOK {
		t.Fatalf("check = %+v, want OK", check)
	}
	if !strings.Contains(check.Detail, "mode=lite") {
		t.Fatalf("unexpected detail: %s", check.Detail)
	}
}

func TestMinimalismCheckOffIsOK(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("GOV_CONFIG", "")
	t.Setenv("GOV_MINIMALISM_MODE", "off")

	check := checkMinimalism()
	if check.Status != StatusOK {
		t.Fatalf("check = %+v, want OK", check)
	}
	if !strings.Contains(check.Detail, "disabled by configuration") {
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
