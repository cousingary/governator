package runtime

import (
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"sync"
	"testing"
)

var (
	govBinaryOnce sync.Once
	govBinaryPath string
	govBinaryErr  error
)

// govBinary builds the real cmd/gov CLI exactly once per test process and
// returns the path to the resulting executable. Needed by any test that
// exercises a real Session 5 (Sol P0-3) external-enforcement launch: NewPlan
// re-execs os.Executable() as `gov __sandbox_exec`, which only the compiled
// CLI understands -- a test driving RunWithAutoRepair directly runs inside
// the `go test` binary itself, so it must set enforce.SelfExeOverride to
// this path before such a launch, or the re-exec has nothing that
// understands "__sandbox_exec" to hand off to (see internal/redteam's
// identical govBinary helper, which this mirrors).
func govBinary(t *testing.T) string {
	t.Helper()
	govBinaryOnce.Do(func() {
		_, thisFile, _, _ := goruntime.Caller(0)
		repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")
		dir, err := os.MkdirTemp("", "gov-runtime-test-bin")
		if err != nil {
			govBinaryErr = err
			return
		}
		out := filepath.Join(dir, "gov")
		cmd := exec.Command("go", "build", "-o", out, "./cmd/gov")
		cmd.Dir = repoRoot
		if combined, err := cmd.CombinedOutput(); err != nil {
			govBinaryErr = err
			govBinaryPath = string(combined)
			return
		}
		govBinaryPath = out
	})
	if govBinaryErr != nil {
		t.Fatalf("build gov binary: %v: %s", govBinaryErr, govBinaryPath)
	}
	return govBinaryPath
}
