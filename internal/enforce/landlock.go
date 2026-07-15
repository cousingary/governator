package enforce

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"github.com/landlock-lsm/go-landlock/landlock"
	llsyscall "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

// landlockUsable probes the kernel directly (LANDLOCK_CREATE_RULESET's
// version query, not merely "the go-landlock import compiled") so Supported
// reflects what THIS host's kernel will actually enforce rather than what a
// linked library merely claims to support.
func landlockUsable() bool {
	v, err := llsyscall.LandlockGetABIVersion()
	return err == nil && v > 0
}

// applyLandlockRuleset restricts the CALLING process (and, because Landlock
// rules are inherited across execve and cannot be dropped by a descendant,
// every process it execs into or forks) to a deny-by-default read envelope:
// the workspace, the verified backend executable location, runtime loader and
// shared-library directories, and minimal /dev + /proc. It intentionally does
// not grant read-only access to /, because that permits undeclared host-secret
// reads (Sol v6 S7 / P0-13).
func applyLandlockRuleset(workspace string, readOnly bool, execPath string) error {
	cfg := landlock.V9.BestEffort()
	ro := []landlock.Rule{
		landlock.RODirs("/bin").IgnoreIfMissing(),
		landlock.RODirs("/usr").IgnoreIfMissing(),
		landlock.RODirs("/lib").IgnoreIfMissing(),
		landlock.RODirs("/lib64").IgnoreIfMissing(),
		landlock.RODirs("/etc").IgnoreIfMissing(),
		landlock.RODirs("/dev").IgnoreIfMissing(),
		landlock.RODirs("/proc").IgnoreIfMissing(),
	}
	if execPath != "" {
		if abs, err := filepath.Abs(execPath); err == nil {
			ro = append(ro, landlock.RODirs(filepath.Dir(abs)).IgnoreIfMissing())
		}
	}
	if readOnly {
		ro = append(ro, landlock.RODirs(workspace).IgnoreIfMissing())
		return cfg.RestrictPaths(ro...)
	}
	rules := append([]landlock.Rule{}, ro...)
	rules = append(rules, landlock.RWDirs(workspace))
	return cfg.RestrictPaths(rules...)
}

// RunSandboxExec is the entry point for the hidden `gov __sandbox_exec`
// subcommand (see cmd/gov/main.go's run(), which intercepts SandboxExecArg
// before any normal CLI dispatch). It applies the Landlock ruleset to
// itself, then replaces its own process image with the real backend via
// execve -- the restriction survives that exec, so the process the caller
// (Plan.Wrap's launch chain) actually observes running IS the confined one,
// not a wrapper sitting in front of an unconfined child.
//
// argv is os.Args[1:] with the "__sandbox_exec" token already stripped:
// --workspace <path> [--readonly] -- <bin> [args...]
func RunSandboxExec(argv []string) int {
	fs := flag.NewFlagSet("__sandbox_exec", flag.ContinueOnError)
	workspace := fs.String("workspace", "", "workspace path Landlock grants write access to")
	readOnly := fs.Bool("readonly", false, "deny writes everywhere, including workspace")
	if err := fs.Parse(argv); err != nil {
		fmt.Fprintln(os.Stderr, "enforce: parse sandbox-exec args:", err)
		return 2
	}
	rest := fs.Args()
	if *workspace == "" || len(rest) == 0 {
		fmt.Fprintln(os.Stderr, "enforce: sandbox-exec requires --workspace and -- <bin> [args...]")
		return 2
	}
	if err := applyLandlockRuleset(*workspace, *readOnly, rest[0]); err != nil {
		fmt.Fprintln(os.Stderr, "enforce: apply landlock ruleset:", err)
		return 1
	}
	bin := rest[0]
	path := bin
	if _, err := os.Stat(bin); err != nil {
		resolved, lerr := exec.LookPath(bin)
		if lerr != nil {
			fmt.Fprintln(os.Stderr, "enforce: resolve sandboxed executable:", lerr)
			return 1
		}
		path = resolved
	}
	if err := syscall.Exec(path, rest, os.Environ()); err != nil {
		fmt.Fprintln(os.Stderr, "enforce: exec sandboxed executable:", err)
		return 1
	}
	return 0 // unreachable: syscall.Exec only returns on error
}
