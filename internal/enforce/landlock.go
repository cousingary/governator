package enforce

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
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
// every process it execs into or forks) to read-only access everywhere
// except workspace, which gets read-write. readOnly additionally strips
// write access from workspace itself, matching agents.SandboxReadOnly.
//
// BestEffort degrades to whatever ABI version this kernel actually supports
// rather than failing outright on an older kernel -- Supported() already
// confirmed ABI>0, so BestEffort here never silently no-ops to "no
// restriction at all," only to "not every V9 refinement is enforced."
func applyLandlockRuleset(workspace string, readOnly bool) error {
	cfg := landlock.V9.BestEffort()
	if readOnly {
		return cfg.RestrictPaths(landlock.RODirs("/"))
	}
	return cfg.RestrictPaths(landlock.RODirs("/"), landlock.RWDirs(workspace))
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
	if err := applyLandlockRuleset(*workspace, *readOnly); err != nil {
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
