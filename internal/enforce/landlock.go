package enforce

import (
	"debug/elf"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/landlock-lsm/go-landlock/landlock"
	llsyscall "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

// RequiredLandlockABI is the minimum ABI that enforces the complete filesystem
// policy Governator relies on: ABI 2 adds cross-directory refer and ABI 3 adds
// truncate. Running V9 in BestEffort mode on an older kernel would silently
// omit rights, so high-authority local execution instead requires this floor.
const RequiredLandlockABI = 3

func activeLandlockABI() (int, error) {
	v, err := llsyscall.LandlockGetABIVersion()
	if err != nil {
		return 0, err
	}
	return v, nil
}

func landlockUsable() bool {
	v, err := activeLandlockABI()
	return err == nil && v >= RequiredLandlockABI
}

var forbiddenBroadReadRoots = map[string]bool{
	"/": true, "/bin": true, "/usr": true, "/usr/local": true,
	"/lib": true, "/lib64": true, "/etc": true, "/dev": true, "/proc": true,
}

// exactReadClosure resolves the executable object and its ELF loader/shared
// libraries into file rules. Directories are admitted only when explicitly
// declared by the contract; implicit host-wide runtime directories are never
// granted. Non-ELF executables (scripts) must declare their interpreter and
// script through ReadRoots.
func exactReadClosure(execPath string, declared []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	add := func(path string, explicit bool) error {
		if strings.TrimSpace(path) == "" {
			return nil
		}
		abs, err := filepath.Abs(path)
		if err != nil {
			return fmt.Errorf("resolve read root %q: %w", path, err)
		}
		abs = filepath.Clean(abs)
		if forbiddenBroadReadRoots[abs] {
			return fmt.Errorf("broad read root %q is forbidden; declare exact files or a narrower application directory", abs)
		}
		resolved, err := filepath.EvalSymlinks(abs)
		if err != nil {
			return fmt.Errorf("resolve read root %q: %w", abs, err)
		}
		if !explicit {
			info, err := os.Stat(resolved)
			if err != nil {
				return err
			}
			if info.IsDir() {
				return fmt.Errorf("implicit runtime read root %q is not an exact file", resolved)
			}
		}
		if !seen[resolved] {
			seen[resolved] = true
			out = append(out, resolved)
		}
		return nil
	}
	for _, root := range declared {
		if err := add(root, true); err != nil {
			return nil, err
		}
	}
	if execPath != "" && execPath != "/proc/self/fd/3" {
		if err := add(execPath, false); err != nil {
			return nil, err
		}
		resolved, _ := filepath.EvalSymlinks(execPath)
		deps, err := elfRuntimeClosure(resolved)
		if err != nil {
			return nil, err
		}
		for _, dep := range deps {
			if err := add(dep, false); err != nil {
				return nil, err
			}
		}
	}
	// Minimal device surface. Missing devices are omitted rather than widening
	// to /dev; callers that need another device must declare that exact node.
	for _, dev := range []string{"/dev/null", "/dev/urandom"} {
		if _, err := os.Stat(dev); err == nil {
			if err := add(dev, false); err != nil {
				return nil, err
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

func elfRuntimeClosure(path string) ([]string, error) {
	seen := map[string]bool{}
	queue := []string{path}
	var out []string
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		deps, err := elfRuntimeFiles(current)
		if err != nil {
			return nil, err
		}
		for _, dep := range deps {
			resolved, err := filepath.EvalSymlinks(dep)
			if err != nil {
				return nil, err
			}
			if seen[resolved] {
				continue
			}
			seen[resolved] = true
			out = append(out, resolved)
			queue = append(queue, resolved)
		}
	}
	return out, nil
}

func elfRuntimeFiles(path string) ([]string, error) {
	f, err := elf.Open(path)
	if err != nil {
		// Scripts and statically opaque formats have no ELF closure. Their
		// interpreters/runtime files must be contract-declared.
		return nil, nil
	}
	defer f.Close()
	var out []string
	for _, prog := range f.Progs {
		if prog.Type != elf.PT_INTERP {
			continue
		}
		b := make([]byte, prog.Filesz)
		if _, err := prog.ReadAt(b, 0); err != nil {
			return nil, fmt.Errorf("read ELF interpreter for %q: %w", path, err)
		}
		interp := strings.TrimRight(string(b), "\x00")
		if interp != "" {
			out = append(out, interp)
		}
	}
	libs, err := f.ImportedLibraries()
	if err != nil {
		return nil, fmt.Errorf("read ELF dependencies for %q: %w", path, err)
	}
	machineDirs := []string{"/lib", "/usr/lib", "/lib64", "/usr/lib64"}
	switch f.Machine {
	case elf.EM_X86_64:
		machineDirs = append([]string{"/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu"}, machineDirs...)
	case elf.EM_AARCH64:
		machineDirs = append([]string{"/lib/aarch64-linux-gnu", "/usr/lib/aarch64-linux-gnu"}, machineDirs...)
	}
	for _, lib := range libs {
		found := ""
		for _, dir := range machineDirs {
			candidate := filepath.Join(dir, lib)
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				found = candidate
				break
			}
		}
		if found == "" {
			return nil, fmt.Errorf("resolve exact ELF dependency %q for %q", lib, path)
		}
		out = append(out, found)
	}
	return out, nil
}

func applyLandlockRuleset(workspace string, readOnly bool, execPath string, declaredReadRoots []string) error {
	abi, err := activeLandlockABI()
	if err != nil {
		return fmt.Errorf("query Landlock ABI: %w", err)
	}
	if abi < RequiredLandlockABI {
		return fmt.Errorf("Landlock ABI %d cannot enforce required ABI %d filesystem rights", abi, RequiredLandlockABI)
	}
	closure, err := exactReadClosure(execPath, declaredReadRoots)
	if err != nil {
		return err
	}
	// V3 without BestEffort is deliberate: RestrictPaths fails if the kernel
	// cannot enforce every filesystem access right this policy claims.
	cfg := landlock.V3
	rules := make([]landlock.Rule, 0, len(closure)+1)
	for _, path := range closure {
		info, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("stat read root %q: %w", path, err)
		}
		if info.IsDir() {
			rules = append(rules, landlock.RODirs(path))
		} else if path == "/dev/null" {
			// Runtime stdio commonly opens the null device for output. Grant
			// this exact device node, never its parent directory.
			rules = append(rules, landlock.RWFiles(path))
		} else {
			rules = append(rules, landlock.ROFiles(path))
		}
	}
	// An empty workspace is only valid in readOnly mode -- it means "no
	// additional writable/readable root beyond the declared closure above,"
	// not "grant rights to the empty path" (RunSandboxExec's own flag check
	// enforces the analogous non-readOnly requirement below).
	if workspace != "" {
		if readOnly {
			rules = append(rules, landlock.RODirs(workspace))
		} else {
			rules = append(rules, landlock.RWDirs(workspace))
		}
	}
	return cfg.RestrictPaths(rules...)
}

func RunSandboxExec(argv []string) int {
	fs := flag.NewFlagSet("__sandbox_exec", flag.ContinueOnError)
	workspace := fs.String("workspace", "", "workspace path Landlock grants write access to")
	readOnly := fs.Bool("readonly", false, "deny writes everywhere, including workspace")
	var readRoots stringListFlag
	fs.Var(&readRoots, "read-root", "exact contract-declared external read path (repeatable)")
	if err := fs.Parse(argv); err != nil {
		fmt.Fprintln(os.Stderr, "enforce: parse sandbox-exec args:", err)
		return 2
	}
	rest := fs.Args()
	// A workspace is only required when granting write access somewhere --
	// a readOnly stage (Sol redteam v7 S1: assay.go's Evaluate,
	// contextgraph.go's Version) may legitimately have no writable/extra
	// root at all beyond its declared read closure.
	if (!*readOnly && *workspace == "") || len(rest) == 0 {
		fmt.Fprintln(os.Stderr, "enforce: sandbox-exec requires --workspace and -- <bin> [args...]")
		return 2
	}
	if err := applyLandlockRuleset(*workspace, *readOnly, rest[0], readRoots); err != nil {
		fmt.Fprintln(os.Stderr, "enforce: apply landlock ruleset:", err)
		return 1
	}
	if err := syscall.Exec(rest[0], rest, os.Environ()); err != nil {
		fmt.Fprintln(os.Stderr, "enforce: exec sandboxed executable:", err)
		return 1
	}
	return 0
}

type stringListFlag []string

func (f *stringListFlag) String() string         { return strings.Join(*f, ",") }
func (f *stringListFlag) Set(value string) error { *f = append(*f, value); return nil }
