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

	"github.com/cousingary/governator/internal/pathsafe"
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

// resolveRealDir opens path as a directory with O_DIRECTORY|O_NOFOLLOW (so
// a symlinked final component is refused outright) and returns the
// kernel-resolved real path via /proc/self/fd, plus the held descriptor.
// The caller owns closing the descriptor. This is Sol9 P1-3 step 1
// ("resolve the real workspace"): the returned path is guaranteed free of
// symlink components at the instant it was resolved, and the returned
// descriptor lets subsequent lookups beneath it (pathsafe.OpenBeneathFd)
// reuse the same already-verified directory instead of reopening a pathname
// string that could have been swapped in the meantime.
func resolveRealDir(path string) (*os.File, string, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, "", fmt.Errorf("open %q: %w", path, err)
	}
	real, err := pathsafe.RealPath(f)
	if err != nil {
		_ = f.Close()
		return nil, "", err
	}
	return f, real, nil
}

// writeCarveOuts resolves the declared extra write-dir/write-file paths
// (Sol v7 S9: read-only-mode jobs still need to land Produces artifacts and
// RESULT.json) into RWDirs/RWFiles rules, refusing anything that would
// escape the workspace it's meant to carve an exception into -- a caller
// error here must never silently grant write access outside the workspace,
// which would defeat the whole point of an otherwise read-only Plan.
//
// Sol9 P1-3: the prior implementation validated lexical containment
// (filepath.Abs/Rel) and then inspected the declared path with os.Stat,
// which follows symlinks. A declared path lexically inside the workspace
// could be -- or gain a parent that becomes -- a symlink resolving outside
// the workspace, passing the lexical check while escaping in practice.
// Every write root is now resolved beneath the held workspace descriptor
// via pathsafe.OpenBeneathFd (openat2 RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|
// RESOLVE_NO_MAGICLINKS), which validates every path component -- not just
// the final one -- as one atomic kernel operation and refuses any symlink
// anywhere in it. The Landlock rule is built from the kernel-resolved real
// path that open call actually produced, never the caller-declared string.
func writeCarveOuts(workspaceFile *os.File, realWorkspace string, writeDirs, writeFiles []string) ([]landlock.Rule, error) {
	var rules []landlock.Rule
	if len(writeDirs) == 0 && len(writeFiles) == 0 {
		return rules, nil
	}
	if workspaceFile == nil || realWorkspace == "" {
		return nil, fmt.Errorf("write-dir/write-file declared with no workspace to scope it to")
	}
	resolve := func(kind, declared string, wantDir bool) (string, error) {
		absPath, err := filepath.Abs(declared)
		if err != nil {
			return "", fmt.Errorf("resolve %s %q: %w", kind, declared, err)
		}
		rel, err := filepath.Rel(realWorkspace, absPath)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return "", fmt.Errorf("%s %q escapes workspace %q", kind, declared, realWorkspace)
		}
		f, err := pathsafe.OpenBeneathFd(workspaceFile, filepath.ToSlash(rel), os.O_RDONLY, 0)
		if err != nil {
			return "", fmt.Errorf("%s %q must exist beneath workspace %q with no symlink components (pre-create it before launch): %w", kind, declared, realWorkspace, err)
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil {
			return "", fmt.Errorf("stat resolved %s %q: %w", kind, declared, err)
		}
		if wantDir && !info.IsDir() {
			return "", fmt.Errorf("%s %q must already exist as a directory (pre-create it before launch)", kind, declared)
		}
		if !wantDir && (info.IsDir() || !info.Mode().IsRegular()) {
			return "", fmt.Errorf("%s %q must already exist as a regular file (pre-create it before launch)", kind, declared)
		}
		real, err := pathsafe.RealPath(f)
		if err != nil {
			return "", fmt.Errorf("resolve real path of %s %q: %w", kind, declared, err)
		}
		return real, nil
	}
	for _, dir := range writeDirs {
		real, err := resolve("write-dir", dir, true)
		if err != nil {
			return nil, err
		}
		rules = append(rules, landlock.RWDirs(real))
	}
	for _, file := range writeFiles {
		real, err := resolve("write-file", file, false)
		if err != nil {
			return nil, err
		}
		rules = append(rules, landlock.RWFiles(real))
	}
	return rules, nil
}

func applyLandlockRuleset(workspace string, readOnly bool, execPath string, declaredReadRoots, writeDirs, writeFiles []string) error {
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
	//
	// The workspace is resolved through a held O_DIRECTORY|O_NOFOLLOW
	// descriptor exactly once (Sol9 P1-3) and the resulting kernel-resolved
	// real path/descriptor pair is what both the workspace rule itself and
	// every write carve-out below are built from -- never the caller-passed
	// pathname string a second time.
	var workspaceFile *os.File
	realWorkspace := ""
	if workspace != "" {
		var err error
		workspaceFile, realWorkspace, err = resolveRealDir(workspace)
		if err != nil {
			return fmt.Errorf("resolve workspace %q: %w", workspace, err)
		}
		defer workspaceFile.Close()
		if readOnly {
			rules = append(rules, landlock.RODirs(realWorkspace))
		} else {
			rules = append(rules, landlock.RWDirs(realWorkspace))
		}
	}
	if len(writeDirs) > 0 || len(writeFiles) > 0 {
		carveOuts, err := writeCarveOuts(workspaceFile, realWorkspace, writeDirs, writeFiles)
		if err != nil {
			return err
		}
		rules = append(rules, carveOuts...)
	}
	return cfg.RestrictPaths(rules...)
}

func RunSandboxExec(argv []string) int {
	fs := flag.NewFlagSet("__sandbox_exec", flag.ContinueOnError)
	workspace := fs.String("workspace", "", "workspace path Landlock grants write access to")
	readOnly := fs.Bool("readonly", false, "deny writes everywhere, including workspace")
	var readRoots stringListFlag
	fs.Var(&readRoots, "read-root", "exact contract-declared external read path (repeatable)")
	var writeDirs stringListFlag
	fs.Var(&writeDirs, "write-dir", "pre-existing directory beneath workspace granted RW despite --readonly (repeatable)")
	var writeFiles stringListFlag
	fs.Var(&writeFiles, "write-file", "pre-existing file beneath workspace granted RW despite --readonly (repeatable)")
	var roBinds stringListFlag
	fs.Var(&roBinds, "ro-bind", "src=dst read-only bind mount, established before the Landlock ruleset (repeatable)")
	var consumedFDs stringListFlag
	fs.Var(&consumedFDs, "consumed-fd", "fdpath=name sealed consumed-artifact descriptor to project into --consumed-dst (repeatable, Sol11 P0-7)")
	consumedDst := fs.String("consumed-dst", "", "placeholder directory to mount a private read-only tmpfs onto, populated from --consumed-fd entries")
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
	// Sol10 P0-1: establish every read-only bind mount BEFORE the Landlock
	// ruleset is computed and applied. Wrap already unshared a private mount
	// namespace (--mount) for this launch whenever roBinds is non-empty, so
	// these mounts are visible only to this process tree and never leak to
	// the host or outlive it. Each dst becomes a separate mount object --
	// this is what lets the RODirs rule added for it below actually be
	// authoritative despite an ancestor RWDirs(workspace) rule (Landlock
	// rules within one ruleset are purely additive and cannot be narrowed by
	// a nested rule on the SAME filesystem object, but a genuinely different
	// mount is not the same object). Any failure here refuses the launch
	// outright -- never falls through to exec with the artifact still only
	// mode-bit-protected.
	readRootsList := []string(readRoots)
	for _, spec := range roBinds {
		src, dst, ok := strings.Cut(spec, "=")
		if !ok || src == "" || dst == "" {
			fmt.Fprintln(os.Stderr, "enforce: malformed --ro-bind (want src=dst):", spec)
			return 1
		}
		if err := bindMountReadOnly(src, dst); err != nil {
			fmt.Fprintln(os.Stderr, "enforce: read-only bind mount", spec, "failed:", err)
			return 1
		}
		readRootsList = append(readRootsList, dst)
	}
	// Sol11 P0-7: consumed artifacts are projected from sealed memfds into a
	// fresh, private tmpfs at *consumedDst -- never bound from a real host
	// source directory -- established before the Landlock ruleset below,
	// exactly like the ro-binds above.
	if len(consumedFDs) > 0 {
		if *consumedDst == "" {
			fmt.Fprintln(os.Stderr, "enforce: --consumed-fd requires --consumed-dst")
			return 1
		}
		if err := mountConsumedArtifacts(*consumedDst, []string(consumedFDs)); err != nil {
			fmt.Fprintln(os.Stderr, "enforce: project consumed artifacts failed:", err)
			return 1
		}
		readRootsList = append(readRootsList, *consumedDst)
	}
	if err := applyLandlockRuleset(*workspace, *readOnly, rest[0], readRootsList, writeDirs, writeFiles); err != nil {
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
