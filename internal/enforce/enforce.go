// Package enforce is Session 5 (Sol redteam v4, P0-3): externally enforced
// capability attestation. The report's fake Codex behaved perfectly during
// every probe -- right version string, right probe files, conforming
// transcript, "network denied" -- then escaped to the host during the real
// run. Self-report is not proof, and randomized nonces do not fix that: a
// program that knows it is being tested can behave only during the test.
//
// This package is the boundary Governator owns and the backend cannot see or
// negotiate with: Landlock LSM confines filesystem writes to the workspace
// (RunSandboxExec, applied to the exact process that becomes the backend, not
// asked of it), and a network namespace with no configured route removes
// egress at the kernel level rather than relying on the backend's own claim
// that it denied a connection. Only THIS layer -- never a declared capability
// or a probe verdict -- may authorize a high-risk local run; see
// containment.EnforcePolicy and runtime.enforceContainment.
package enforce

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/cousingary/governator/internal/toolregistry"
)

// SandboxExecArg is the hidden gov subcommand name that applies the Landlock
// ruleset to itself and then execs the real backend. It must be intercepted
// before any normal CLI parsing (see cmd/gov/main.go's run()) -- it is never
// a user-facing command and carries no config dependency, matching how a raw
// exec wrapper needs to behave: fast, and unable to be redirected by a
// contract or policy the process it's about to become could influence.
const SandboxExecArg = "__sandbox_exec"

// Plan is the enforcement posture for one governed local launch, resolved
// once (alongside containment.NewScope) and threaded via context to whichever
// executor ends up building the launch command -- the same pattern S2 uses
// for the descendant-owning Scope, so a launch is either fully wrapped by
// both or the run never reached launch at all.
type Plan struct {
	// Active is false for launches that never require external enforcement
	// (non-effectful / non-high-risk contracts, or a Docker runner, which
	// gets its own containment from the container). Wrap is a no-op when
	// Active is false.
	Active bool
	// Workspace is the absolute worktree path Landlock grants write access
	// to; every other path on the filesystem is read-only (or, for
	// ReadOnly, every path including the workspace is read-only).
	Workspace string
	ReadOnly  bool
	// AllowNetwork mirrors agents.BackendSpec.Network. false (the common
	// case) wraps the launch in a network namespace with no configured
	// route, so egress is structurally impossible rather than merely denied
	// by policy the backend could lie about honoring.
	AllowNetwork bool
	// ReadRoots is the pre-resolved exact kernel read envelope. It contains
	// individual executable/loader/library files plus only contract-declared
	// narrow directories; it is never reconstructed inside the sandbox.
	ReadRoots   []string
	LandlockABI int
	// WriteDirs/WriteFiles are pre-existing paths beneath Workspace granted
	// RW despite ReadOnly (Sol v7 S9): a read-only-mode contract still needs
	// to land Produces artifacts and RESULT.json, and Landlock's readOnly
	// ruleset otherwise denies writes everywhere with no carve-out. The
	// caller must create these paths before Wrap's launch -- Landlock binds
	// rules to an opened path, so a not-yet-created artifact directory or
	// RESULT.json can't be granted in advance.
	WriteDirs  []string
	WriteFiles []string
	// ROBinds are read-only bind mounts Wrap establishes inside a private
	// mount namespace before exec'ing the backend (Sol10 P0-1): each Src
	// (a controller-private path outside Workspace, e.g. a consumed-artifact
	// store) is bind-mounted then remounted read-only onto Dst (a
	// pre-created, empty placeholder directory the caller must have created
	// beneath Workspace before Wrap's launch -- mount(2) requires the target
	// to already exist, mirroring WriteDirs/WriteFiles's own "pre-create it
	// before launch" contract). Landlock alone cannot carve a read-only hole
	// out of an otherwise-writable RWDirs(Workspace) rule: rules within one
	// ruleset are purely additive, so a narrower RODirs rule nested under a
	// broader RWDirs ancestor grants nothing back. Making Dst a genuinely
	// separate mount before the Landlock ruleset is applied is what lets the
	// RODirs rule __sandbox_exec adds for it actually be authoritative --
	// Landlock enforcement is mount-aware, so the ancestor Workspace rule's
	// recursive reach stops at the new mount boundary. See RunSandboxExec.
	ROBinds []ROBind

	// ConsumedDst/ConsumedArtifacts project sealed, kernel-write-sealed
	// memfd content directly into a fresh, private tmpfs __sandbox_exec
	// mounts at ConsumedDst (Sol11 P0-7): unlike ROBinds, there is no real
	// host source directory at all -- the retained descriptors in
	// ConsumedArtifacts are the only place the bytes exist prior to
	// projection, so no same-UID process outside this one launch's own
	// private mount namespace ever has a filesystem path to locate and
	// mutate them. ConsumedDst is a pre-created, empty placeholder
	// directory beneath Workspace, exactly like ROBind.Dst.
	ConsumedDst       string
	ConsumedArtifacts []ConsumedArtifactFD

	// selfExe is the string-based launch path used only when selfExeFile is
	// nil: the SelfExeOverride test seam (a real, distinct sealed-copy file,
	// never process-relative) or a non-Linux os.Executable() result. Never
	// populated on production Linux -- see selfExeFile.
	selfExe string
	// selfExeFile is Governator's own running executable, opened in THIS
	// process before any wrapper is composed (Sol v9 P0-1). /proc/self/exe
	// unambiguously names Governator here; the defect was ever handing that
	// PATH STRING to a second process (unshare) to resolve for itself, where
	// "self" becomes unshare, not Governator. Wrap passes this descriptor
	// through as /proc/self/fd/<n> instead, so no second resolution ever
	// happens. nil on non-Linux or when SelfExeOverride is set, in which
	// case selfExe (a real path) is used instead.
	selfExeFile *os.File
	// unsharePath is unshareHandle's canonical path, retained only as a
	// string fallback for Plans built directly by tests (struct literals
	// that never went through NewPlanForExecutable, so unshareHandle is
	// nil). Every Plan NewPlanForExecutable actually constructs sets
	// unshareHandle and launches through it.
	unsharePath string
	// unshareHandle is a sealed, open handle to the trusted-tool registry's
	// verified unshare(1) object (Sol v9 P0-2). NewPlanForExecutable resolves
	// and opens it once; Wrap launches through the held descriptor
	// (/proc/self/fd/<n>), never by reopening unsharePath -- a same-uid
	// replacement of the enrolled unshare binary after resolution can no
	// longer change what actually execs.
	unshareHandle *toolregistry.Handle
}

// Close releases any file descriptors this Plan holds open (the fd-backed
// Governor self-exe and unshare handle Wrap launches through). Safe to call
// on a zero/inactive Plan or one built from a test struct literal that never
// opened either. Callers that obtained a Plan from NewPlan/NewPlanForExecutable
// own it and must close it once the launch it was built for has started
// (mirroring containment.Scope.Started's own primitiveHandle.Close()) --
// holding these open any longer is pure fd leakage, since the child already
// has its own independent descriptors after Start().
func (p *Plan) Close() error {
	var err error
	if p.selfExeFile != nil {
		err = p.selfExeFile.Close()
		p.selfExeFile = nil
	}
	if p.unshareHandle != nil {
		if cerr := p.unshareHandle.Close(); cerr != nil && err == nil {
			err = cerr
		}
		p.unshareHandle = nil
	}
	return err
}

// SelfExeOverride is a test-only seam. NewPlan wraps a launch by re-executing
// THE TRUSTED gov BINARY (os.Executable()) as `gov __sandbox_exec`, so
// Landlock -- applied to that re-exec before it becomes the backend -- is
// enforced by code the caller cannot substitute. In production that is
// exactly right: os.Executable() resolves to the installed, hash-verified
// `gov` a run was actually launched from. Inside `go test`, though,
// os.Executable() resolves to the *test binary* -- tests that exercise
// RunWithAutoRepair directly (never through a compiled cmd/gov) have no
// other process that understands "__sandbox_exec" to re-exec into, so a
// test that needs a real high-risk local launch to actually reach the
// backend must build the real CLI once (see internal/redteam's govBinary
// helper) and point this at it. Never set outside a test.
var SelfExeOverride string

// SelfExeFDOverride is a test-only seam for the mandatory release
// integration tier (rc8-upg15 S3, Sol15 P0-4 part B), distinct from
// SelfExeOverride above. Sol found that SelfExeOverride's route -- open the
// candidate once, copy it into a fresh sealed 0500 file, and pass that copy
// as a literal argv path string -- never exercises the production Linux
// fd-backed /proc/self/exe route: the mandatory suite validated a
// substitute mechanism while claiming to test self-reexecution.
//
// The calling process during the integration tier is a `go test` binary,
// never gov itself, so a literal read of "/proc/self/exe" can never name
// the exact candidate under test -- that seam is genuinely unavoidable (Sol's
// required correction #9: "use an inherited open file descriptor or handle
// for any unavoidable test seam"). SelfExeFDOverride names that candidate's
// path and NewPlanForExecutable resolves it through openExecutableFile --
// the SAME ELF-verifying helper production Linux uses for /proc/self/exe --
// so Wrap threads it through WrapWith's selfExeFile-backed
// /proc/self/fd/<n> argument exactly like production, instead of falling
// back to SelfExeOverride's sealed-copy pathname argument. Takes precedence
// over SelfExeOverride when both are set. Never set outside a test.
var SelfExeFDOverride string

// The SelfExeRoute* constants name which resolution branch
// NewPlanForExecutable actually took, recorded via recordSelfExeRoute and
// readable through LastSelfExeRoute for the mandatory integration tier's
// permanent assertion that fd-backed semantics -- never the pathname-copy
// route -- were exercised (rc8-upg15 S3). Test introspection only; never
// consulted for any policy decision. internal/redteamgate duplicates the
// FDOverride value as its own literal (avoiding an import of this package)
// -- keep the two in sync.
const (
	SelfExeRouteFDProcSelfExe = "fd-proc-self-exe"
	SelfExeRouteFDOverride    = "fd-override"
	SelfExeRoutePathname      = "pathname"
)

var (
	selfExeRouteMu sync.Mutex
	selfExeRoute   string
)

func recordSelfExeRoute(route string) {
	selfExeRouteMu.Lock()
	selfExeRoute = route
	selfExeRouteMu.Unlock()
}

// LastSelfExeRoute reports which route (see the SelfExeRoute* constants) the
// most recent NewPlanForExecutable call took. Test introspection only.
func LastSelfExeRoute() string {
	selfExeRouteMu.Lock()
	defer selfExeRouteMu.Unlock()
	return selfExeRoute
}

// selfExePath is the string-based fallback used only for the
// SelfExeOverride test seam and non-Linux hosts. It must never be called for
// the production Linux path -- see openSelfExecutable, which that path uses
// instead specifically because a string here would have to be re-resolved
// by whatever process reads it next (the P0-1 defect: unshare resolving
// "/proc/self/exe" for itself, not for Governator).
func selfExePath() (string, error) {
	if SelfExeOverride != "" {
		return sealedExecutableCopy(SelfExeOverride, "governator-self-exec-*")
	}
	return os.Executable()
}

// openExecutableFile opens path (verifying it is an ELF binary on Linux,
// mirroring sealedExecutableCopy's own magic check) and rewinds it, ready to
// be threaded through Wrap as an inherited /proc/self/fd/<n> descriptor.
// openSelfExecutable and SelfExeFDOverride's resolution both share this one
// implementation, so "fd-backed" always means the exact same open+verify+
// rewind sequence regardless of which path named the executable.
func openExecutableFile(path string) (*os.File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open executable for fd-backed self-exec: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
		}
	}()
	var magic [4]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil {
		return nil, fmt.Errorf("read executable magic for fd-backed self-exec: %w", err)
	}
	if magic != [4]byte{0x7f, 'E', 'L', 'F'} {
		return nil, fmt.Errorf("fd-backed self-exec target is not an ELF binary")
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("rewind executable for fd-backed self-exec: %w", err)
	}
	ok = true
	return f, nil
}

// openSelfExecutable opens Governator's own running executable in THIS
// process, before any wrapper is composed (Sol v9 P0-1's required
// correction). Opened here, "/proc/self/exe" is unambiguous: self is
// Governator. The returned descriptor is what Wrap threads through the
// launch chain as /proc/self/fd/<n> -- never a path string a wrapper
// process would resolve for itself.
func openSelfExecutable() (*os.File, error) {
	return openExecutableFile("/proc/self/exe")
}

func sealedExecutableCopy(src, pattern string) (string, error) {
	in, err := os.Open(src)
	if err != nil {
		return "", fmt.Errorf("open executable for sealed copy: %w", err)
	}
	defer in.Close()
	if runtime.GOOS == "linux" {
		var magic [4]byte
		if _, err := io.ReadFull(in, magic[:]); err != nil {
			return "", fmt.Errorf("read executable magic for sealed copy: %w", err)
		}
		if magic != [4]byte{0x7f, 'E', 'L', 'F'} {
			return "", fmt.Errorf("sealed gov executable is not an ELF binary")
		}
		if _, err := in.Seek(0, io.SeekStart); err != nil {
			return "", fmt.Errorf("rewind executable for sealed copy: %w", err)
		}
	}
	dir, err := os.MkdirTemp("", pattern)
	if err != nil {
		return "", fmt.Errorf("create sealed exec dir: %w", err)
	}
	outPath := filepath.Join(dir, "gov")
	out, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0500)
	if err != nil {
		_ = os.RemoveAll(dir)
		return "", fmt.Errorf("create sealed exec copy: %w", err)
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil {
		_ = os.RemoveAll(dir)
		return "", fmt.Errorf("copy sealed exec: %w", copyErr)
	}
	if closeErr != nil {
		_ = os.RemoveAll(dir)
		return "", fmt.Errorf("close sealed exec: %w", closeErr)
	}
	if err := os.Chmod(outPath, 0500); err != nil {
		_ = os.RemoveAll(dir)
		return "", fmt.Errorf("chmod sealed exec copy: %w", err)
	}
	if err := os.Chmod(dir, 0500); err != nil {
		_ = os.RemoveAll(dir)
		return "", fmt.Errorf("chmod sealed exec dir: %w", err)
	}
	return outPath, nil
}

// ForceUnsupported is a test-only seam: Supported() has no meaningful way to
// be mocked (it probes live kernel/host state), so tests that need to
// exercise the "this host cannot actually provide external enforcement, a
// high-risk run must refuse" fail-closed path set this true for the
// duration of the test rather than faking a whole hostile host. Never set
// outside a test.
var ForceUnsupported bool

// Supported reports whether this host can actually provide external
// enforcement: a usable Landlock ABI (kernel support, not merely the
// go-landlock import) and the unshare(1) binary for network-namespace
// wrapping. Mirrors containment.NewScope's "no primitive, high-risk must
// refuse" posture -- see NewPlan.
func Supported() bool {
	if ForceUnsupported {
		return false
	}
	if !landlockUsable() {
		return false
	}
	_, err := toolregistry.ResolveTrusted("unshare", "unshare")
	return err == nil
}

// NewPlan resolves an enforcement Plan for one run. highRisk mirrors S2's
// NewScope: when true and this host cannot actually provide external
// enforcement, NewPlan refuses outright rather than silently producing an
// inactive Plan that would let a high-risk contract launch unconfined.
// active is the caller's own "does this contract require external
// enforcement at all" decision (containment.RequiresHostContainment) --
// NewPlan performs no policy evaluation of its own.
func NewPlan(active bool, workspace string, readOnly, allowNetwork, highRisk bool) (Plan, error) {
	return NewPlanForExecutable(active, workspace, readOnly, allowNetwork, highRisk, "", nil)
}

// NewPlanForExecutable freezes the exact read closure before launch. The
// sandbox consumes these resolved paths rather than discovering host state.
func NewPlanForExecutable(active bool, workspace string, readOnly, allowNetwork, highRisk bool, executable string, declaredReadRoots []string) (Plan, error) {
	if !active {
		return Plan{}, nil
	}
	if !Supported() {
		if highRisk {
			return Plan{}, fmt.Errorf("enforce: no externally enforced sandbox available on this host (Landlock LSM + unshare required); refusing high-risk local run rather than trusting the backend's own self-reported containment")
		}
		return Plan{}, nil
	}
	// Resolved again here (Supported() above already resolved it once to
	// answer "does unshare exist and verify") rather than reusing that
	// result: this is the trust decision that actually gets bound into the
	// Plan and later executed by Wrap, so it gets its own fresh, fully
	// fail-closed resolution rather than trusting an earlier boolean. Held
	// as an open handle (Sol v9 P0-2), not just a verified path string: the
	// old code stored unshareIdentity.CanonicalPath and let Wrap reopen it
	// by name, leaving a same-uid TOCTOU window between this resolution and
	// the actual exec.
	registry, err := toolregistry.Load()
	if err != nil {
		return Plan{}, fmt.Errorf("enforce: load trusted-tool registry: %w", err)
	}
	unshareHandle, err := registry.ResolveHandle("unshare", "unshare", toolregistry.KindTrustedController)
	if err != nil {
		return Plan{}, fmt.Errorf("enforce: resolve trusted unshare handle: %w", err)
	}
	closeOnErr := true
	defer func() {
		if closeOnErr {
			_ = unshareHandle.Close()
		}
	}()

	// selfExeFile (production Linux, SelfExeOverride unset) is the fd-backed
	// fix for P0-1; selfExe (everything else) is the pre-existing
	// string-based path, unchanged. See openSelfExecutable's doc comment.
	// SelfExeFDOverride (rc8-upg15 S3, P0-4 B) takes precedence over both: it
	// is the mandatory integration tier's fd-backed substitute for a true
	// /proc/self/exe read, which can never name the candidate under test
	// since the calling process is a go test binary, not gov itself.
	var self string
	var selfFile *os.File
	var route string
	switch {
	case SelfExeFDOverride != "":
		selfFile, err = openExecutableFile(SelfExeFDOverride)
		route = SelfExeRouteFDOverride
	case runtime.GOOS == "linux" && SelfExeOverride == "":
		selfFile, err = openSelfExecutable()
		route = SelfExeRouteFDProcSelfExe
	default:
		self, err = selfExePath()
		route = SelfExeRoutePathname
	}
	if err != nil {
		return Plan{}, fmt.Errorf("enforce: resolve gov executable for sandbox wrapper: %w", err)
	}
	recordSelfExeRoute(route)
	if selfFile != nil {
		defer func() {
			if closeOnErr {
				_ = selfFile.Close()
			}
		}()
	}

	readRoots, err := exactReadClosure(executable, declaredReadRoots)
	if err != nil {
		return Plan{}, fmt.Errorf("enforce: construct exact read closure: %w", err)
	}
	abi, err := activeLandlockABI()
	if err != nil || abi < RequiredLandlockABI {
		return Plan{}, fmt.Errorf("enforce: required Landlock ABI %d unavailable (active=%d): %v", RequiredLandlockABI, abi, err)
	}
	abs := workspace
	if !readOnly && workspace != "" {
		if a, aerr := filepath.Abs(workspace); aerr == nil {
			abs = a
		}
	}
	closeOnErr = false
	return Plan{
		Active:        true,
		Workspace:     abs,
		ReadOnly:      readOnly,
		AllowNetwork:  allowNetwork,
		ReadRoots:     readRoots,
		LandlockABI:   abi,
		selfExe:       self,
		selfExeFile:   selfFile,
		unsharePath:   unshareHandle.Identity.CanonicalPath,
		unshareHandle: unshareHandle,
	}, nil
}

// ExecutableReadClosure resolves executable's own file plus its ELF runtime
// dependencies (dynamic loader + shared libraries, when it is an ELF
// binary) into the same exact-file list exactReadClosure computes
// internally for a Plan's primary executable. Exported so a contract or
// fixture that needs a SECOND executable readable under the sandbox --
// most commonly a script's own interpreter, since exactReadClosure's own
// doc comment already requires "non-ELF executables (scripts) must declare
// their interpreter ... through ReadRoots" -- can compute that interpreter's
// full closure instead of hand-enumerating its shared libraries.
func ExecutableReadClosure(executable string) ([]string, error) {
	return exactReadClosure(executable, nil)
}

func (p Plan) WithReadRoots(roots ...string) (Plan, error) {
	return p.WithExecutableAndReadRoots("", roots...)
}

// WithExecutableAndReadRoots extends an active plan for a distinct stage
// executable, deriving that executable's complete ELF runtime closure rather
// than treating only the executable object as a declared file.
func (p Plan) WithExecutableAndReadRoots(executable string, roots ...string) (Plan, error) {
	if !p.Active {
		return p, nil
	}
	closure, err := exactReadClosure(executable, append(append([]string(nil), p.ReadRoots...), roots...))
	if err != nil {
		return Plan{}, err
	}
	p.ReadRoots = closure
	return p, nil
}

// WithWriteRoots grants RW on pre-existing dirs/files beneath Workspace even
// when ReadOnly is set (Sol v7 S9). The caller must have already created
// every path (Landlock binds rules to an opened path, so a not-yet-created
// artifact directory or RESULT.json can't be granted in advance).
func (p Plan) WithWriteRoots(dirs, files []string) Plan {
	if !p.Active {
		return p
	}
	p.WriteDirs = append(append([]string(nil), p.WriteDirs...), dirs...)
	p.WriteFiles = append(append([]string(nil), p.WriteFiles...), files...)
	return p
}

// ROBind is one read-only bind mount Wrap establishes before exec'ing the
// backend. Src is a controller-private absolute path (never inside
// Workspace); Dst is the pre-created, empty placeholder directory beneath
// Workspace the backend will see it at.
type ROBind struct {
	Src string
	Dst string
}

// WithReadOnlyBinds adds read-only bind-mount requirements for this launch
// (Sol10 P0-1). Each Dst must already exist as an empty directory beneath
// Workspace before Wrap's launch starts -- see ROBind's doc comment and
// RunSandboxExec, which performs the actual mount(2) calls from inside the
// namespace, before applying the Landlock ruleset.
func (p Plan) WithReadOnlyBinds(binds ...ROBind) Plan {
	if !p.Active || len(binds) == 0 {
		return p
	}
	p.ROBinds = append(append([]ROBind(nil), p.ROBinds...), binds...)
	return p
}

// ConsumedArtifactFD is one named consumed artifact's sealed, unlinked memfd
// content (runtime.sealConsumedArtifacts), threaded through Wrap/WrapWith
// exactly like selfExeFile/unshareHandle/binFile: the retained descriptor,
// never a real host directory path, is what __sandbox_exec inherits and
// projects into a fresh, private tmpfs at Plan.ConsumedDst.
type ConsumedArtifactFD struct {
	Name string
	File *os.File
}

// WithConsumedArtifacts requires a fresh, private, read-only tmpfs be
// mounted directly at dst (a pre-created, empty placeholder directory
// beneath Workspace, mirroring ROBind.Dst's contract) and populated from
// files' sealed memfd content, inside the private mount namespace Wrap
// unshares for this launch (Sol11 P0-7). Unlike WithReadOnlyBinds, dst is
// never bound from a real host source path: the bytes exist only as
// kernel-write-sealed, unlinked memfd objects the caller retains, so no
// same-UID process -- inside or outside this launch's own fresh namespace --
// ever has a filesystem path to the content at all.
func (p Plan) WithConsumedArtifacts(dst string, files []ConsumedArtifactFD) Plan {
	if !p.Active || dst == "" || len(files) == 0 {
		return p
	}
	p.ConsumedDst = dst
	p.ConsumedArtifacts = append([]ConsumedArtifactFD(nil), files...)
	return p
}

// Wrap rewrites bin/args so the process that actually starts is already
// confined: Landlock is applied to it before it execs into bin (see
// RunSandboxExec), and -- unless the run is permitted network access -- the
// whole thing runs inside a network namespace with no configured route.
//
// Wrap's return values are (bin, args, extraFiles): the caller must build
// its *exec.Cmd from bin/args as before AND set cmd.ExtraFiles = extraFiles
// (appending, never replacing, if the caller's own scope wrapper already
// populated some) before Start -- extraFiles holds the open descriptors
// bin/args reference as /proc/self/fd/<n>, and Start dup's them into the
// child at the deterministic fd numbers Wrap assigned. A no-op/inactive
// Plan returns bin/args unchanged and a nil extraFiles.
func (p Plan) Wrap(bin string, args []string) (string, []string, []*os.File) {
	alloc := &toolregistry.FDAllocator{}
	wb, wa := p.WrapWith(alloc, bin, nil, args)
	return wb, wa, alloc.Files()
}

// WrapWith is Wrap's composable form (Sol11 P0-5): a caller that must
// combine this Plan's own descriptor-backed layers (Governator's self-exec,
// unshare) with ANOTHER descriptor-backed layer of its own -- most
// concretely containment.Scope's own primitive launcher (systemd-run/
// unshare-for-containment, via Scope.CommandWith), or the final stage
// executable itself -- passes one shared alloc so every layer's
// /proc/self/fd/<n> argv string lands at the fd number Start will actually
// dup it to, instead of two independently-numbered ExtraFiles lists
// colliding at fd 3 (the composition hazard containment.Scope's own Command
// doc comment describes, which is why Command still falls back to a sealed
// pathname copy for its primitive when no shared allocator is available).
//
// binFile, when non-nil, is the final stage executable's own held,
// already-verified descriptor (toolregistry.Handle.File()): it is fd-arged
// through alloc exactly like selfExeFile/unshareHandle, so the final exec
// never reopens a same-uid-mutable pathname after that executable's own
// verification. bin is used unchanged, as a literal argv string, only when
// binFile is nil (legacy string-path callers, and Wrap itself).
//
// The caller must set exec.Cmd.ExtraFiles = alloc.Files() itself once every
// layer it composes -- including any registered after WrapWith returns,
// such as Scope.CommandWith's own primitive descriptor -- has finished
// registering.
func (p Plan) WrapWith(alloc *toolregistry.FDAllocator, bin string, binFile *os.File, args []string) (string, []string) {
	if !p.Active {
		return bin, args
	}

	execArg := bin
	if binFile != nil {
		execArg = alloc.Arg(binFile)
	}

	// selfArg is Governator's own re-exec target. selfExeFile (set by
	// NewPlanForExecutable on production Linux) is threaded through as an
	// inherited descriptor -- Sol v9 P0-1's required correction: a plain
	// path string here would be re-resolved by whichever process reads it
	// next, and after unshare that process is unshare itself, not
	// Governator. selfExe (a real, distinct path -- SelfExeOverride's
	// sealed test copy, or os.Executable() off Linux) is used unchanged
	// when there is no descriptor to pass.
	selfArg := p.selfExe
	if p.selfExeFile != nil {
		selfArg = alloc.Arg(p.selfExeFile)
	}

	inner := []string{selfArg, SandboxExecArg, "--workspace", p.Workspace}
	if p.ReadOnly {
		inner = append(inner, "--readonly")
	}
	for _, root := range p.ReadRoots {
		inner = append(inner, "--read-root", root)
	}
	for _, dir := range p.WriteDirs {
		inner = append(inner, "--write-dir", dir)
	}
	for _, file := range p.WriteFiles {
		inner = append(inner, "--write-file", file)
	}
	for _, b := range p.ROBinds {
		inner = append(inner, "--ro-bind", b.Src+"="+b.Dst)
	}
	for _, cf := range p.ConsumedArtifacts {
		// Sol11 P0-7: cf.File is a sealed, unlinked memfd -- alloc.Arg
		// threads it through the same inherited-descriptor mechanism as
		// selfExeFile/unshareHandle above, so __sandbox_exec receives
		// /proc/self/fd/<n> referencing its OWN inherited copy, never a real
		// host pathname another same-UID process could locate.
		fdArg := alloc.Arg(cf.File)
		inner = append(inner, "--consumed-fd", fdArg+"="+cf.Name)
	}
	if p.ConsumedDst != "" {
		inner = append(inner, "--consumed-dst", p.ConsumedDst)
	}
	inner = append(inner, "--")
	inner = append(inner, execArg)
	inner = append(inner, args...)
	// Sol10 P0-1: a read-only bind mount needs a private mount namespace
	// regardless of network policy, so AllowNetwork alone no longer decides
	// whether this launch goes through unshare -- it only decides whether
	// --net (no configured route) is one of the namespaces unshared. Sol11
	// P0-7's consumed-artifact tmpfs projection needs the same private mount
	// namespace, so it joins ROBinds in that decision.
	if p.AllowNetwork && len(p.ROBinds) == 0 && p.ConsumedDst == "" {
		return inner[0], inner[1:]
	}
	// No configured route inside the namespace means every connect()/bind()
	// past loopback fails at the kernel level -- this is not a policy the
	// backend can be asked to honor, it structurally cannot reach anywhere.
	// The launch chain is: verified unshare object -> verified Governator
	// object -> __sandbox_exec -> verified stage executable (Sol v9
	// P0-1/P0-2). unshareHandle (set by NewPlanForExecutable) is threaded
	// through the same fd-argv mechanism as selfExeFile above, never
	// reopened by unsharePath's string -- a same-uid replacement of the
	// enrolled unshare binary after resolution can no longer change what
	// launches. unsharePath itself remains only for Plans built directly by
	// tests as struct literals, which never populate unshareHandle.
	unshareArg := p.unsharePath
	if p.unshareHandle != nil {
		unshareArg = alloc.Arg(p.unshareHandle.File())
	}
	nsFlags := []string{}
	if !p.AllowNetwork {
		nsFlags = append(nsFlags, "--net")
	}
	nsFlags = append(nsFlags, "--map-root-user")
	if len(p.ROBinds) > 0 || p.ConsumedDst != "" {
		// --mount: a private mount namespace so the ro-bind(s)/consumed-
		// artifact tmpfs __sandbox_exec establishes below never leak to the
		// host or outlive this launch.
		nsFlags = append(nsFlags, "--mount")
	}
	full := append(append(nsFlags, "--"), inner...)
	return unshareArg, full
}

type planContextKey struct{}

// WithPlan attaches p to ctx for the launch site (agents.defaultExecutor,
// several packages away from whoever resolved the Plan) to retrieve via
// PlanFromContext, mirroring containment.WithScope/ScopeFromContext.
func WithPlan(ctx context.Context, p Plan) context.Context {
	return context.WithValue(ctx, planContextKey{}, p)
}

// PlanFromContext retrieves a Plan attached by WithPlan. ok is false for any
// launch that never went through enforceContainment (doctor probes, direct
// adapter tests) -- callers treat that identically to an inactive Plan.
func PlanFromContext(ctx context.Context) (Plan, bool) {
	p, ok := ctx.Value(planContextKey{}).(Plan)
	return p, ok
}
