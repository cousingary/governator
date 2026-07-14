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
	"os"
	"path/filepath"

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

	selfExe string
	// unsharePath is the trusted-tool registry's verified canonical path to
	// unshare(1), resolved once at NewPlan time and bound into this Plan so
	// Wrap never falls back to a bare "unshare" argv0 that os/exec would
	// resolve via ambient PATH (Session 2, post-v4 hardening plan item C).
	unsharePath string
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

func selfExePath() (string, error) {
	if SelfExeOverride != "" {
		return SelfExeOverride, nil
	}
	return os.Executable()
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
	if !active {
		return Plan{}, nil
	}
	if !Supported() {
		if highRisk {
			return Plan{}, fmt.Errorf("enforce: no externally enforced sandbox available on this host (Landlock LSM + unshare required); refusing high-risk local run rather than trusting the backend's own self-reported containment")
		}
		return Plan{}, nil
	}
	self, err := selfExePath()
	if err != nil {
		return Plan{}, fmt.Errorf("enforce: resolve gov executable for sandbox wrapper: %w", err)
	}
	// Resolved again here (Supported() above already resolved it once to
	// answer "does unshare exist and verify") rather than reusing that
	// result: this is the trust decision that actually gets bound into the
	// Plan and later executed by Wrap, so it gets its own fresh, fully
	// fail-closed resolution rather than trusting an earlier boolean.
	unshareIdentity, err := toolregistry.ResolveTrusted("unshare", "unshare")
	if err != nil {
		return Plan{}, fmt.Errorf("enforce: resolve trusted unshare: %w", err)
	}
	abs := workspace
	if !readOnly && workspace != "" {
		if a, aerr := filepath.Abs(workspace); aerr == nil {
			abs = a
		}
	}
	return Plan{
		Active:       true,
		Workspace:    abs,
		ReadOnly:     readOnly,
		AllowNetwork: allowNetwork,
		selfExe:      self,
		unsharePath:  unshareIdentity.CanonicalPath,
	}, nil
}

// Wrap rewrites bin/args so the process that actually starts is already
// confined: Landlock is applied to it before it execs into bin (see
// RunSandboxExec), and -- unless the run is permitted network access -- the
// whole thing runs inside a network namespace with no configured route. A
// no-op Plan (Active false) returns bin/args unchanged.
func (p Plan) Wrap(bin string, args []string) (string, []string) {
	if !p.Active {
		return bin, args
	}
	inner := []string{p.selfExe, SandboxExecArg, "--workspace", p.Workspace}
	if p.ReadOnly {
		inner = append(inner, "--readonly")
	}
	inner = append(inner, "--")
	inner = append(inner, bin)
	inner = append(inner, args...)
	if p.AllowNetwork {
		return inner[0], inner[1:]
	}
	// No configured route inside the namespace means every connect()/bind()
	// past loopback fails at the kernel level -- this is not a policy the
	// backend can be asked to honor, it structurally cannot reach anywhere.
	// p.unsharePath (not a bare "unshare" argv0) so the process that
	// actually launches is the exact binary NewPlan verified, never
	// whatever a PATH substitution after that point would redirect a bare
	// name to (Session 2, post-v4 hardening plan item C).
	full := append([]string{"--net", "--map-root-user", "--"}, inner...)
	return p.unsharePath, full
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
