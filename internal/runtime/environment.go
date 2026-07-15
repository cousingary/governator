package runtime

import (
	"fmt"

	"github.com/cousingary/governator/internal/config"
	"github.com/cousingary/governator/internal/controllerenv"
	"github.com/cousingary/governator/internal/protectedpaths"
)

// RunEnvironment is the immutable snapshot of every configuration-derived
// input a run's decisions are evaluated against (Sol Finding 2 / Session 3).
//
// Before this type existed, execution-critical code called config.Current()
// independently at several different points during a single run: once near
// the top of runOnce, again inside auditTranscript (after the agent had
// already executed), again inside the route broker, again inside Docker
// credential-mount resolution, again inside the protected-path fingerprint.
// Each call re-read config.yaml from disk, so a file edit made while the
// backend was running could change enforcement partway through a run whose
// identity and approval were computed against the *starting* configuration —
// the exact exploit the audit reproduced (doctrine.unenforceable_rule_action
// flipped from "block" to "flag" mid-run; the run was approved anyway).
//
// buildRunEnvironment is called exactly once, at the very top of runOnce,
// before any run decision (lock, quota, routing, containment, policy gate,
// launch). Every subsequent execution-critical read of configuration takes
// its value from this struct, never from config.Current() again.
type ControllerEnvironment struct {
	Environment     []string
	EnvironmentHash string
}

type RunEnvironment struct {
	// Config is the full effective configuration, loaded once via
	// config.LoadStrict() (never config.Current(), which silently swallows a
	// malformed file — a run must fail closed on that, not fall back to
	// built-in defaults mid-execution).
	Config config.Config
	// ConfigHash is Config.Hash(), captured at the same instant as Config so
	// the recorded ExecutionIdentity always describes the exact environment
	// the run was evaluated against.
	ConfigHash string
	// ProtectedManifestPath is Config.ProtectedManifest, resolved once.
	ProtectedManifestPath string
	// ProtectedPatterns is the protected-path manifest's parsed pattern list,
	// read once from ProtectedManifestPath. Both the pre/post-run protected
	// fingerprint and the transcript audit's secret-pattern check use this
	// frozen list rather than re-reading the manifest file path out of a
	// freshly re-loaded config.
	ProtectedPatterns []string
	// CredentialRoots is Config.Credentials.Roots, captured once so Docker
	// credential-mount resolution can't be redirected mid-run by an edited
	// config file.
	CredentialRoots []string
	Controller      ControllerEnvironment
}

// buildRunEnvironment loads and freezes every configuration-derived input a
// run needs before making its first decision. Called once per runOnce
// attempt (never per-decision) — see RunEnvironment's doc comment.
func buildRunEnvironment() (RunEnvironment, error) {
	cfg, err := config.LoadStrict()
	if err != nil {
		return RunEnvironment{}, fmt.Errorf("load configuration: %w", err)
	}
	patterns, err := protectedpaths.PatternsFor(cfg.ProtectedManifest)
	if err != nil {
		return RunEnvironment{}, fmt.Errorf("load protected-path manifest %q: %w", cfg.ProtectedManifest, err)
	}
	controllerEnv := controllerenv.Base()
	return RunEnvironment{
		Config:                cfg,
		ConfigHash:            cfg.Hash(),
		ProtectedManifestPath: cfg.ProtectedManifest,
		ProtectedPatterns:     patterns,
		CredentialRoots:       append([]string(nil), cfg.Credentials.Roots...),
		Controller: ControllerEnvironment{
			Environment:     append([]string(nil), controllerEnv...),
			EnvironmentHash: controllerenv.Hash(controllerEnv),
		},
	}, nil
}
