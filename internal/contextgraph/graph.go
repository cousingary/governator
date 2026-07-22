package contextgraph

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cousingary/governator/internal/config"
	"github.com/cousingary/governator/internal/controllerenv"
	stageexec "github.com/cousingary/governator/internal/stage"
	"github.com/cousingary/governator/internal/toolregistry"
)

type Status struct {
	Mode       string
	Provider   string
	Bin        string
	Path       string
	SHA256     string
	IdentityID string
	Enabled    bool
}

type Stats struct {
	Version       string         `json:"version"`
	Initialized   bool           `json:"initialized"`
	ProjectPath   string         `json:"projectPath"`
	IndexPath     string         `json:"indexPath"`
	FileCount     int            `json:"fileCount"`
	NodeCount     int            `json:"nodeCount"`
	EdgeCount     int            `json:"edgeCount"`
	DBSizeBytes   int64          `json:"dbSizeBytes"`
	LastIndexed   string         `json:"lastIndexed"`
	Pending       map[string]int `json:"pendingChanges"`
	Languages     []string       `json:"languages"`
	WorktreeState any            `json:"worktreeMismatch"`
}

type Snapshot struct {
	Mode        string `json:"mode"`
	Provider    string `json:"provider"`
	Version     string `json:"version,omitempty"`
	ProjectPath string `json:"project_path,omitempty"`
	IndexPath   string `json:"index_path,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	FileCount   int    `json:"file_count,omitempty"`
	NodeCount   int    `json:"node_count,omitempty"`
	EdgeCount   int    `json:"edge_count,omitempty"`
	DBSizeBytes int64  `json:"db_size_bytes,omitempty"`
	Available   bool   `json:"available"`
	Refreshed   bool   `json:"refreshed"`
	Warning     string `json:"warning,omitempty"`
	BinaryPath  string `json:"-"`
	// IdentityID carries status.IdentityID (provider name:path:sha256, see
	// ResolveConfigWithRegistry) forward from resolution through Prepare/
	// Current so a later caller building a Status from this Snapshot (Query's
	// top-level wrapper) can still pin the same frozen identity rather than
	// trusting whatever the provider's name resolves to at that later moment
	// (Sol v9 P0-3 TOCTOU: "a provider rotation after replay calculation can
	// therefore change the executed provider").
	IdentityID string `json:"-"`
	// PriorGraphFingerprint is the hash of .codegraph/codegraph.db
	// immediately before a mutating (init/sync) invocation ran, empty when no
	// prior index file existed. Combined with Fingerprint (the post-mutation
	// hash), it attributes exactly what the graph tool itself changed,
	// distinct from any agent-authored change in the same transaction, and
	// folds into replay identity the same way Fingerprint already does (both
	// are hashed via hashJSON(snapshot) at the call site).
	PriorGraphFingerprint string `json:"-"`
}

// Resolve determines whether the configured graph provider is available.
// Sol report P0-5/attack 9: a context-graph helper is a controller
// component that runs on the host before the backend and before baseline
// measurement, with no sandbox of its own — so it must never be trusted
// merely because it resolved via PATH. Resolve gates through the
// trusted-tool registry keyed on status.Provider (e.g. "codegraph"):
// absent a registry entry (shipped default, or an operator's own
// ~/.governator/tools.yaml declaration), the provider is treated exactly
// like "not found" for "auto"/"off" — silently disabled, never invoked —
// and as a hard failure for "required", the same shape as today's "not
// found in PATH" error. A registered provider is still independently
// verified every resolution: canonical path, content hash, owner, mode,
// non-writable parent directories (registry.Resolve).
func Resolve() (Status, error) {
	cfg, err := config.Load()
	if err != nil {
		return Status{}, err
	}
	return ResolveConfig(cfg)
}

// ResolveConfig resolves the graph provider from the already-loaded run config.
// Standalone callers load the registry here; governed runs use
// ResolveConfigWithRegistry with the registry frozen at run construction.
func ResolveConfig(cfg config.Config) (Status, error) {
	registry, err := toolregistry.Load()
	if err != nil {
		return Status{}, err
	}
	return ResolveConfigWithRegistry(cfg, registry)
}

func ResolveConfigWithRegistry(cfg config.Config, registry *toolregistry.Registry) (Status, error) {
	status := Status{Mode: cfg.Graph.Mode, Provider: cfg.Graph.Provider, Bin: cfg.Graph.Bin}
	if status.Mode == "off" {
		return status, nil
	}
	if registry == nil {
		return status, fmt.Errorf("graph provider registry is not frozen")
	}
	identity, terr := registry.Resolve(status.Provider, status.Bin)
	if terr != nil {
		if status.Mode == "required" {
			return status, fmt.Errorf("%s graph provider is required but not trusted: %w", status.Provider, terr)
		}
		return status, nil
	}
	status.Path = identity.CanonicalPath
	status.SHA256 = identity.SHA256
	status.IdentityID = identity.Name + ":" + identity.CanonicalPath + ":" + identity.SHA256
	status.Enabled = true
	return status, nil
}

// scopedCommandOutput declares stage authority directly and lets
// stage.Executor compile the matching sandbox. Read-only invocations
// (version/status/query/callers/callees/impact) get project-read-only
// authority with no write roots at all; mutating invocations (init/sync)
// additionally receive exactly the precreated .codegraph directory as a
// write root (writeRoots), never the whole project -- see PrepareWithStatus.
// The caller-supplied registry is never reloaded here (Sol v9 P0-3: "reloads
// the trusted-tool registry and resolves the provider again for each
// invocation" without checking it against the identity frozen before
// replay); resolving the handle from it still re-opens and re-hashes the
// file every call (registry.ResolveHandle's own TOCTOU protection), and that
// freshly resolved identity must additionally equal status.IdentityID -- the
// identity Resolve/ResolveConfigWithRegistry captured before replay -- so a
// same-name provider rotated after that point is rejected rather than
// silently executed.
func scopedCommandOutput(ctx context.Context, status Status, registry *toolregistry.Registry, args []string, dir string, writeRoots []string, env controllerenv.Frozen) ([]byte, error) {
	if err := env.Validate(); err != nil {
		return nil, err
	}
	if registry == nil {
		return nil, fmt.Errorf("contextgraph: provider registry is not frozen for this invocation")
	}
	providerHandle, err := registry.ResolveHandle(status.Provider, status.Bin, toolregistry.KindTrustedController)
	if err != nil {
		return nil, err
	}
	defer providerHandle.Close()
	if status.IdentityID != "" {
		gotID := providerHandle.Identity.Name + ":" + providerHandle.Identity.CanonicalPath + ":" + providerHandle.Identity.SHA256
		if gotID != status.IdentityID {
			return nil, fmt.Errorf("%s provider identity changed since resolution: frozen %s, now %s", status.Provider, status.IdentityID, gotID)
		}
	}
	executable := stageexec.ExecutableIdentity{CanonicalPath: providerHandle.Identity.CanonicalPath, SHA256: providerHandle.Identity.SHA256}
	authority := stageexec.StageAuthority{ReadRoots: []string{dir}, WriteRoots: append([]string(nil), writeRoots...), Network: stageexec.NetworkPolicyDenied, Credentials: stageexec.CredentialPolicyNone, RequireStrongScope: true}
	result, err := stageexec.NewExecutor().Run(ctx, stageexec.StageSpec{
		RunID:            "contextgraph",
		StageID:          status.Provider,
		Executable:       executable,
		Arguments:        append([]string(nil), args...),
		WorkingDirectory: dir,
		Environment:      stageexec.FrozenEnvironment{Values: append([]string(nil), env.Values...), Hash: env.Hash},
		NetworkPolicy:    authority.Network,
		CredentialPolicy: authority.Credentials,
		OutputLimit:      2 << 20,
		OutputCapture:    stageexec.CaptureRequiredComplete,
		DescendantPolicy: stageexec.DescendantPolicy{RequireStrong: authority.RequireStrongScope},
		Authority:        authority,
		ExecutableHandle: providerHandle,
	})
	if err != nil {
		return []byte(result.Output), err
	}
	// StageResult.ExitStatus and err are deliberately distinct (see
	// assay.Evaluate's identical fix this session): err is nil for a plain
	// nonzero exit, so a caller that only checks err treats a blocked or
	// failing provider command as success.
	if result.ExitStatus != 0 {
		return []byte(result.Output), fmt.Errorf("%s %v: exit status %d", status.Provider, args, result.ExitStatus)
	}
	return []byte(result.Output), nil
}

func Version(ctx context.Context, status Status) (string, error) {
	registry, err := toolregistry.Load()
	if err != nil {
		return "", err
	}
	return versionWithEnvironment(ctx, status, registry, controllerenv.Freeze())
}

func versionWithEnvironment(ctx context.Context, status Status, registry *toolregistry.Registry, env controllerenv.Frozen) (string, error) {
	if !status.Enabled {
		return "", fmt.Errorf("graph provider is not enabled")
	}
	output, err := scopedCommandOutput(ctx, status, registry, []string{"version"}, "", nil, env)
	if err != nil {
		return "", fmt.Errorf("%s version: %w: %s", status.Provider, err, strings.TrimSpace(string(output)))
	}
	return strings.TrimSpace(string(output)), nil
}

func Inspect(ctx context.Context, status Status, project string) (Stats, error) {
	registry, err := toolregistry.Load()
	if err != nil {
		return Stats{}, err
	}
	return inspectWithEnvironment(ctx, status, project, registry, controllerenv.Freeze())
}

func inspectWithEnvironment(ctx context.Context, status Status, project string, registry *toolregistry.Registry, env controllerenv.Frozen) (Stats, error) {
	if !status.Enabled {
		return Stats{}, fmt.Errorf("graph provider is not enabled")
	}
	output, err := scopedCommandOutput(ctx, status, registry, []string{"status", "--json", project}, project, nil, env)
	if err != nil {
		return Stats{}, fmt.Errorf("%s status: %w: %s", status.Provider, err, strings.TrimSpace(string(output)))
	}
	var stats Stats
	if err := json.Unmarshal(output, &stats); err != nil {
		return Stats{}, fmt.Errorf("decode %s status: %w", status.Provider, err)
	}
	return stats, nil
}

// Current is a standalone (non-governed) caller's entry point: it loads the
// trusted-tool registry exactly once and reuses that single Registry for
// both resolving the provider and every subprocess invocation this call
// makes, rather than Resolve() and CurrentWithStatus's internals each
// loading their own copy from disk.
func Current(project string) (Snapshot, error) {
	registry, err := toolregistry.Load()
	if err != nil {
		return Snapshot{}, err
	}
	cfg, err := config.Load()
	if err != nil {
		return Snapshot{}, err
	}
	status, err := ResolveConfigWithRegistry(cfg, registry)
	if err != nil {
		return Snapshot{}, err
	}
	return CurrentWithStatus(context.Background(), project, status, registry, controllerenv.Freeze())
}

// CurrentWithStatus snapshots an already-resolved provider without mutating
// the graph. registry must be the same Registry status was resolved against
// (governed runs pass RunEnvironment.ToolRegistry, frozen once at run
// construction, see runtime.buildRunEnvironment) -- it is never reloaded
// here or in any invocation this call makes.
func CurrentWithStatus(ctx context.Context, project string, status Status, registry *toolregistry.Registry, env controllerenv.Frozen) (Snapshot, error) {
	var err error
	snapshot := Snapshot{Mode: status.Mode, Provider: status.Provider, BinaryPath: status.Path, IdentityID: status.IdentityID}
	if !status.Enabled {
		return snapshot, nil
	}
	project, err = filepath.Abs(project)
	if err != nil {
		return snapshot, err
	}
	snapshot.ProjectPath = project
	snapshot.Version, err = versionWithEnvironment(ctx, status, registry, env)
	if err != nil {
		return snapshot, err
	}
	stats, err := inspectWithEnvironment(ctx, status, project, registry, env)
	if err != nil || !stats.Initialized {
		return snapshot, nil
	}
	snapshot, err = snapshotFromStats(snapshot, stats)
	if err != nil {
		return prepareFailure(snapshot, status.Mode, err)
	}
	return snapshot, nil
}

// Prepare is Current's mutating counterpart: standalone callers (the `gov
// graph refresh`/`gov graph query` CLI) load the registry once here and
// reuse it through PrepareWithStatus's own multi-step invocation.
func Prepare(ctx context.Context, project string) (Snapshot, error) {
	registry, err := toolregistry.Load()
	if err != nil {
		return Snapshot{}, err
	}
	cfg, err := config.Load()
	if err != nil {
		return Snapshot{}, err
	}
	status, err := ResolveConfigWithRegistry(cfg, registry)
	if err != nil {
		return Snapshot{}, err
	}
	return PrepareWithStatus(ctx, project, status, registry, controllerenv.Freeze())
}

// PrepareWithStatus runs an already-resolved provider handle. registry is
// loaded exactly once by the caller (Prepare, or a governed run's frozen
// RunEnvironment.ToolRegistry) and reused for every subprocess this call
// makes -- version, then init/sync, then status -- never reloaded per
// invocation (Sol v9 P0-3).
//
// init/sync are the only mutating graph operations: version/status/query/
// callers/callees/impact all get project-read-only authority with no write
// roots (scopedCommandOutput's default). init/sync additionally need to
// create or update <project>/.codegraph/codegraph.db, so this function
// precreates exactly that directory and grants it -- and nothing else in the
// project -- as a write root; a provider that writes outside .codegraph
// fails closed under Landlock rather than silently getting broad write
// access to the project it is meant to be read-only over.
func PrepareWithStatus(ctx context.Context, project string, status Status, registry *toolregistry.Registry, env controllerenv.Frozen) (Snapshot, error) {
	var err error
	snapshot := Snapshot{Mode: status.Mode, Provider: status.Provider, BinaryPath: status.Path, IdentityID: status.IdentityID}
	if !status.Enabled {
		return snapshot, nil
	}
	project, err = filepath.Abs(project)
	if err != nil {
		return prepareFailure(snapshot, status.Mode, err)
	}
	snapshot.ProjectPath = project
	snapshot.Version, err = versionWithEnvironment(ctx, status, registry, env)
	if err != nil {
		return prepareFailure(snapshot, status.Mode, err)
	}

	codegraphDir := filepath.Join(project, ".codegraph")
	dbPath := filepath.Join(codegraphDir, "codegraph.db")
	priorFingerprint, priorErr := hashFile(dbPath)
	if priorErr != nil && !os.IsNotExist(priorErr) {
		return prepareFailure(snapshot, status.Mode, priorErr)
	}
	snapshot.PriorGraphFingerprint = priorFingerprint

	args := []string{"sync", "--quiet", project}
	if _, statErr := os.Stat(dbPath); os.IsNotExist(statErr) {
		args = []string{"init", "--target", "none", project}
	} else if statErr != nil {
		return prepareFailure(snapshot, status.Mode, statErr)
	}
	// Landlock binds write rules to an already-opened path (enforce.Plan.
	// WithWriteRoots stats every root before granting it), so .codegraph
	// must exist before the provider's mutating invocation, not be left for
	// the provider itself to create under a sandbox that only ever grants
	// pre-existing paths.
	if err := os.MkdirAll(codegraphDir, 0o700); err != nil {
		return prepareFailure(snapshot, status.Mode, fmt.Errorf("precreate %s: %w", codegraphDir, err))
	}
	output, runErr := scopedCommandOutput(ctx, status, registry, args, project, []string{codegraphDir}, env)
	if runErr != nil {
		err = fmt.Errorf("%s %s: %w: %s", status.Provider, args[0], runErr, strings.TrimSpace(string(output)))
		return prepareFailure(snapshot, status.Mode, err)
	}
	stats, err := inspectWithEnvironment(ctx, status, project, registry, env)
	if err != nil {
		return prepareFailure(snapshot, status.Mode, err)
	}
	if !stats.Initialized {
		return prepareFailure(snapshot, status.Mode, fmt.Errorf("%s did not initialize an index for %s", status.Provider, project))
	}
	snapshot, err = snapshotFromStats(snapshot, stats)
	if err != nil {
		return prepareFailure(snapshot, status.Mode, err)
	}
	snapshot.Refreshed = true
	return snapshot, nil
}

func prepareFailure(snapshot Snapshot, mode string, err error) (Snapshot, error) {
	snapshot.Warning = err.Error()
	if mode == "required" {
		return snapshot, err
	}
	return snapshot, nil
}

// snapshotFromStats resolves the on-disk index path and hashes it into
// Fingerprint. Sol10 P0-7: Available used to be set true before the
// fingerprint hash was even attempted, so a hashFile failure (index path
// missing/unreadable) still returned Available=true with an empty
// Fingerprint -- and for any mode other than "required", the caller
// (prepareFailure) swallowed the error entirely, silently handing the rest
// of the run a snapshot that claimed to have graph state it did not
// actually have. Available is now set only once the fingerprint has
// actually been computed, so a hashing failure is honestly Available=false
// in every mode, not just "required".
func snapshotFromStats(snapshot Snapshot, stats Stats) (Snapshot, error) {
	snapshot.ProjectPath = stats.ProjectPath
	snapshot.IndexPath = stats.IndexPath
	snapshot.FileCount = stats.FileCount
	snapshot.NodeCount = stats.NodeCount
	snapshot.EdgeCount = stats.EdgeCount
	snapshot.DBSizeBytes = stats.DBSizeBytes
	if snapshot.ProjectPath == "" {
		snapshot.ProjectPath = filepath.Dir(filepath.Dir(stats.IndexPath))
	}
	indexPath := stats.IndexPath
	if indexPath == "" {
		indexPath = filepath.Join(snapshot.ProjectPath, ".codegraph", "codegraph.db")
	} else if info, err := os.Stat(indexPath); err != nil {
		return snapshot, fmt.Errorf("locate graph index: %w", err)
	} else if info.IsDir() {
		indexPath = filepath.Join(indexPath, "codegraph.db")
	}
	snapshot.IndexPath = indexPath
	fingerprint, err := hashFile(indexPath)
	if err != nil {
		return snapshot, fmt.Errorf("fingerprint graph index: %w", err)
	}
	snapshot.Fingerprint = fingerprint
	snapshot.Available = true
	return snapshot, nil
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	// Stream instead of os.ReadFile: a codegraph index can be hundreds of MB,
	// and slurping it whole caused avoidable memory spikes on large repos.
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	sum := h.Sum(nil)
	return hex.EncodeToString(sum), nil
}

// Query is the standalone caller's entry point: it loads the trusted-tool
// registry once for this single invocation. A caller chaining Prepare then
// Query in one process (the `gov graph query` CLI) should use
// QueryWithRegistry instead, threading the same Registry Prepare already
// loaded rather than reloading here (Sol v9 P0-3: "Pass a frozen provider
// handle through: Resolve, Current, Prepare, Query").
func Query(ctx context.Context, snapshot Snapshot, search string, limit int) ([]byte, error) {
	registry, err := toolregistry.Load()
	if err != nil {
		return nil, err
	}
	return QueryWithRegistry(ctx, snapshot, registry, search, limit)
}

// QueryWithRegistry is Query with the registry supplied by the caller
// (governed runs, or a CLI chain that already loaded one for Prepare).
// snapshot.IdentityID -- carried forward from whichever Resolve/Prepare/
// Current call produced this Snapshot -- pins scopedCommandOutput's identity
// check even when registry was reloaded between Prepare and Query, so a
// provider rotated in between is rejected rather than silently queried.
func QueryWithRegistry(ctx context.Context, snapshot Snapshot, registry *toolregistry.Registry, search string, limit int) ([]byte, error) {
	if !snapshot.Available {
		return nil, fmt.Errorf("context graph is not available")
	}
	search = strings.TrimSpace(search)
	if search == "" {
		return nil, fmt.Errorf("graph query search cannot be empty")
	}
	if limit <= 0 || limit > 20 {
		return nil, fmt.Errorf("graph query limit must be between 1 and 20")
	}
	status := Status{Provider: snapshot.Provider, Path: snapshot.BinaryPath, Enabled: snapshot.Available, IdentityID: snapshot.IdentityID}
	output, err := scopedCommandOutput(ctx, status, registry, []string{"query", "--json", "--path", snapshot.ProjectPath, "--limit", strconv.Itoa(limit), search}, snapshot.ProjectPath, nil, controllerenv.Freeze())
	if err != nil {
		return nil, fmt.Errorf("%s query: %w: %s", snapshot.Provider, err, strings.TrimSpace(string(output)))
	}
	return output, nil
}

func ProviderIdentityHash(status Status) string {
	if status.Mode == "off" {
		return "off"
	}
	if !status.Enabled {
		return "disabled:" + status.Mode + ":" + status.Provider + ":" + status.Bin
	}
	return hashString(status.IdentityID)
}

func hashString(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func CommandPatterns(snapshot Snapshot) []string {
	if !snapshot.Available {
		return nil
	}
	prefix := shellQuote(snapshot.BinaryPath)
	path := shellQuote(snapshot.ProjectPath)
	return []string{
		prefix + " query --json --path " + path + " --limit 5 *",
		prefix + " callers --json --path " + path + " --limit 10 *",
		prefix + " callees --json --path " + path + " --limit 10 *",
		prefix + " impact --json --path " + path + " --depth 2 *",
	}
}

func PromptAnnotation(snapshot Snapshot) string {
	if !snapshot.Available {
		return ""
	}
	patterns := CommandPatterns(snapshot)
	return fmt.Sprintf(`
Structural context graph: %s %s (fingerprint %s; files=%d nodes=%d edges=%d).
Before broad grep or repeated file reads, query this read-only index with one of these controller-approved forms:
- %s
- %s
- %s
- %s
Replace the final * with one shell-quoted symbol or search term. Use graph results to select files, then verify source before editing.
`, snapshot.Provider, snapshot.Version, snapshot.Fingerprint, snapshot.FileCount, snapshot.NodeCount, snapshot.EdgeCount, patterns[0], patterns[1], patterns[2], patterns[3])
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}
