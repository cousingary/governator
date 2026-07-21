package runtime

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	goruntime "runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cousingary/governator/internal/agents"
	"github.com/cousingary/governator/internal/assay"
	"github.com/cousingary/governator/internal/attest"
	"github.com/cousingary/governator/internal/breaker"
	"github.com/cousingary/governator/internal/config"
	"github.com/cousingary/governator/internal/containment"
	"github.com/cousingary/governator/internal/contextgraph"
	"github.com/cousingary/governator/internal/contracts"
	"github.com/cousingary/governator/internal/controllerenv"
	"github.com/cousingary/governator/internal/enforce"
	"github.com/cousingary/governator/internal/gitplumb"
	"github.com/cousingary/governator/internal/lifecycle"
	"github.com/cousingary/governator/internal/minimalism"
	"github.com/cousingary/governator/internal/observability"
	"github.com/cousingary/governator/internal/policy"
	"github.com/cousingary/governator/internal/prompts"
	"github.com/cousingary/governator/internal/protectedpaths"
	"github.com/cousingary/governator/internal/quota"
	"github.com/cousingary/governator/internal/router"
	"github.com/cousingary/governator/internal/runner"
	"github.com/cousingary/governator/internal/spend"
	stageexec "github.com/cousingary/governator/internal/stage"
	"github.com/cousingary/governator/internal/tokenoptimizer"
	"github.com/cousingary/governator/internal/toolregistry"
)

var RuntimeGOOS = goruntime.GOOS

type RunRecord struct {
	ID              string                    `json:"id"`
	JobID           string                    `json:"job_id"`
	JobType         string                    `json:"job_type,omitempty"`
	Agent           string                    `json:"agent,omitempty"`
	Mode            string                    `json:"mode,omitempty"`
	Status          string                    `json:"status"`
	Root            string                    `json:"root"`
	Worktree        string                    `json:"worktree,omitempty"`
	Branch          string                    `json:"branch,omitempty"`
	Diff            string                    `json:"diff,omitempty"`
	Transcript      string                    `json:"transcript,omitempty"`
	Message         string                    `json:"message"`
	Commit          string                    `json:"commit,omitempty"`
	Created         string                    `json:"created"`
	Replayed        bool                      `json:"replayed"`
	IdentityHash    string                    `json:"identity_hash,omitempty"`
	CostUSD         float64                   `json:"cost_usd"`
	Usage           observability.TokenUsage  `json:"usage"`
	ToolCalls       int                       `json:"tool_calls"`
	TranscriptBytes int64                     `json:"transcript_bytes"`
	Graph           contextgraph.Snapshot     `json:"graph"`
	ValidOutput     bool                      `json:"valid_output"`
	FailureTaxonomy string                    `json:"failure_taxonomy,omitempty"`
	SelfReview      *contracts.ResultDocument `json:"self_review,omitempty"`
	PromptVersion   string                    `json:"prompt_version,omitempty"`
	Envelope        string                    `json:"envelope,omitempty"`
	Notes           string                    `json:"notes,omitempty"`
	RepairOf        string                    `json:"repair_of,omitempty"`
}

func envelopeJSON(spec agents.BackendSpec, capability agents.Capability) string {
	native := []string{}
	compensated := []string{"pre_post_fingerprint"}
	add := func(name string, isNative bool) {
		if isNative {
			native = append(native, name)
		} else {
			compensated = append(compensated, name)
		}
	}
	add("filesystem_sandbox", capability.NativeSandbox)
	if spec.Sandbox == agents.SandboxReadOnly {
		add("read_only", capability.NativeReadOnly)
	}
	add("approval_policy", capability.NativeApprovalPolicy)
	if !spec.Network {
		add("network_control", capability.NetworkControl)
	}
	payload, _ := json.Marshal(map[string]any{
		"native": native, "compensated": compensated,
		"transcript_format": capability.TranscriptFormat,
	})
	return string(payload)
}

// workspaceDescriptor is the complete workspace/runner descriptor persisted
// as the WORKSPACE_READY stage's detail (Sol P1.6, finding #13): everything
// a later process-crash recovery pass needs to reconstruct the exact Runner
// and runner.Workspace an interrupted run was using, without any in-memory
// state surviving the crash. Runner/Path/Root/Branch/Git/Container are what
// recovery.go's destroyLeftoverWorkspace actually needs to call the real
// runner.Destroy path; ImageID/RunnerConfigHash/WorkspaceDigest are
// provenance recorded because a crashed run is exactly when that context is
// otherwise lost.
type workspaceDescriptor struct {
	Runner           string `json:"runner"`
	Path             string `json:"path"`
	Root             string `json:"root"`
	Branch           string `json:"branch,omitempty"`
	Git              bool   `json:"git"`
	Container        string `json:"container,omitempty"`
	ImageID          string `json:"image_id,omitempty"`
	RunnerConfigHash string `json:"runner_config_hash,omitempty"`
	WorkspaceDigest  string `json:"workspace_digest,omitempty"`
}

// newWorkspaceDescriptor captures ws (freshly returned by rn.Prepare) plus
// the contract's runner configuration into a workspaceDescriptor. Called
// once, before the agent ever launches, so the recorded state cannot be
// contaminated by anything the agent does afterward.
func newWorkspaceDescriptor(c contracts.Contract, ws runner.Workspace) (workspaceDescriptor, error) {
	snap, err := fingerprint(ws.Path)
	if err != nil {
		return workspaceDescriptor{}, err
	}
	d := workspaceDescriptor{
		Runner:          c.EffectiveRunner(),
		Path:            ws.Path,
		Root:            ws.Root,
		Branch:          ws.Branch,
		Git:             ws.Git,
		Container:       ws.Container,
		WorkspaceDigest: snapshotDigest(snap),
	}
	if d.Runner == "docker" && c.Docker != nil {
		d.ImageID = c.Docker.Image
	}
	d.RunnerConfigHash = runnerConfigHash(d.Runner, c.Docker, c.Local)
	return d, nil
}

// runnerConfigHash fingerprints whichever runner config is actually active
// for kind, so a workspaceDescriptor records exactly what configuration
// produced the workspace it describes.
func runnerConfigHash(kind string, docker *contracts.DockerRunnerConfig, local *contracts.LocalRunnerConfig) string {
	var payload any
	switch kind {
	case "docker":
		payload = docker
	default:
		payload = local
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

type Runner struct{ Home string }

func Home() string { return config.Current().LedgerDir }

func New() *Runner { return &Runner{Home: Home()} }

func dbOpen(home string) (*sql.DB, error) {
	return observability.Open(home)
}

func insertRun(db *sql.DB, r RunRecord, ch, head string) error {
	_, err := db.Exec(`INSERT INTO runs(id,job_id,job_type,agent,mode,status,root,worktree,branch,contract_hash,base_head,diff,transcript,message,created,prompt_version,envelope_json,notes,graph_provider,graph_version,graph_fingerprint,graph_files,graph_nodes,graph_edges,graph_db_bytes,repair_of,identity_hash)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, r.ID, r.JobID, r.JobType, r.Agent, r.Mode, r.Status, r.Root, r.Worktree, r.Branch, ch, head, r.Diff, r.Transcript, r.Message, r.Created, r.PromptVersion, r.Envelope, r.Notes, r.Graph.Provider, r.Graph.Version, r.Graph.Fingerprint, r.Graph.FileCount, r.Graph.NodeCount, r.Graph.EdgeCount, r.Graph.DBSizeBytes, r.RepairOf, r.IdentityHash)
	return err
}

func updateRun(db *sql.DB, r RunRecord, approved string) error {
	_, err := db.Exec(`UPDATE runs SET status=?,approved_head=?,diff=?,message=?,commit_hash=?,identity_hash=? WHERE id=?`,
		r.Status, approved, r.Diff, r.Message, r.Commit, r.IdentityHash, r.ID)
	return err
}

func updateRunGraph(db *sql.DB, r RunRecord) error {
	_, err := db.Exec(`UPDATE runs SET prompt_version=?,envelope_json=?,notes=?,graph_provider=?,graph_version=?,graph_fingerprint=?,graph_files=?,graph_nodes=?,graph_edges=?,graph_db_bytes=?,identity_hash=? WHERE id=?`,
		r.PromptVersion, r.Envelope, r.Notes, r.Graph.Provider, r.Graph.Version, r.Graph.Fingerprint, r.Graph.FileCount, r.Graph.NodeCount, r.Graph.EdgeCount, r.Graph.DBSizeBytes, r.IdentityHash, r.ID)
	return err
}

func Last(id string) (RunRecord, error) {
	db, err := dbOpen(Home())
	if err != nil {
		return RunRecord{}, err
	}
	defer db.Close()
	q := `SELECT id,job_id,COALESCE(job_type,''),COALESCE(agent,''),COALESCE(mode,''),status,root,worktree,branch,diff,transcript,message,COALESCE(commit_hash,''),created,cost_usd,valid_output,failure_taxonomy,result_json,COALESCE(prompt_version,''),COALESCE(envelope_json,''),COALESCE(notes,''),input_tokens,output_tokens,cached_input_tokens,cache_creation_tokens,reasoning_tokens,total_tokens,usage_available,tool_calls,transcript_bytes,COALESCE(graph_provider,''),COALESCE(graph_version,''),COALESCE(graph_fingerprint,''),graph_files,graph_nodes,graph_edges,graph_db_bytes,COALESCE(repair_of,'') FROM runs`
	var row *sql.Row
	if id == "" || id == "last" {
		row = db.QueryRow(q + ` ORDER BY created DESC LIMIT 1`)
	} else {
		row = db.QueryRow(q+` WHERE id=?`, id)
	}
	r, err := scanRun(row)
	return r, err
}

func Quarantines() ([]RunRecord, error) {
	db, err := dbOpen(Home())
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.Query(`SELECT id,job_id,COALESCE(job_type,''),COALESCE(agent,''),COALESCE(mode,''),status,root,worktree,branch,diff,transcript,message,COALESCE(commit_hash,''),created,cost_usd,valid_output,failure_taxonomy,result_json,COALESCE(prompt_version,''),COALESCE(envelope_json,''),COALESCE(notes,''),input_tokens,output_tokens,cached_input_tokens,cache_creation_tokens,reasoning_tokens,total_tokens,usage_available,tool_calls,transcript_bytes,COALESCE(graph_provider,''),COALESCE(graph_version,''),COALESCE(graph_fingerprint,''),graph_files,graph_nodes,graph_edges,graph_db_bytes,COALESCE(repair_of,'') FROM runs WHERE status='QUARANTINED' ORDER BY created DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RunRecord
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

type rowScanner interface {
	Scan(...any) error
}

func scanRun(row rowScanner) (RunRecord, error) {
	var r RunRecord
	var resultJSON string
	err := row.Scan(&r.ID, &r.JobID, &r.JobType, &r.Agent, &r.Mode, &r.Status, &r.Root, &r.Worktree, &r.Branch, &r.Diff, &r.Transcript, &r.Message, &r.Commit, &r.Created, &r.CostUSD, &r.ValidOutput, &r.FailureTaxonomy, &resultJSON, &r.PromptVersion, &r.Envelope, &r.Notes, &r.Usage.InputTokens, &r.Usage.OutputTokens, &r.Usage.CachedInputTokens, &r.Usage.CacheCreationTokens, &r.Usage.ReasoningTokens, &r.Usage.TotalTokens, &r.Usage.Available, &r.ToolCalls, &r.TranscriptBytes, &r.Graph.Provider, &r.Graph.Version, &r.Graph.Fingerprint, &r.Graph.FileCount, &r.Graph.NodeCount, &r.Graph.EdgeCount, &r.Graph.DBSizeBytes, &r.RepairOf)
	if err == nil {
		r.Graph.Available = r.Graph.Fingerprint != ""
	}
	if err == nil && resultJSON != "" {
		var review contracts.ResultDocument
		if json.Unmarshal([]byte(resultJSON), &review) == nil {
			r.SelfReview = &review
		}
	}
	return r, err
}

// lockStaleThreshold bounds how long a live-PID lock is trusted before the
// controller reclaims it. Governed runs are capped by budget.max_minutes (and
// release the lock on return), so a lock held far beyond any plausible run
// length is far more likely a recycled PID than a genuinely in-flight job. 2h
// comfortably exceeds the largest realistic max_minutes while still catching
// day-old orphan locks within the same session.
const lockStaleThreshold = 2 * time.Hour

// processStartTicks returns the kernel start time of pid on Linux, or "" off
// Linux / on any read failure. Two PIDs that happen to share a number across
// recycling will have different start times, so this distinguishes "same
// process, lock is real" from "PID reused, lock is phantom" without the
// coarser staleness heuristic. Field 22 of /proc/<pid>/stat is starttime in
// clock ticks since boot.
func processStartTicks(pid int) string {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return ""
	}
	rparen := strings.LastIndexByte(string(data), ')')
	if rparen < 0 {
		return ""
	}
	// Fields after ')' start at stat field 3 (state), so starttime (field 22)
	// sits at index 19. Off-by-one here previously read field 21 (itrealvalue,
	// always 0 since Linux 2.6.17), which made every process report the same
	// tick value and silently disabled recycled-PID detection.
	fields := strings.Fields(string(data)[rparen+1:])
	if len(fields) < 20 {
		return ""
	}
	return fields[19]
}

// canonicalLockIdentity returns the physical identity used for the workspace
// lock. A path string is not authority: /repo and /alias-to-repo must contend
// for one lock. Resolve symlinks first, then prefer the device/inode pair
// (with the resolved path retained only as diagnostic/collision material).
func canonicalLockIdentity(root string) string {
	abs, err := filepath.Abs(root)
	if err != nil {
		abs = filepath.Clean(root)
	}
	resolved := abs
	if eval, err := filepath.EvalSymlinks(abs); err == nil {
		resolved = eval
	}
	if goruntime.GOOS == "windows" {
		resolved = strings.ToLower(resolved)
	}
	if info, err := os.Stat(resolved); err == nil {
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			return fmt.Sprintf("dev=%d ino=%d path=%s", st.Dev, st.Ino, resolved)
		}
	}
	return "path=" + resolved
}

// lockPath returns the workspace lock file path for root, shared by lock()
// and the Phase 4 recovery checks (which need to read a lock's liveness
// without acquiring it).
func lockPath(root, home string) string {
	sum := sha1.Sum([]byte(canonicalLockIdentity(root)))
	return filepath.Join(home, "locks", hex.EncodeToString(sum[:])+".lock")
}

func randomLockToken() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("fallback-%d-%d", os.Getpid(), time.Now().UTC().UnixNano())
	}
	return hex.EncodeToString(b)
}

func lock(root, home string) (func(), error) {
	dir := filepath.Join(home, "locks")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	p := lockPath(root, home)
	f, err := os.OpenFile(p, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	locked := false
	defer func() {
		if !locked {
			f.Close()
		}
	}()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return nil, fmt.Errorf("workspace locked by an in-flight governator run (lock %s)", p)
	}
	locked = true
	// If an old marker-only lock belongs to a live process, honor it even
	// though that process cannot hold our advisory flock. This preserves
	// recovery correctness across upgrades and also prevents a re-entrant lock
	// in this same process from deleting a lock it did not create.
	if isLiveLock(p) {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		locked = false
		return nil, fmt.Errorf("workspace locked by an in-flight governator run (lock %s)", p)
	}
	token := randomLockToken()
	body := fmt.Sprintf("%d %d %s %s", os.Getpid(), time.Now().UTC().UnixNano(), processStartTicks(os.Getpid()), token)
	if err := f.Truncate(0); err != nil {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		locked = false
		return nil, err
	}
	if _, err := f.Seek(0, 0); err != nil {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		locked = false
		return nil, err
	}
	if _, err := fmt.Fprint(f, body); err != nil {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		locked = false
		return nil, err
	}
	if err := f.Sync(); err != nil {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		locked = false
		return nil, err
	}
	return func() {
		remove := false
		if b, err := os.ReadFile(p); err == nil {
			parts := strings.Fields(strings.TrimSpace(string(b)))
			remove = len(parts) >= 4 && parts[3] == token
		}
		if remove {
			_ = os.Remove(p)
		}
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}

// isLiveLock reports whether an existing lock file points at a genuinely
// in-flight governator process. A lock is considered live only when:
//   - the holder PID exists (syscall.Kill(pid, 0) succeeds), AND
//   - on Linux, its /proc start ticks still match what the lock recorded, OR
//   - off Linux / when start ticks are unavailable, the lock was created
//     within lockStaleThreshold (a coarse but portable recycle guard).
//
// Any parse failure, dead PID, tick mismatch, or stale timestamp means the
// lock is reclaimable.
func isLiveLock(p string) bool {
	b, err := os.ReadFile(p)
	if err != nil {
		return false
	}
	parts := strings.Fields(strings.TrimSpace(string(b)))
	if len(parts) == 0 {
		return false
	}
	pid, err := strconv.Atoi(parts[0])
	if err != nil || pid <= 0 {
		return false
	}
	if syscall.Kill(pid, 0) != nil {
		return false
	}
	if len(parts) >= 3 && parts[2] != "" {
		return parts[2] == processStartTicks(pid)
	}
	if len(parts) >= 2 {
		if created, err := strconv.ParseInt(parts[1], 10, 64); err == nil {
			return time.Unix(0, created).Add(lockStaleThreshold).After(time.Now())
		}
	}
	// Old-format lock containing only a pid, held by a live process: trust it
	// (preserves prior behaviour for locks written before this change).
	return true
}

type stamp struct {
	Size  int64
	Mode  os.FileMode
	MTime int64
	Hash  string
}
type snapshot map[string]stamp

func fingerprint(root string) (snapshot, error) {
	out := snapshot{}
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, e := filepath.Rel(root, p)
		if e != nil {
			return e
		}
		rel = filepath.ToSlash(rel)
		if rel == ".git" || strings.HasPrefix(rel, ".git/") || rel == ".codegraph" || strings.HasPrefix(rel, ".codegraph/") {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if info.IsDir() {
			return nil
		}
		s := stamp{Size: info.Size(), Mode: info.Mode(), MTime: info.ModTime().UnixNano()}
		if info.Mode().IsRegular() {
			f, e := os.Open(p)
			if e != nil {
				return e
			}
			h := sha256.New()
			_, e = io.Copy(h, f)
			f.Close()
			if e != nil {
				return e
			}
			s.Hash = hex.EncodeToString(h.Sum(nil))
		}
		out[rel] = s
		return nil
	})
	return out, err
}

func writeFileNoFollow(path string, data []byte, perm os.FileMode) error {
	fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW, uint32(perm))
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return err
	}
	return f.Chmod(perm)
}

func protectedFingerprint(patterns []string) (snapshot, error) {
	out := snapshot{}
	for _, pattern := range patterns {
		matches := protectedpaths.Resolve(pattern)
		if len(matches) == 0 {
			out[protectedpaths.Expand(pattern)] = stamp{Hash: "MISSING"}
			continue
		}
		for _, p := range matches {
			info, statErr := os.Lstat(p)
			if statErr != nil {
				return nil, statErr
			}
			if info.IsDir() {
				s, walkErr := fingerprint(p)
				if walkErr != nil {
					return nil, walkErr
				}
				for rel, st := range s {
					out[p+"::"+rel] = st
				}
				continue
			}
			st := stamp{Size: info.Size(), Mode: info.Mode(), MTime: info.ModTime().UnixNano()}
			if info.Mode().IsRegular() {
				f, openErr := os.Open(p)
				if openErr != nil {
					return nil, openErr
				}
				h := sha256.New()
				_, copyErr := io.Copy(h, f)
				f.Close()
				if copyErr != nil {
					return nil, copyErr
				}
				st.Hash = hex.EncodeToString(h.Sum(nil))
			}
			out[p] = st
		}
	}
	return out, nil
}

func changes(a, b snapshot) (changed, deleted []string) {
	set := map[string]bool{}
	for k := range a {
		set[k] = true
	}
	for k := range b {
		set[k] = true
	}
	for k := range set {
		av, aok := a[k]
		bv, bok := b[k]
		if aok && !bok {
			deleted = append(deleted, k)
		} else if !aok || av != bv {
			changed = append(changed, k)
		}
	}
	sort.Strings(changed)
	sort.Strings(deleted)
	return
}

func glob(pattern, name string) bool {
	pattern = filepath.ToSlash(pattern)
	name = filepath.ToSlash(name)
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		if c == '*' {
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				b.WriteString(".*")
				i++
			} else {
				b.WriteString("[^/]*")
			}
		} else if c == '?' {
			b.WriteString("[^/]")
		} else {
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString("$")
	ok, _ := regexp.MatchString(b.String(), name)
	return ok
}
func matchesAny(ps []string, n string) bool {
	for _, p := range ps {
		if glob(p, n) {
			return true
		}
	}
	return false
}

func shell(ctx context.Context, dir, command string) (int, string, error) {
	registry, rerr := toolregistry.Load()
	if rerr != nil {
		return -1, "", fmt.Errorf("load trusted-tool registry: %w", rerr)
	}
	// Sol9 P0-6: every command this helper runs is a git invocation (or,
	// in runner.go's copy, a plain cp — prepending is a no-op for it). The
	// prior fix (Sol report attack 10 / P0-5) resolved git through the
	// trusted-tool registry but only ever handed bash a live PATH-directory
	// string to resolve "git" against at call time — a same-uid swap of
	// the enrolled git binary after this resolution and before bash's own
	// lookup would still run. Sealing the verified handle's exact bytes
	// into a private, immutable, 0500 copy (the same primitive
	// SealedExecutablePath gives structured validators for P0-5) and
	// prepending THAT directory closes the window: bash's PATH lookup can
	// only ever find the bytes verified here, never a path that could be
	// replaced out from under it. The handle itself is no longer needed
	// once the immutable copy exists.
	gitHandle, gerr := registry.ResolveHandle("git", "git", toolregistry.KindTrustedController)
	if gerr != nil {
		return -1, "", fmt.Errorf("resolve trusted git handle: %w", gerr)
	}
	sealedGit, gerr := gitHandle.SealedExecutablePath()
	_ = gitHandle.Close()
	if gerr != nil {
		return -1, "", fmt.Errorf("seal trusted git: %w", gerr)
	}
	defer sealedGit.Close()
	// Session 2 (post-v4 hardening plan item C) / Sol9 P0-6: bash itself is
	// the controller tool actually running this command string (including
	// every deterministic validator/formatter/linter a job contract
	// declares). It now launches from a held, verified descriptor
	// (/proc/self/fd/<n>, via Handle.CommandWith — the same fd-argv
	// mechanic enforce.Plan.Wrap uses for unshare/self-exec, Sol9
	// P0-1/P0-2) instead of a pathname exec.CommandContext would have to
	// re-resolve, so a same-uid swap of the enrolled bash binary between
	// verification and this exec has no effect on what actually runs.
	bashHandle, berr := registry.ResolveHandle("bash", "bash", toolregistry.KindTrustedController)
	if berr != nil {
		return -1, "", fmt.Errorf("resolve trusted bash handle: %w", berr)
	}
	defer bashHandle.Close()
	build := func(c context.Context, bin string, a []string) *exec.Cmd {
		if scope, ok := containment.ScopeFromContext(c); ok {
			return scope.Command(c, bin, a, dir)
		}
		cc := exec.CommandContext(c, bin, a...) // govratchet:exec-allow(production_launch_factory) -- bin is bashHandle's verified/sealed path, substituted by the caller
		cc.Dir = dir
		cc.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		return cc
	}
	cmd, err := bashHandle.CommandWith(ctx, []string{"--noprofile", "--norc", "-c", command}, build)
	if err != nil {
		return -1, "", err
	}
	frozen := controllerenv.Freeze()
	pathValue := filepath.Dir(sealedGit.Path)
	if basePath, ok := frozen.Lookup("PATH"); ok && basePath != "" {
		pathValue += string(os.PathListSeparator) + basePath
	}
	cmd.Env = frozen.With(map[string]string{"PATH": pathValue}).Values
	// Sol9 P1-4: re-verify the sealed git copy immediately before it can be
	// found through PATH below -- a private read-only copy is not
	// kernel-immutable, so this is the last point Governator can catch a
	// same-UID tamper before launch.
	if verr := sealedGit.Verify(); verr != nil {
		return -1, "", fmt.Errorf("verify sealed git before launch: %w", verr)
	}
	var out []byte
	if scope, ok := containment.ScopeFromContext(ctx); ok {
		var buf strings.Builder
		cmd.Stdout = &buf
		cmd.Stderr = &buf
		startErr := cmd.Start()
		if startErr == nil && cmd.Process != nil {
			scope.Started(cmd.Process.Pid)
		}
		if startErr != nil {
			return -1, buf.String(), startErr
		}
		err = cmd.Wait()
		out = []byte(buf.String())
	} else {
		out, err = cmd.CombinedOutput()
	}
	if ctx.Err() != nil && cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			return -1, string(out), err
		}
	}
	return code, string(out), nil
}

// shellStage runs command via bash -lc in dir like shell(), but through
// internal/stage's StageExecutor -- the one launch path every external
// executable stage (backend, validators, cleanup validators, graph
// provider, Assayer) shares (Sol redteam v7 S1 / RB3). Before this, a
// validator/cleanup-validator got only a descendant-owning containment
// scope (via containment.NewScope directly, with a scope name that was
// just runID+"-"+stage -- reused across every validator in one run, which
// StageExecutor's runID+stageID+nonce naming fixes) and none of the
// filesystem/network/credential envelope a governed backend gets.
//
// trustedToolDirs drives the structured-validator PATH policy (Sol9
// P0-5). When non-empty, the entries are private per-validator sealed
// directories populated with verified-bytes copies of exactly the tools
// the validator declared -- PATH is set to those directories ALONE,
// with no ambient base PATH and no auto-added git directory, so a
// validator declaring only "go" can no longer resolve python3/perl/curl/
// ssh/git/sh the way filepath.Dir(canonical) + base PATH let it before.
// When empty (legacy string validators, already marked
// validator_tools=Known:false in the identity), the pre-fix ambient
// behavior is preserved: PATH = gitDir + frozen base PATH.
func shellStage(ctx context.Context, runID, stageName, dir, command string, authority stageexec.StageAuthority, frozen ControllerEnvironment, trustedToolDirs []string, registry *toolregistry.Registry) (int, string, error, error) {
	if registry == nil {
		return -1, "", fmt.Errorf("controller tool registry is not frozen"), nil
	}
	gitIdentity, gerr := registry.Resolve("git", "git")
	if gerr != nil {
		return -1, "", fmt.Errorf("resolve trusted git: %w", gerr), nil
	}
	bashHandle, berr := registry.ResolveHandle("bash", "bash", toolregistry.KindTrustedController)
	if berr != nil {
		return -1, "", fmt.Errorf("resolve trusted bash handle: %w", berr), nil
	}
	defer bashHandle.Close()
	bashIdentity := bashHandle.Identity
	execID := stageexec.ExecutableIdentity{CanonicalPath: bashIdentity.CanonicalPath, SHA256: bashIdentity.SHA256}
	if err := frozen.Validate(); err != nil {
		return -1, "", err, nil
	}
	structured := len(trustedToolDirs) > 0
	var pathValue string
	if structured {
		// P0-5: structured validators get PATH = sealed dirs only. No
		// ambient base PATH, no auto-added git directory. A validator
		// that needs git must declare it explicitly.
		pathValue = strings.Join(trustedToolDirs, string(os.PathListSeparator))
	} else {
		pathParts := []string{filepath.Dir(gitIdentity.CanonicalPath)}
		if basePath, ok := frozen.Lookup("PATH"); ok && basePath != "" {
			pathParts = append(pathParts, basePath)
		}
		pathValue = strings.Join(pathParts, string(os.PathListSeparator))
	}
	stageEnv := frozen.With(map[string]string{"PATH": pathValue})
	readRoots := append([]string(nil), authority.ReadRoots...)
	if structured {
		// P0-5: sealed dirs (and their tool ELF closures, already merged
		// into authority.ReadRoots by the caller) are the only additional
		// read roots. The git directory is NOT added -- a structured
		// validator that wants git must declare it, at which point its
		// sealed copy + closure land in trustedToolDirs/ReadRoots like
		// any other declared tool.
		readRoots = append(readRoots, trustedToolDirs...)
	} else {
		readRoots = append(readRoots, filepath.Dir(gitIdentity.CanonicalPath))
	}
	authority.ReadRoots = readRoots
	res, err := stageexec.NewExecutor().Run(ctx, stageexec.StageSpec{
		RunID:            runID,
		StageID:          stageName,
		Executable:       execID,
		Arguments:        []string{"--noprofile", "--norc", "-c", command},
		WorkingDirectory: dir,
		Environment:      stageexec.FrozenEnvironment{Values: stageEnv.Values, Hash: stageEnv.Hash},
		NetworkPolicy:    authority.Network,
		CredentialPolicy: authority.Credentials,
		OutputLimit:      10 << 20,
		OutputCapture:    stageexec.CaptureRequiredComplete,
		DescendantPolicy: stageexec.DescendantPolicy{RequireStrong: authority.RequireStrongScope},
		Authority:        authority,
		ExecutableHandle: bashHandle,
	})
	out := res.Output
	var extinctionErr error
	if err != nil && !res.DescendantsGone {
		extinctionErr = err
		if out != "" && !strings.HasSuffix(out, "\n") {
			out += "\n"
		}
		out += "descendant containment: " + err.Error()
	}
	return res.ExitStatus, out, err, extinctionErr
}

func stagePathRoots(root string, paths []string) []string {
	if len(paths) == 0 {
		return nil
	}
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		if strings.TrimSpace(p) == "" {
			continue
		}
		if filepath.IsAbs(p) {
			out = append(out, filepath.Clean(p))
		} else {
			out = append(out, filepath.Join(root, filepath.FromSlash(p)))
		}
	}
	return out
}

func validatorAuthority(root string, spec *contracts.ValidatorSpec, writeable bool, requireStrong bool) stageexec.StageAuthority {
	authority := stageexec.StageAuthority{
		ReadRoots:          []string{root},
		Network:            stageexec.NetworkPolicyDenied,
		Credentials:        stageexec.CredentialPolicyNone,
		RequireStrongScope: requireStrong,
	}
	if spec == nil {
		return authority
	}
	authority.ReadRoots = append(authority.ReadRoots, stagePathRoots(root, spec.Files)...)
	authority.ReadRoots = append(authority.ReadRoots, stagePathRoots(root, spec.ReadRoots)...)
	authority.WriteRoots = append(authority.WriteRoots, stagePathRoots(root, spec.WriteRoots)...)
	if strings.TrimSpace(spec.Network) == string(stageexec.NetworkPolicyAllowed) {
		authority.Network = stageexec.NetworkPolicyAllowed
	}
	if strings.TrimSpace(spec.Credentials) == string(stageexec.CredentialPolicyDeclared) {
		authority.Credentials = stageexec.CredentialPolicyDeclared
	}
	if spec.RequireStrongScope {
		authority.RequireStrongScope = true
	}
	if !writeable {
		authority.WriteRoots = nil
	}
	return authority
}

func localReadRoots(cfg *contracts.LocalRunnerConfig) []string {
	if cfg == nil {
		return nil
	}
	return append([]string(nil), cfg.ReadRoots...)
}

func gitHead(root string) (string, error) {
	c, o, e := shell(context.Background(), root, "git rev-parse HEAD")
	if e == nil && c == 0 {
		return strings.TrimSpace(o), nil
	}
	if head, ferr := gitHeadFromFiles(root); ferr == nil {
		return head, nil
	}
	return "", fmt.Errorf("git rev-parse: %s", strings.TrimSpace(o))
}

func gitHeadFromFiles(root string) (string, error) {
	gitDir := filepath.Join(root, ".git")
	if data, err := os.ReadFile(gitDir); err == nil {
		line := strings.TrimSpace(string(data))
		if strings.HasPrefix(line, "gitdir:") {
			gitDir = strings.TrimSpace(strings.TrimPrefix(line, "gitdir:"))
			if !filepath.IsAbs(gitDir) {
				gitDir = filepath.Join(root, gitDir)
			}
		}
	}
	data, err := os.ReadFile(filepath.Join(gitDir, "HEAD"))
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(data))
	if strings.HasPrefix(value, "ref:") {
		ref := strings.TrimSpace(strings.TrimPrefix(value, "ref:"))
		data, err = os.ReadFile(filepath.Join(gitDir, filepath.FromSlash(ref)))
		if err != nil {
			return "", err
		}
		value = strings.TrimSpace(string(data))
	}
	if value == "" {
		return "", fmt.Errorf("empty HEAD")
	}
	return value, nil
}
func isGit(root string) bool {
	c, _, _ := shell(context.Background(), root, "git rev-parse --is-inside-work-tree")
	if c == 0 {
		return true
	}
	if _, err := os.Stat(filepath.Join(root, ".git")); err == nil {
		return true
	}
	return false
}

func validateNoLocalSymlinkEscape(root string) error {
	return filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel(root, p)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)
		if rel == ".git" || strings.HasPrefix(rel, ".git/") || rel == ".codegraph" || strings.HasPrefix(rel, ".codegraph/") {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("local containment: symlink/junction paths are not allowed in local worktrees: %s", rel)
		}
		info, statErr := d.Info()
		if statErr != nil {
			return statErr
		}
		mode := info.Mode()
		if !mode.IsRegular() && !mode.IsDir() {
			return fmt.Errorf("local containment: special files are not allowed in local worktrees: %s", rel)
		}
		return nil
	})
}

func appendRuntimePathScanViolation(violations []string, stage, work string) []string {
	if err := validateFinalWorktreeShape(work); err != nil {
		return append(violations, "runtime path containment "+stage+": "+err.Error())
	}
	return violations
}

// enforceContainment applies the Session 3 (Phase 2) risk-class containment
// policy, as re-grounded by Session 5 (Sol P0-3, report §9 attack 5):
// authorization for a "local" runner now comes from Governator's OWN
// externally enforced sandbox (enforce.Supported() — Landlock LSM + network
// namespace, applied outside the backend and independent of anything it
// claims about itself), never from a backend's declared or probe-attested
// native sandbox alone. The check runs before quota/workspace acquisition so
// a denied high-risk or medium-risk effectful run leaves no side effects.
//
// agent is the single Agent instance the caller already built for this run
// (via agents.New) — enforceContainment builds no Agent of its own. It
// resolves the backend binary itself (into a *agents.BackendExecutionHandle,
// Sol P0-6 / Session 3), but only when the backend declares a native sandbox
// worth recording attestation evidence for: authorization itself (Session 5)
// no longer depends on the backend's identity at all, only on whether this
// host can provide Governator's own externally enforced sandbox, so a
// backend that declares no native sandbox never needs to be resolvable (or
// even installed) just to be correctly denied or approved on host-capability
// grounds alone. enforce.Plan.Wrap (attached by the caller once it has a
// workspace path, below) needs no BackendExecutionHandle either — it wraps
// bin/args generically at the launch site.
//
// The returned handle, when non-nil, is the ONE resolution performed for
// this run — the caller (runOnce) must reuse it for execution identity and
// launch rather than resolving again; when nil, the caller resolves once,
// later, itself (the existing fallback already does this unconditionally
// before launch). This is what closes P0-6's "resolved twice" gap: exactly
// one of enforceContainment or its caller ever calls agents.ResolveHandle
// for a given run.
//
// The final bool return, requiresEnforcementWrap, tells the caller (runOnce,
// once it has a workspace path and BackendSpec to build one) whether it must
// construct and attach an enforce.Plan before launch: true exactly when this
// is a "local" runner that needed host containment and was not authorized by
// a signed override — the same condition already evaluated once here, not
// recomputed independently at the launch site.
func enforceContainment(ctx context.Context, db *sql.DB, c contracts.Contract, agent agents.Agent, cfg config.Config) (string, *agents.BackendExecutionHandle, bool, error) {
	enforceLocalEffectful := containment.LocalEffectfulTieringEnforced(cfg.Containment.LocalEffectfulTiering)
	if !containment.RequiresHostContainment(c, enforceLocalEffectful) {
		return "", nil, false, nil
	}
	nativeSandboxDeclared := agent.Capabilities().NativeSandbox
	requiresEnforcementWrap := c.EffectiveRunner() == "local" && !containment.VerifyOverride(c, cfg.Containment.OverridePublicKey)
	var attestationID string
	var handle *agents.BackendExecutionHandle
	// Sol P0-3 (Session 5): a fresh ledgered capability attestation is still
	// generated and recorded when the backend declares a native sandbox — it
	// remains useful probe-observed evidence and audit history — but its
	// outcome no longer gates authorization below. Only
	// containment.EnforcePolicy's externallyEnforced argument (Governator's
	// own sandbox, not the backend's self-report) does.
	if requiresEnforcementWrap && nativeSandboxDeclared {
		h, err := agents.ResolveHandle(ctx, cfg, agent)
		if err != nil {
			return "", nil, false, err
		}
		handle = h
		if id, aerr := attest.VerifyHighRiskNative(db, cfg, agent, handle.PathResolution, handle.Identity); aerr == nil {
			attestationID = id
		}
	}
	externallyEnforced := c.EffectiveRunner() == "local" && enforce.Supported()
	if err := containment.EnforcePolicy(c, externallyEnforced, cfg.Containment.OverridePublicKey, enforceLocalEffectful); err != nil {
		return "", nil, false, err
	}
	return attestationID, handle, requiresEnforcementWrap, nil
}

// requiresCompleteTranscript reports whether c may never be approved on an
// incomplete (capped or unverifiable) transcript: either the operator opted
// in explicitly (docker.require_complete_transcript, or local's equivalent
// require_complete_transcript for runner: local — Sol High 11) or the run is
// evidence-bearing by construction — a blocking assay's verdict gates the
// merge, so the audit trail behind that verdict must be whole. Checks both
// the contract-wide default and any per-artifact assays[] override (Sol
// audit finding #16) — a contract declaring blocking only per-artifact is
// just as evidence-bearing as one declaring it contract-wide.
func requiresCompleteTranscript(c contracts.Contract) bool {
	if c.Docker != nil && c.Docker.RequireCompleteTranscript {
		return true
	}
	if c.Local != nil && c.Local.RequireCompleteTranscript {
		return true
	}
	return c.Assay != nil && assayDeclaresBlocking(c.Assay)
}

// declaredCredentialPolicy is the declared-authority tier of the effect
// ledger's credential evidence (Sol9 P1-5): it reflects only what the
// contract asked for, never anything observed about actual credential
// access, which Governator's local/Docker containment has no interposition
// to witness (see ObservedCredentialAccess = "unavailable" at every call
// site).
func declaredCredentialPolicy(c contracts.Contract) string {
	if c.Docker != nil && len(c.Docker.CredentialMounts) > 0 {
		return "declared"
	}
	return "none"
}

// networkDenialMechanism names the applied-enforcement mechanism behind a
// deny verdict (Sol9 P1-5) -- Governator's only real local network denial
// today is process isolation via a network namespace, never a kernel-level
// per-attempt observation, so this stays constant across every deny case
// rather than implying finer-grained enforcement exists.
func networkDenialMechanism(planActive, allowNetwork bool) string {
	if planActive && !allowNetwork {
		return "isolated_namespace"
	}
	return ""
}

const workspaceCleanupTimeout = 2 * time.Minute

func destroyWorkspaceWithOutbox(db *sql.DB, runID string, rn runner.Runner, ws runner.Workspace, approved bool) {
	ctx, cancel := context.WithTimeout(context.Background(), workspaceCleanupTimeout)
	defer cancel()
	if err := rn.Destroy(ctx, ws, approved); err != nil {
		payload, _ := json.Marshal(workspaceDestroyPayload{
			Path: ws.Path, Root: ws.Root, Branch: ws.Branch, Git: ws.Git, Container: ws.Container, Approved: approved,
		})
		noteOperationalFailure(db, runID, opWorkspaceDestroy, err, string(payload))
	}
}

func remainingRunBudget(ctx context.Context) time.Duration {
	deadline, ok := ctx.Deadline()
	if !ok {
		return 0
	}
	remaining := time.Until(deadline)
	if remaining < 0 {
		return 0
	}
	return remaining
}

func stageTimeout(ctx context.Context, stage string) (context.Context, context.CancelFunc, error) {
	remaining := remainingRunBudget(ctx)
	if remaining <= 0 {
		cancelCtx, cancel := context.WithCancel(ctx)
		cancel()
		return cancelCtx, cancel, fmt.Errorf("run deadline exceeded before %s", stage)
	}
	stageCtx, cancel := context.WithTimeout(ctx, remaining)
	return stageCtx, cancel, nil
}

func effectiveTelemetryMode(c contracts.Contract) string {
	if c.TelemetryMode != "" {
		return c.TelemetryMode
	}
	if c.Budget.MaxTokens > 0 {
		return "strict"
	}
	return "advisory"
}

func telemetryViolations(c contracts.Contract, audit transcriptAudit) []string {
	mode := effectiveTelemetryMode(c)
	var out []string
	if c.Budget.MaxTokens > 0 && !audit.Usage.Available {
		switch mode {
		case "strict":
			out = append(out, "strict telemetry unavailable: token usage required for budget.max_tokens")
		case "estimated":
			// The quota reservation already used budget.max_tokens conservatively.
		case "advisory":
			// Notes only.
		}
	}
	return out
}

func recordValidatorEvidence(db *sql.DB, runID, command string, exitCode int, output, stage string) {
	if _, err := db.Exec(`INSERT INTO validators(run_id,command,exit_code,output,stage) VALUES(?,?,?,?,?)`, runID, command, exitCode, output, stage); err != nil {
		payload, _ := json.Marshal(validatorEvidencePayload{RunID: runID, Command: command, ExitCode: exitCode, Output: output, Stage: stage})
		noteOperationalFailure(db, runID, opValidatorEvidence, err, string(payload))
	}
}

func cleanupCanary(path string) error {
	var first error
	if err := os.Chmod(path, 0600); err != nil && !os.IsNotExist(err) {
		first = fmt.Errorf("chmod canary: %w", err)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		if retryErr := os.Remove(path); retryErr != nil && !os.IsNotExist(retryErr) {
			if first != nil {
				return fmt.Errorf("%v; remove canary after retry: %w", first, retryErr)
			}
			return fmt.Errorf("remove canary after retry: %w", retryErr)
		}
	}
	return first
}

func gitControlFingerprint(root string) (snapshot, error) {
	out := snapshot{}
	addFile := func(label, path string) error {
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			out[label] = stamp{Hash: "MISSING"}
			return nil
		}
		if err != nil {
			return err
		}
		st := stamp{Size: info.Size(), Mode: info.Mode(), MTime: info.ModTime().UnixNano()}
		if info.Mode().IsRegular() {
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			h := sha256.New()
			_, err = io.Copy(h, f)
			f.Close()
			if err != nil {
				return err
			}
			st.Hash = hex.EncodeToString(h.Sum(nil))
		}
		out[label] = st
		return nil
	}
	if err := addFile(".git", filepath.Join(root, ".git")); err != nil {
		return nil, err
	}
	// Sol §6 item 5: hooks and config are the shared control plane, not
	// per-worktree state. A linked worktree's --git-dir points at its
	// private worktrees/<name> directory, which has no hooks/config
	// subdirectory at all — joining onto it would silently fingerprint
	// nothing and let a hook mutation in the real (shared) .git/hooks pass
	// undetected. --git-common-dir always resolves to the shared root,
	// from either the main worktree or a linked one.
	code, gitDir, err := shell(context.Background(), root, "git rev-parse --git-common-dir")
	if err != nil || code != 0 {
		return out, nil
	}
	gitDir = strings.TrimSpace(gitDir)
	if !filepath.IsAbs(gitDir) {
		gitDir = filepath.Join(root, gitDir)
	}
	for _, rel := range []string{"config", "hooks"} {
		path := filepath.Join(gitDir, rel)
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			out["gitdir/"+rel] = stamp{Hash: "MISSING"}
			continue
		}
		if err != nil {
			return nil, err
		}
		if info.IsDir() {
			err = filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if info.IsDir() {
					return nil
				}
				r, _ := filepath.Rel(path, p)
				return addFile("gitdir/"+rel+"/"+filepath.ToSlash(r), p)
			})
			if err != nil {
				return nil, err
			}
			continue
		}
		if err := addFile("gitdir/"+rel, path); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// statusSummary renders porcelain=v2 entries as a compact, safe error
// string: Path is printed exactly as Git returned it (no shell-style
// unquoting was ever applied), so a hostile filename can't inject anything
// beyond its own bytes into this message (P1-9).
func statusSummary(entries []gitplumb.StatusEntry) string {
	parts := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.Kind == '2' {
			parts = append(parts, string(e.Kind)+" "+e.XY+" "+e.OrigPath+" -> "+e.Path)
			continue
		}
		parts = append(parts, string(e.Kind)+" "+e.XY+" "+e.Path)
	}
	return strings.Join(parts, "; ")
}

func requireCleanLiveRoot(ctx context.Context, root string) error {
	entries, err := gitplumb.StatusPorcelainV2(ctx, root)
	if err != nil {
		return err
	}
	if len(entries) > 0 {
		return fmt.Errorf("live root dirty before merge: %s", statusSummary(entries))
	}
	return nil
}

type finalStateMeasurement struct {
	work            snapshot
	changed         []string
	deleted         []string
	artifactRecords []observability.ArtifactRecord
	diff            string
}

func validateFinalWorktreeShape(root string) error {
	return filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel(root, p)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)
		if rel == ".git" || strings.HasPrefix(rel, ".git/") || rel == ".codegraph" || strings.HasPrefix(rel, ".codegraph/") {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink/junction path: %s", rel)
		}
		info, statErr := d.Info()
		if statErr != nil {
			return statErr
		}
		mode := info.Mode()
		if !mode.IsRegular() && !mode.IsDir() {
			return fmt.Errorf("special file path: %s", rel)
		}
		return nil
	})
}

func finalValidationMeasurement(ctx context.Context, home, root, work, runID string, git bool, c contracts.Contract, protectedPatterns []string, workBefore, liveBefore, protectedBefore, gitControlBefore snapshot) (finalStateMeasurement, []string) {
	var m finalStateMeasurement
	var violations []string
	if err := validateFinalWorktreeShape(work); err != nil {
		violations = append(violations, "final barrier worktree scan: "+err.Error())
	}
	workAfter, werr := fingerprint(work)
	liveAfter, lerr := fingerprint(root)
	protectedAfter, perr := protectedFingerprint(protectedPatterns)
	gitControlAfter, gcerr := gitControlFingerprint(work)
	if werr != nil {
		violations = append(violations, "final barrier worktree fingerprint: "+werr.Error())
	}
	if lerr != nil {
		violations = append(violations, "final barrier live fingerprint: "+lerr.Error())
	}
	if perr != nil {
		violations = append(violations, "final barrier protected fingerprint: "+perr.Error())
	}
	if gcerr != nil {
		violations = append(violations, "final barrier git control-plane fingerprint: "+gcerr.Error())
	} else if snapshotDigest(gitControlBefore) != snapshotDigest(gitControlAfter) {
		violations = append(violations, "final barrier git control-plane mutation")
	}
	if perr == nil {
		protectedChanged, protectedDeleted := changes(protectedBefore, protectedAfter)
		if len(protectedChanged)+len(protectedDeleted) > 0 {
			violations = append(violations, "final barrier protected path mutation: "+strings.Join(append(protectedChanged, protectedDeleted...), ","))
		}
	}
	if werr == nil {
		rawChanged, rawDeleted := changes(workBefore, workAfter)
		m.work = workAfter
		m.changed, m.deleted = filterSourceChanges(rawChanged, rawDeleted)
	}
	if lerr == nil {
		liveChanged, liveDeleted := changes(liveBefore, liveAfter)
		if len(liveChanged)+len(liveDeleted) > 0 {
			violations = append(violations, "final barrier out-of-worktree mutation: "+strings.Join(append(liveChanged, liveDeleted...), ","))
		}
	}
	artifactRecords, artifactViolations := collectProducedArtifacts(home, work, runID, c.Produces)
	m.artifactRecords = artifactRecords
	violations = append(violations, artifactViolations...)
	for _, p := range append(append([]string{}, m.changed...), m.deleted...) {
		if !matchesAny(c.Allowed.Write, p) && p != "RESULT.json" {
			violations = append(violations, "final barrier write outside allowlist: "+p)
		}
		if matchesAny(c.Forbidden.Paths, p) {
			violations = append(violations, "final barrier forbidden path: "+p)
		}
		if !policy.MatchesAny(c.Preflight.IntendedWrites, p) && p != "RESULT.json" {
			violations = append(violations, "final barrier write outside intended_writes: "+p)
		}
	}
	if len(m.changed)+len(m.deleted) > c.Budget.MaxFilesChanged {
		violations = append(violations, "final barrier max_files_changed exceeded")
	}
	if len(m.deleted) > c.Budget.MaxDeleted {
		violations = append(violations, "final barrier max_deleted exceeded")
	}
	metrics := measureDiff(root, work, git, workBefore, m.changed, m.deleted)
	if metrics.Lines > c.Budget.MaxLinesChanged {
		violations = append(violations, fmt.Sprintf("final barrier max_lines_changed exceeded: %d > %d", metrics.Lines, c.Budget.MaxLinesChanged))
	}
	if metrics.NewFiles > c.Budget.MaxNewFiles {
		violations = append(violations, fmt.Sprintf("final barrier max_new_files exceeded: %d > %d", metrics.NewFiles, c.Budget.MaxNewFiles))
	}
	if werr == nil {
		for _, p := range c.Success.RequiredFiles {
			found := false
			for n := range workAfter {
				if glob(p, n) {
					found = true
					break
				}
			}
			if !found {
				violations = append(violations, "final barrier required file missing: "+p)
			}
		}
	}
	m.diff = workspaceDiff(root, work, git, m.changed, m.deleted)
	return m, violations
}

func artifactRecordsDigest(records []observability.ArtifactRecord) string {
	sorted := append([]observability.ArtifactRecord(nil), records...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Name == sorted[j].Name {
			return sorted[i].Path < sorted[j].Path
		}
		return sorted[i].Name < sorted[j].Name
	})
	h := sha256.New()
	for _, r := range sorted {
		h.Write([]byte(r.Name))
		h.Write([]byte{0})
		h.Write([]byte(r.SHA256))
		h.Write([]byte{0})
		h.Write([]byte(strconv.FormatInt(r.Bytes, 10)))
		h.Write([]byte{0})
		h.Write([]byte(strconv.FormatBool(r.SchemaOK)))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func finalStateDeltaViolations(approved, final finalStateMeasurement) []string {
	var violations []string
	if snapshotDigest(approved.work) != snapshotDigest(final.work) {
		violations = append(violations, "final barrier worktree changed after approved measurement")
	}
	if strings.Join(approved.changed, "\\x00") != strings.Join(final.changed, "\\x00") || strings.Join(approved.deleted, "\\x00") != strings.Join(final.deleted, "\\x00") {
		violations = append(violations, "final barrier change set changed after approved measurement")
	}
	if artifactRecordsDigest(approved.artifactRecords) != artifactRecordsDigest(final.artifactRecords) {
		violations = append(violations, "final barrier artifacts changed after approved measurement")
	}
	return violations
}

// approvedMergeResult carries the built-and-verified tree plus the
// isolated gitplumb session used to build it, so the caller can commit it
// and, only then, sync the live root's working tree and real index.
type approvedMergeResult struct {
	session   *gitplumb.Session
	mergeTree string
}

// buildApprovedMergeTree is the Sol redteam v4 S1 replacement for the old
// gitAddExactPaths/verifyOnlyApprovedGitChanges pair (P0-1/P0-2/P1-6/P1-9).
// It never touches the real .git/index and never invokes `git add` or
// `git commit` in repository context, so no hook, filter, or signing
// program ever runs with Governator's authority. It builds the merge tree
// in an isolated temporary index seeded from head's tree, hashing each
// approved changed file directly off work's filesystem (--no-filters
// --literally: P0-1's clean-filter vector) and staging it under its exact,
// literal path (a cacheinfo entry, never a pathspec: P0-2/P1-9's
// filename-as-magic vector) — then independently verifies the result: the
// tree's diff from baseline must be exactly the approved change set, no
// more and no less, and .governator/.codegraph must be completely absent
// from the final tree regardless of what the diff says (never skip
// verification for Governator's own internal paths — that skip is exactly
// what P0-2 exploited). The caller must Close() the returned session's
// session field once done (commitAndSyncRoot does this).
func buildApprovedMergeTree(ctx context.Context, root, work, head string, changed, deleted []string) (*approvedMergeResult, error) {
	sess, err := gitplumb.NewSession(ctx, root)
	if err != nil {
		return nil, fmt.Errorf("git merge: open plumbing session: %w", err)
	}
	baseline, err := sess.RevParseTree(ctx, head)
	if err != nil {
		sess.Close()
		return nil, fmt.Errorf("git merge: resolve baseline tree: %w", err)
	}
	if err := sess.ReadTreeIntoIndex(ctx, baseline); err != nil {
		sess.Close()
		return nil, fmt.Errorf("git merge: seed isolated index: %w", err)
	}
	approved := map[string]bool{}
	for _, p := range changed {
		if p == "" {
			continue
		}
		approved[p] = true
		diskPath := filepath.Join(work, filepath.FromSlash(p))
		if err := sess.UpdateIndexAddFile(ctx, diskPath, p); err != nil {
			sess.Close()
			return nil, fmt.Errorf("git merge: stage %s: %w", p, err)
		}
	}
	for _, p := range deleted {
		if p == "" {
			continue
		}
		approved[p] = true
		if err := sess.UpdateIndexRemove(ctx, p); err != nil {
			sess.Close()
			return nil, fmt.Errorf("git merge: unstage %s: %w", p, err)
		}
	}
	mergeTree, err := sess.WriteTree(ctx)
	if err != nil {
		sess.Close()
		return nil, fmt.Errorf("git merge: write-tree: %w", err)
	}

	diff, err := sess.DiffTreePaths(ctx, baseline, mergeTree)
	if err != nil {
		sess.Close()
		return nil, fmt.Errorf("git merge: diff baseline/merge tree: %w", err)
	}
	for _, p := range diff {
		if !approved[p] {
			sess.Close()
			return nil, fmt.Errorf("git merge: unapproved tree diff: %s", p)
		}
	}
	finalPaths, err := sess.LsTreePaths(ctx, mergeTree)
	if err != nil {
		sess.Close()
		return nil, fmt.Errorf("git merge: list final tree: %w", err)
	}
	for _, p := range finalPaths {
		if isGovernatorInternalPath(p) || p == ".codegraph" || strings.HasPrefix(p, ".codegraph/") {
			sess.Close()
			return nil, fmt.Errorf("git merge: internal path present in final tree: %s", p)
		}
	}
	return &approvedMergeResult{session: sess, mergeTree: mergeTree}, nil
}

// commitAndSyncRoot commits result's verified tree as a child of head,
// atomically advances root's HEAD (compare-and-swap against head — P1-6:
// nothing else may have moved the branch since the pre-run measurement),
// re-verifies the landed commit's tree matches exactly what was approved,
// then materializes the change set into root's actual working directory
// and real index. The working-tree sync is a plain byte copy (never `git
// checkout`/`read-tree -u`), so no clean/smudge filter runs on the way
// back out to disk either. Always closes result's session, even on error.
func commitAndSyncRoot(ctx context.Context, result *approvedMergeResult, root, work, head, message string, changed, deleted []string) (string, error) {
	defer result.session.Close()
	commit, err := result.session.CommitTree(ctx, result.mergeTree, head, message)
	if err != nil {
		return "", fmt.Errorf("git merge: commit-tree: %w", err)
	}
	if err := result.session.UpdateRefCAS(ctx, root, "HEAD", commit, head); err != nil {
		return "", fmt.Errorf("git merge: update-ref: %w", err)
	}
	if err := result.session.RequireLooseObjectInGitDir(result.mergeTree); err != nil {
		return "", fmt.Errorf("git merge: verify tree object database: %w", err)
	}
	if err := result.session.RequireLooseObjectInGitDir(commit); err != nil {
		return "", fmt.Errorf("git merge: verify commit object database: %w", err)
	}
	verifyTree, err := result.session.RevParseTree(ctx, commit)
	if err != nil {
		return "", fmt.Errorf("git merge: re-verify commit tree: %w", err)
	}
	if verifyTree != result.mergeTree {
		return "", fmt.Errorf("git merge: committed tree %s does not match approved tree %s", verifyTree, result.mergeTree)
	}
	for _, p := range changed {
		if p == "" {
			continue
		}
		src := filepath.Join(work, filepath.FromSlash(p))
		dst := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
			return "", fmt.Errorf("git merge: sync %s: %w", p, err)
		}
		if err := copyFile(src, dst); err != nil {
			return "", fmt.Errorf("git merge: sync %s: %w", p, err)
		}
	}
	for _, p := range deleted {
		if p == "" {
			continue
		}
		if err := os.Remove(filepath.Join(root, filepath.FromSlash(p))); err != nil && !os.IsNotExist(err) {
			return "", fmt.Errorf("git merge: remove %s: %w", p, err)
		}
	}
	if err := result.session.SyncRealIndex(ctx, root, result.mergeTree); err != nil {
		return "", fmt.Errorf("git merge: sync real index: %w", err)
	}
	return commit, nil
}

func preserveQuarantineWorktree(ctx context.Context, work, head, runID string) (string, error) {
	sess, err := gitplumb.NewSession(ctx, work)
	if err != nil {
		return "", fmt.Errorf("git quarantine: open plumbing session: %w", err)
	}
	defer sess.Close()
	baseline, err := sess.RevParseTree(ctx, head)
	if err != nil {
		return "", fmt.Errorf("git quarantine: resolve baseline tree: %w", err)
	}
	if err := sess.ReadTreeIntoIndex(ctx, baseline); err != nil {
		return "", fmt.Errorf("git quarantine: seed isolated index: %w", err)
	}
	entries, err := gitplumb.StatusPorcelainV2(ctx, work)
	if err != nil {
		return "", fmt.Errorf("git quarantine: status: %w", err)
	}
	seen := map[string]bool{}
	var paths []string
	addPath := func(p string) {
		if p == "" || seen[p] || isGovernatorInternalPath(p) || p == ".codegraph" || strings.HasPrefix(p, ".codegraph/") {
			return
		}
		seen[p] = true
		paths = append(paths, p)
	}
	for _, e := range entries {
		if e.Kind == '2' && e.OrigPath != "" && e.OrigPath != e.Path {
			addPath(e.OrigPath)
		}
		addPath(e.Path)
	}
	sort.Strings(paths)
	for _, p := range paths {
		disk := filepath.Join(work, filepath.FromSlash(p))
		info, statErr := os.Stat(disk)
		switch {
		case statErr == nil && info.Mode().IsRegular():
			if err := sess.UpdateIndexAddFile(ctx, disk, p); err != nil {
				return "", fmt.Errorf("git quarantine: stage %s: %w", p, err)
			}
		case statErr == nil && info.IsDir():
			if err := filepath.WalkDir(disk, func(child string, d os.DirEntry, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}
				if d.IsDir() {
					return nil
				}
				info, err := d.Info()
				if err != nil {
					return err
				}
				if !info.Mode().IsRegular() {
					return fmt.Errorf("unsupported non-regular path %s", child)
				}
				rel, err := filepath.Rel(work, child)
				if err != nil {
					return err
				}
				literal := filepath.ToSlash(rel)
				if isGovernatorInternalPath(literal) || literal == ".codegraph" || strings.HasPrefix(literal, ".codegraph/") {
					return nil
				}
				return sess.UpdateIndexAddFile(ctx, child, literal)
			}); err != nil {
				return "", fmt.Errorf("git quarantine: stage directory %s: %w", p, err)
			}
		case statErr == nil:
			return "", fmt.Errorf("git quarantine: unsupported non-regular path %s", p)
		case os.IsNotExist(statErr):
			if err := sess.UpdateIndexRemove(ctx, p); err != nil {
				return "", fmt.Errorf("git quarantine: remove %s: %w", p, err)
			}
		default:
			return "", fmt.Errorf("git quarantine: stat %s: %w", p, statErr)
		}
	}
	tree, err := sess.WriteTree(ctx)
	if err != nil {
		return "", fmt.Errorf("git quarantine: write-tree: %w", err)
	}
	commit, err := sess.CommitTree(ctx, tree, head, "Quarantined Governator run "+runID+"\n\nGov-Run: "+runID+"\n")
	if err != nil {
		return "", fmt.Errorf("git quarantine: commit-tree: %w", err)
	}
	if err := sess.RequireLooseObjectInGitDir(tree); err != nil {
		return "", fmt.Errorf("git quarantine: verify tree object database: %w", err)
	}
	if err := sess.RequireLooseObjectInGitDir(commit); err != nil {
		return "", fmt.Errorf("git quarantine: verify commit object database: %w", err)
	}
	if err := sess.UpdateRefCAS(ctx, work, "HEAD", commit, head); err != nil {
		return "", fmt.Errorf("git quarantine: update-ref: %w", err)
	}
	return commit, nil
}

func rollbackLiveRoot(ctx context.Context, root, previousHead string, before snapshot, mergePaths []string) error {
	if code, out, err := shell(ctx, root, "git reset --hard "+shQuote(previousHead)); err != nil || code != 0 {
		return fmt.Errorf("rollback reset --hard: %s", strings.TrimSpace(out))
	}
	seen := map[string]bool{}
	for _, p := range mergePaths {
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		// Clean only the paths this Governator merge was about to land; never
		// run a broad git clean over the operator's repository.
		_, _, _ = shell(ctx, root, "git clean -fd -- "+shQuote(p))
	}
	entries, err := gitplumb.StatusPorcelainV2(ctx, root)
	if err != nil {
		return err
	}
	if len(entries) > 0 {
		return fmt.Errorf("rollback left live root dirty: %s", statusSummary(entries))
	}
	after, err := fingerprint(root)
	if err != nil {
		return fmt.Errorf("rollback fingerprint: %w", err)
	}
	if snapshotDigest(after) != snapshotDigest(before) {
		return errors.New("rollback fingerprint mismatch")
	}
	return nil
}

func shQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }

func workspaceDiff(root, work string, git bool, changed, deleted []string) string {
	if git {
		_, o, _ := shell(context.Background(), work, "git diff --binary --no-ext-diff HEAD; git ls-files --others --exclude-standard | grep -v '^.codegraph/' | sed 's/^/UNTRACKED /'")
		return o
	}
	var b strings.Builder
	for _, p := range changed {
		fmt.Fprintf(&b, "CHANGED %s\n", p)
	}
	for _, p := range deleted {
		fmt.Fprintf(&b, "DELETED %s\n", p)
	}
	return b.String()
}

var secrets = []*regexp.Regexp{
	regexp.MustCompile(`sk-[A-Za-z0-9_-]{8,}`), regexp.MustCompile(`AKIA[A-Z0-9]{12,}`),
	regexp.MustCompile(`(?i)Bearer[[:space:]]+[A-Za-z0-9._-]+`),
	regexp.MustCompile(`(?im)^[A-Z0-9_]*(KEY|TOKEN|SECRET|PASSWORD)[A-Z0-9_]*=.*$`),
	regexp.MustCompile(`(?s)-----BEGIN [^-]+-----.*?-----END [^-]+-----`),
}

func commandMatches(pattern, command string) bool {
	var b strings.Builder
	// (?s) makes '.' span newlines: allowed.execute wildcards must match
	// real multi-line backend commands (e.g. heredocs), not just one line.
	b.WriteString("(?s)^")
	for _, c := range pattern {
		if c == '*' {
			b.WriteString(".*")
		} else if c == '?' {
			b.WriteString(".")
		} else {
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString("$")
	ok, _ := regexp.MatchString(b.String(), command)
	return ok
}

type transcriptAudit struct {
	Violations      []string
	Commands        []string
	CostUSD         float64
	CostAvailable   bool
	CostUnavailable bool
	Usage           observability.TokenUsage
	ToolCalls       int
	TranscriptBytes int64
	// ConformanceSchemaVersion (Sol3 P1.8, finding #15) is Governator's own
	// versioned transcript-sequence-conformance schema this run was checked
	// against — see transcriptConformanceSchemaVersion. Recorded even when
	// empty protectedPatterns/format make every conformance check a no-op,
	// so the evidence trail always states which schema generation produced
	// this audit.
	ConformanceSchemaVersion string
	// RuleViolations (Phase 6) is every hit from the temporal rule engine —
	// both the blocking (deny) kind, which is also folded into Violations
	// above, and the advisory (flag) kind, which is not. Callers ledger the
	// full list via observability.RecordPolicyRuleEvents regardless of
	// verdict, so an advisory flag stays visible for operator review even
	// though it never changed this run's outcome.
	RuleViolations []policy.RuleViolation
}

func transcriptCommand(format string, value map[string]any) string {
	getCommand := func(container any) string {
		input, _ := container.(map[string]any)
		command, _ := input["command"].(string)
		return command
	}
	typeName, _ := value["type"].(string)
	switch format {
	case agents.TranscriptClaude, agents.TranscriptGLM:
		name, _ := value["name"].(string)
		if typeName == "tool_use" && strings.EqualFold(name, "bash") {
			return getCommand(value["input"])
		}
	case agents.TranscriptCodex:
		if typeName == "command_execution" {
			command, _ := value["command"].(string)
			return command
		}
	case agents.TranscriptOpenCode:
		tool, _ := value["tool"].(string)
		name, _ := value["name"].(string)
		if strings.EqualFold(tool, "bash") || strings.EqualFold(name, "bash") {
			if command := getCommand(value["input"]); command != "" {
				return command
			}
			if state, ok := value["state"].(map[string]any); ok {
				return getCommand(state["input"])
			}
		}
	case agents.TranscriptPi:
		tool, _ := value["toolName"].(string)
		if tool == "" {
			tool, _ = value["tool_name"].(string)
		}
		if strings.EqualFold(tool, "bash") {
			if command := getCommand(value["args"]); command != "" {
				return command
			}
			return getCommand(value["input"])
		}
	}
	return ""
}

// transcriptResultText extracts the plain-text payload of an Anthropic-style
// tool_result content field, which is either a bare string or a list of
// content blocks ({"type":"text","text":"..."}). Used only to feed the
// starter rule set's injection-marker scan (policy.LooksLikeInjection) — the
// text is read, never interpreted or executed.
func transcriptResultText(content any) string {
	switch v := content.(type) {
	case string:
		return v
	case []any:
		var parts []string
		for _, item := range v {
			block, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if text, ok := block["text"].(string); ok {
				parts = append(parts, text)
			}
		}
		return strings.Join(parts, "\n")
	}
	return ""
}

// transcriptEvent extracts zero or more Phase 6 (Session 6, Sol High 12: the
// normalized backend event protocol) policy.Event nodes from one transcript
// line, per format:
//
//   - Claude/GLM transcripts carry explicit Anthropic-style content blocks
//     (tool_use: name+input; tool_result: content) so every tool call and
//     its output classify directly via policy.ClassifyEvent /
//     policy.ToolOutputEvent — full coverage, including EventToolOutput.
//   - OpenCode/Pi expose a generic tool-name+input shape (the same shape
//     transcriptCommand already mined for bash extraction alone); Session 6
//     generalizes that to classify ANY tool call via policy.ClassifyEvent,
//     giving these formats real read/write/exec/network coverage whenever
//     the backend's own tool names match the classifier's maps. Neither
//     format exposes tool-result *text* the way Claude/GLM's tool_result
//     blocks do, so no EventToolOutput is ever produced for them.
//   - Codex's JSON stream has no generic tool-call schema this codebase
//     parses at all — only command_execution (shell) — so it falls back to
//     the exec-only event already available from command (transcriptCommand's
//     extraction, reused rather than recomputed).
//
// policy.formatEventCoverage declares exactly this truth so
// policy.UnenforceableRules can flag/block (rather than silently skip) a
// temporal rule that needs an event kind a format can't supply — see
// auditTranscript's Phase 6 section below.
func transcriptEvent(format string, value map[string]any, seq int, command string) []policy.Event {
	typeName, _ := value["type"].(string)
	switch format {
	case agents.TranscriptClaude, agents.TranscriptGLM:
		switch typeName {
		case "tool_use":
			name, _ := value["name"].(string)
			input, _ := value["input"].(map[string]any)
			return []policy.Event{policy.ClassifyEvent(seq, name, input)}
		case "tool_result":
			if text := transcriptResultText(value["content"]); text != "" {
				return []policy.Event{policy.ToolOutputEvent(seq, "tool_result", text)}
			}
		}
		return nil
	case agents.TranscriptOpenCode:
		tool, _ := value["tool"].(string)
		if tool == "" {
			tool, _ = value["name"].(string)
		}
		if tool == "" {
			return nil
		}
		input, _ := value["input"].(map[string]any)
		if input == nil {
			if state, ok := value["state"].(map[string]any); ok {
				input, _ = state["input"].(map[string]any)
			}
		}
		return []policy.Event{policy.ClassifyEvent(seq, tool, input)}
	case agents.TranscriptPi:
		tool, _ := value["toolName"].(string)
		if tool == "" {
			tool, _ = value["tool_name"].(string)
		}
		if tool == "" {
			return nil
		}
		input, _ := value["args"].(map[string]any)
		if input == nil {
			input, _ = value["input"].(map[string]any)
		}
		return []policy.Event{policy.ClassifyEvent(seq, tool, input)}
	default:
		if command != "" {
			return []policy.Event{policy.ClassifyEvent(seq, "bash", map[string]any{"command": command})}
		}
		return nil
	}
}

// transcriptTail returns the last maxBytes of a transcript file as a string,
// for infrastructure-failure classification (Session 2). Infra signatures
// (rate-limit strings, auth errors) appear in the backend's stderr tail, so
// only the tail is matched — not the whole transcript — keeping the classifier
// cheap and focused on launch/serve-time failures rather than mid-run noise.
// A missing or unreadable transcript yields "" (classify as non-infra).
func transcriptTail(path string, maxBytes int64) string {
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}
	size := info.Size()
	if size <= maxBytes {
		data, err := os.ReadFile(path)
		if err != nil {
			return ""
		}
		return string(data)
	}
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	if _, err := f.Seek(size-maxBytes, 0); err != nil {
		return ""
	}
	buf := make([]byte, maxBytes)
	n, _ := f.Read(buf)
	return string(buf[:n])
}

// relUnderWork returns subject's path relative to work (forward-slashed) and
// true when subject is an absolute path that actually falls under work; it
// returns ("", false) for anything else (relative subjects, commands, URLs,
// or absolute paths outside the worktree), so callers can leave those
// untouched.
func relUnderWork(work, subject string) (string, bool) {
	if work == "" || subject == "" || !filepath.IsAbs(subject) {
		return "", false
	}
	rel, err := filepath.Rel(work, subject)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return "", false
	}
	return filepath.ToSlash(rel), true
}

func allowedStartupNotice(format, line string) bool {
	trimmed := strings.TrimSpace(line)
	return format == agents.TranscriptCodex && trimmed == "Reading additional input from stdin..."
}

func recognizedTranscriptEvent(format string, v any) bool {
	m, ok := v.(map[string]any)
	if !ok {
		if items, ok := v.([]any); ok {
			for _, item := range items {
				if recognizedTranscriptEvent(format, item) {
					return true
				}
			}
		}
		return false
	}
	typeName, _ := m["type"].(string)
	switch format {
	case agents.TranscriptClaude, agents.TranscriptGLM:
		if typeName == "tool_use" || typeName == "tool_result" || typeName == "result" || typeName == "message_start" || typeName == "message_stop" {
			return true
		}
	case agents.TranscriptCodex:
		if strings.HasPrefix(typeName, "item.") || typeName == "command_execution" || typeName == "result" || typeName == "agent_message" || typeName == "turn.completed" {
			return true
		}
	case agents.TranscriptOpenCode:
		if typeName == "tool" || typeName == "result" || typeName == "message" || m["tool"] != nil || m["name"] != nil {
			return true
		}
	case agents.TranscriptPi:
		if strings.HasPrefix(typeName, "tool_execution") || typeName == "result" || typeName == "done" || m["toolName"] != nil || m["tool_name"] != nil {
			return true
		}
	}
	for _, child := range m {
		if recognizedTranscriptEvent(format, child) {
			return true
		}
	}
	return false
}

func auditTranscript(path, format, work string, c contracts.Contract, protectedPatterns []string, unenforceableRuleAction, transcriptConformanceAction string) transcriptAudit {
	data, err := os.ReadFile(path)
	if err != nil {
		return transcriptAudit{Violations: []string{"transcript audit: " + err.Error()}, CostUnavailable: true}
	}
	audit := transcriptAudit{TranscriptBytes: int64(len(data)), ConformanceSchemaVersion: transcriptConformanceSchemaVersion}
	usage := newUsageAccumulator()
	conf := newTranscriptConformanceState(format)
	known := map[string]bool{
		agents.TranscriptClaude: true, agents.TranscriptCodex: true,
		agents.TranscriptGLM: true, agents.TranscriptOpenCode: true,
		agents.TranscriptPi: true,
	}
	if !known[format] {
		audit.CostUnavailable = true
	}
	var events []policy.Event
	eventSeq := 0
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case []any:
			for _, item := range x {
				walk(item)
			}
		case map[string]any:
			conf.observeNode(x)
			command := transcriptCommand(format, x)
			if command != "" {
				audit.Commands = append(audit.Commands, command)
			}
			nodeEvents := transcriptEvent(format, x, eventSeq, command)
			for _, e := range nodeEvents {
				events = append(events, e)
				eventSeq++
			}
			for _, key := range []string{"total_cost_usd", "cost_usd"} {
				if cost, ok := x[key].(float64); ok {
					audit.CostAvailable = true
					if cost > audit.CostUSD {
						audit.CostUSD = cost
					}
				}
			}
			for _, item := range x {
				walk(item)
			}
		}
	}
	sawValidJSON := false
	sawRecognizedEvent := false
	startupLines := 0
	startupBytes := 0
	for lineNumber, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var v any
		if err := json.Unmarshal([]byte(line), &v); err != nil {
			if sawValidJSON {
				audit.Violations = append(audit.Violations,
					fmt.Sprintf("transcript audit: malformed JSON on line %d", lineNumber+1))
				continue
			}
			startupLines++
			startupBytes += len(line)
			if startupLines > 3 || startupBytes > 512 || !allowedStartupNotice(format, line) {
				audit.Violations = append(audit.Violations,
					fmt.Sprintf("TRANSCRIPT_FORMAT_INVALID: unrecognized non-JSON startup line %d", lineNumber+1))
			}
			continue
		}
		sawValidJSON = true
		if recognizedTranscriptEvent(format, v) {
			sawRecognizedEvent = true
		}
		if m, ok := v.(map[string]any); ok {
			conf.observeLine(m)
		}
		usage.walk(format, v)
		walk(v)
	}
	if known[format] {
		if !sawValidJSON {
			audit.Violations = append(audit.Violations, "TRANSCRIPT_FORMAT_INVALID: no valid JSON events")
		} else if !sawRecognizedEvent {
			audit.Violations = append(audit.Violations, "TRANSCRIPT_FORMAT_INVALID: no recognizable "+format+" events")
		}
	}
	audit.Usage, audit.ToolCalls = usage.result()
	if !audit.CostAvailable {
		audit.CostUnavailable = true
	}
	if c.Budget.MaxTokens > 0 && audit.Usage.Available && audit.Usage.TotalTokens > int64(c.Budget.MaxTokens) {
		audit.Violations = append(audit.Violations, fmt.Sprintf("max_tokens exceeded: %d > %d", audit.Usage.TotalTokens, c.Budget.MaxTokens))
	}
	if len(audit.Commands) > c.Budget.MaxCommands {
		audit.Violations = append(audit.Violations, "max_commands exceeded")
	}
	for _, command := range audit.Commands {
		normalized := policy.NormalizeShellCommand(command)
		if class := policy.ClassifyShellCommand(normalized, false); class != nil {
			audit.Violations = append(audit.Violations, fmt.Sprintf("destructive command classified as %s %s: %s", class.Verb, class.Resource, command))
		}
		allowed := false
		for _, pattern := range c.Allowed.Execute {
			if commandMatches(pattern, normalized) || commandMatches(pattern, command) {
				allowed = true
				break
			}
		}
		if !allowed {
			audit.Violations = append(audit.Violations, "command outside allowlist: "+command)
		}
		for _, forbidden := range c.Forbidden.Commands {
			if strings.Contains(normalized, forbidden) || strings.Contains(command, forbidden) {
				audit.Violations = append(audit.Violations, "forbidden command: "+command)
				break
			}
		}
	}
	lower := strings.ToLower(string(data))
	for _, phrase := range []string{"while i'm here", "while i’m here", "i'll also refactor", "i’ll also refactor", "inspect the broader project"} {
		if strings.Contains(lower, phrase) {
			audit.Violations = append(audit.Violations, "scope-expansion tripwire: "+phrase)
		}
	}
	// Phase 6: run the starter temporal rule set over this run's event graph.
	// secretPatterns = the operator's global protected-path manifest plus
	// this contract's own forbidden.paths; scopePatterns = this contract's
	// declared allowed.read. A deny-verdict hit is a real violation (folds
	// into audit.Violations like any other policy breach); a flag-verdict hit
	// stays advisory (RuleViolations only — the caller ledgers it but it never
	// changes this run's outcome, same posture as an assay advisory verdict).
	secretPatterns := append(append([]string{}, protectedPatterns...), c.Forbidden.Paths...)
	// Real agent transcripts (Claude's Read/Write tool_use blocks) always
	// carry absolute file_path values, but allowed.read/forbidden.paths are
	// documented and validated as repository-relative patterns (see
	// docs/contracts.md). Rewriting a read/write Subject to its
	// worktree-relative form — but only when it actually falls under this
	// run's disposable worktree — lets rule 2 (out-of-scope-read-precedes-
	// write) match real transcripts correctly, while leaving rule 1 (secret-
	// precedes-network) unaffected: global protected paths and any operator
	// secret glob live outside the worktree, so they never take this branch
	// and keep matching the raw absolute Subject exactly as before.
	scopedEvents := events
	if work != "" {
		scopedEvents = make([]policy.Event, len(events))
		copy(scopedEvents, events)
		for i, e := range scopedEvents {
			if e.Kind != policy.EventRead && e.Kind != policy.EventWrite {
				continue
			}
			if rel, ok := relUnderWork(work, e.Subject); ok {
				e.Subject = rel
				scopedEvents[i] = e
			}
		}
	}
	audit.RuleViolations = policy.EvaluateTemporalRules(scopedEvents, secretPatterns, c.Allowed.Read)
	// Session 6 (Sol High 12): a starter rule that cannot possibly fire for
	// this backend's transcript format (policy.UnenforceableRules — e.g.
	// Codex's exec-only event coverage) must never stay silent just because
	// it never fired; that silence is the exact coverage gap the finding
	// described ("do not advertise a temporal rule as cross-backend until
	// every supported adapter supplies its required event types"). Recorded
	// as a RuleViolation like any other rule outcome — advisory (RuleFlag,
	// the default) unless doctrine.unenforceable_rule_action is "block", in
	// which case it folds into audit.Violations via the same RuleDeny path
	// below as a real policy rule violation, for operators who'd rather fail
	// closed on missing coverage than merely be told about it.
	//
	// Sol Finding 2 / Session 3: this used to call config.Current() here,
	// re-reading config.yaml from disk at audit time — after the agent has
	// already run. An operator (or an attacker with file write access) could
	// flip doctrine.unenforceable_rule_action from "block" to "flag" while
	// the backend was still executing and the run would be evaluated against
	// the *changed* value, contradicting the frozen RunEnvironment the rest
	// of the run already committed to. unenforceableRuleAction is now the
	// value captured once in the run's RunEnvironment, before the agent ever
	// launched.
	unenforceableVerdict := policy.RuleFlag
	if unenforceableRuleAction == "block" {
		unenforceableVerdict = policy.RuleDeny
	}
	for _, rule := range policy.UnenforceableRules(format) {
		audit.RuleViolations = append(audit.RuleViolations, policy.RuleViolation{
			Rule: rule, Verdict: unenforceableVerdict, CauseSeq: -1, TriggerSeq: -1,
			Detail: fmt.Sprintf("rule unenforceable for backend transcript format %q: its parser does not supply an event kind this rule requires", format),
		})
	}
	// Sol3 P1.8 (finding #15): same two-tier posture as the unenforceable-rule
	// handling just above — advisory (RuleFlag, the default) unless
	// doctrine.transcript_conformance_action is "block", in which case a
	// failed session-start/completion/pairing/identity/turn-count check
	// folds into audit.Violations via the exact same loop below.
	conformanceVerdict := policy.RuleFlag
	if transcriptConformanceAction == "block" {
		conformanceVerdict = policy.RuleDeny
	}
	audit.RuleViolations = append(audit.RuleViolations, conf.violations(conformanceVerdict)...)
	for _, rv := range audit.RuleViolations {
		if rv.Verdict == policy.RuleDeny {
			audit.Violations = append(audit.Violations, "policy rule violation ("+rv.Rule+"): "+rv.Detail)
		}
	}
	return audit
}

func appendNote(notes, note string) string {
	if notes == "" {
		return note
	}
	return notes + "," + note
}

func readSelfReview(work string) (*contracts.ResultDocument, string) {
	data, err := os.ReadFile(filepath.Join(work, "RESULT.json"))
	if err != nil {
		return nil, ""
	}
	var review contracts.ResultDocument
	if json.Unmarshal(data, &review) != nil {
		return nil, ""
	}
	normalized, err := json.Marshal(review)
	if err != nil {
		return nil, ""
	}
	return &review, string(normalized)
}

// undisclosedChanges returns every EXTERNALLY measured changed/deleted path
// (the actual worktree diff, never trusted from the backend) that the
// backend's own self-reported RESULT.json files_changed never listed (Sol
// P1-15: the transcript/self-report is explanatory evidence, never
// authoritative). A nil review is not itself a mismatch -- a missing
// self-report is its own, separately caught failure (required-file/validator
// checks); this only flags a review that DID run but suppressed a real
// change.
func undisclosedChanges(review *contracts.ResultDocument, changed, deleted []string) []string {
	if review == nil {
		return nil
	}
	claimed := make(map[string]bool, len(review.FilesChanged))
	for _, p := range review.FilesChanged {
		claimed[p] = true
	}
	var undisclosed []string
	for _, p := range append(append([]string{}, changed...), deleted...) {
		if p == "RESULT.json" || claimed[p] {
			continue
		}
		undisclosed = append(undisclosed, p)
	}
	return undisclosed
}

// effectLedgerViolations is the post-v4 hardening plan's Session 3 (item D)
// gate over the kernel-observed effect ledger S9 started recording
// (internal/observability/effects.go) but never wired into a decision.
//
// Investigated all three named effect kinds against the actual reachable
// states of this codebase (not just the report's abstract framing) before
// writing this function -- see agents/governator-post-v4-hardening-plan.md
// Session 3 findings:
//
//   - executable_launch: handle.ParentWritable (Sol P0-6's "parent-directory
//     trust state," computed by agents.ResolveHandle since before this
//     session) was never read by anything -- a backend binary reachable only
//     because an untrusted party could rewrite something upstream of it in
//     its own directory chain sailed through unexamined. Gated here. The
//     trusted-tool registry (Session 2, item C) already resolves every
//     OTHER controller-invoked binary (git/unshare/bash/docker/python3/
//     systemd-run) with this exact check built in and reporting
//     ParentWritable=false unconditionally (internal/toolregistry), so this
//     can only ever fire for the one path Session 2 didn't cover: the
//     governed backend's own executable.
//   - network: the only reachable state where the recorded effect shows
//     "not kernel-namespaced" while the contract forbids network is exactly
//     when containment.RequiresHostContainment was false for this run's risk
//     tier -- i.e. containment was never policy-required, the deliberate,
//     tested default for ordinary (non-high/medium-risk) contracts.
//     Wherever containment IS required, containment.EnforcePolicy already
//     fails the run closed before launch (externally enforced or a valid
//     signed override, nothing else) -- there is no surviving gap for this
//     function to catch without changing risk-tiering policy, which is a
//     separate decision, not this session's.
//   - process_creation: TestAttack8DetachedSetsidChildCannotWriteAfterApproval
//     (internal/redteam) is the existing, deliberately-still-green proof
//     that "kernel observed a live descendant process, self-report/transcript
//     never mentioned any command" is not on its own a violation -- P0-4's
//     whole design is that detecting and confirming extinction of an
//     undisclosed descendant IS the safety property, not evidence of
//     concealment requiring a second, separate penalty. Every peak-process-
//     count-based mismatch this function's author could construct fires on
//     that exact fixture; none is added. Closing this further needs new
//     per-descendant identity instrumentation (matching each live PID back
//     to a resolved, trusted binary), not a threshold over the existing
//     aggregate count -- real follow-on work, not attempted here.
func effectLedgerViolations(handle *agents.BackendExecutionHandle) []string {
	if handle != nil && handle.ParentWritable {
		return []string{fmt.Sprintf("executable_launch: backend executable %s has an untrusted-writable directory in its ancestry (no proof this exact binary could not have been substituted before resolution)", handle.CanonicalPath)}
	}
	return nil
}

type diffMetrics struct {
	Lines    int
	NewFiles int
}

func countLines(path string) int {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return 0
	}
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	count := 0
	for scanner.Scan() {
		count++
	}
	return count
}

func parseNumstat(output string) int {
	total := 0
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		parts := strings.SplitN(line, "\t", 3)
		if len(parts) < 2 {
			continue
		}
		added, aerr := strconv.Atoi(parts[0])
		deleted, derr := strconv.Atoi(parts[1])
		if aerr == nil {
			total += added
		}
		if derr == nil {
			total += deleted
		}
	}
	return total
}

func measureDiff(root, work string, git bool, before snapshot, changed, deleted []string) diffMetrics {
	metrics := diffMetrics{}
	if git {
		_, output, _ := shell(context.Background(), work, "git diff --numstat HEAD")
		metrics.Lines = parseNumstat(output)
	}
	for _, name := range changed {
		if _, existed := before[name]; existed {
			if !git {
				oldPath := filepath.Join(root, filepath.FromSlash(name))
				newPath := filepath.Join(work, filepath.FromSlash(name))
				_, output, _ := shell(context.Background(), work, "git diff --no-index --numstat -- "+shQuote(oldPath)+" "+shQuote(newPath))
				metrics.Lines += parseNumstat(output)
			}
			continue
		}
		metrics.NewFiles++
		metrics.Lines += countLines(filepath.Join(work, filepath.FromSlash(name)))
	}
	if !git {
		for _, name := range deleted {
			metrics.Lines += countLines(filepath.Join(root, filepath.FromSlash(name)))
		}
	}
	return metrics
}

func redact(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	s := string(b)
	for _, r := range secrets {
		s = r.ReplaceAllString(s, "[REDACTED]")
	}
	return os.WriteFile(path, []byte(s), 0600)
}

func (r *Runner) Run(ctx context.Context, c contracts.Contract) (RunRecord, error) {
	if !routingFallbackEnabled(c) {
		return r.runOnce(ctx, c)
	}
	maxAttempts := c.Routing.EffectiveMaxAttempts()
	current := c
	failed := map[string]bool{}
	var rootRunID string
	// The loop always returns from inside: every iteration either falls back
	// (continue) or returns, and the attempt >= maxAttempts arm makes the
	// final iteration unconditionally a return. No trailing statement — a
	// reachable one would launch an extra, unledgered attempt.
	for attempt := 1; ; attempt++ {
		current = withExcludedRoutingCandidates(current, failed)
		rec, err := r.runOnce(ctx, current)
		if rootRunID == "" && rec.ID != "" {
			rootRunID = rec.ID
		}
		fallbackReason := ""
		eligible, reason, eligErr := r.fallbackEligible(current, rec)
		if eligErr != nil {
			return rec, eligErr
		}
		if eligible && attempt < maxAttempts {
			fallbackReason = reason
		}
		if (eligible || attempt > 1) && rootRunID != "" && rec.ID != "" {
			if err := r.recordFallbackAttempt(rootRunID, rec, attempt, fallbackReason); err != nil {
				return rec, err
			}
		}
		if err != nil || !eligible || attempt >= maxAttempts {
			return rec, err
		}
		if rec.Agent == "" {
			return rec, err
		}
		failed[rec.Agent] = true
		if !hasRemainingRoutingCandidate(c, failed) {
			return rec, err
		}
	}
}

func routingFallbackEnabled(c contracts.Contract) bool {
	return c.Agent == contracts.AgentAuto && c.Routing.EffectiveMaxAttempts() > 1
}

func hasRemainingRoutingCandidate(c contracts.Contract, failed map[string]bool) bool {
	pool := []string{}
	if c.Routing != nil {
		pool = append(pool, c.Routing.Candidates...)
	}
	if len(pool) == 0 {
		pool = router.RegisteredAgents()
	}
	for _, name := range pool {
		agent, err := agents.New(name)
		if err != nil {
			continue
		}
		if !failed[agent.Name()] {
			return true
		}
	}
	return false
}

func withExcludedRoutingCandidates(c contracts.Contract, failed map[string]bool) contracts.Contract {
	if len(failed) == 0 {
		return c
	}
	clone := c
	var routing contracts.Routing
	if c.Routing != nil {
		routing = *c.Routing
	} else {
		routing = contracts.Routing{}
	}
	pool := append([]string{}, routing.Candidates...)
	if len(pool) == 0 {
		pool = router.RegisteredAgents()
	}
	filtered := make([]string, 0, len(pool))
	for _, name := range pool {
		agent, err := agents.New(name)
		if err != nil {
			continue
		}
		canonical := agent.Name()
		if failed[canonical] {
			continue
		}
		filtered = append(filtered, canonical)
	}
	routing.Candidates = filtered
	clone.Routing = &routing
	return clone
}

func (r *Runner) fallbackEligible(c contracts.Contract, rec RunRecord) (bool, string, error) {
	if rec.ID == "" || !observability.IsInfraFailure(rec.FailureTaxonomy) {
		return false, "", nil
	}
	if !strings.Contains(rec.Notes, "fallback_worktree_unchanged") {
		return false, "", nil
	}
	if rec.ToolCalls != 0 {
		return false, "", nil
	}
	db, err := dbOpen(r.Home)
	if err != nil {
		return false, "", err
	}
	defer db.Close()
	var touched int
	if err := db.QueryRow(`SELECT COUNT(*) FROM files_touched WHERE run_id=?`, rec.ID).Scan(&touched); err != nil {
		return false, "", err
	}
	if touched != 0 {
		return false, "", nil
	}
	// Session 5 candidate ASK target: "fallback after unusual infra
	// failure". Routine backpressure (rate limit, quota, auth expiry) keeps
	// auto-falling-back exactly as unattended as before this session —
	// only the rarer BINARY_MISSING/FLAG_DRIFT/TRANSIENT_UPSTREAM kinds
	// consult the policy gate, since those often mean something is
	// structurally wrong rather than a backend being routinely busy.
	if observability.IsUnusualInfraFailure(rec.FailureTaxonomy) {
		root, err := filepath.Abs(c.Workspace.Root)
		if err != nil {
			return false, "", err
		}
		// fallbackEligible runs strictly after the previous runOnce attempt
		// has already returned — this is a fresh decision point for the next
		// attempt, not a re-read partway through an in-flight run, so loading
		// current configuration here (via LoadStrict, which fails closed
		// instead of silently falling back to defaults) is correct rather
		// than a repeat of Sol Finding 2.
		cfg, err := config.LoadStrict()
		if err != nil {
			return false, "", err
		}
		facts := policy.MergeFacts(policy.BuildContractFacts(c, rec.Agent), map[string]any{
			policy.FactUnusualInfraRetry: true,
			policy.FactInfraFailureKind:  rec.FailureTaxonomy,
		})
		bundle, err := loadPolicyBundle(cfg, c, root)
		if err != nil {
			return false, "", err
		}
		decision, _, pendingOneShotIDs, gerr := evaluatePolicyGate(db, cfg, c, bundle, rec.ID, facts)
		if gerr != nil {
			return false, "", gerr
		}
		// This call only answers "is a fallback retry eligible?" — it never
		// itself launches a governed action (a separate runOnce call does,
		// with its own independent policy gate evaluation), so any one-shot
		// override it resolved to ALLOW must be released immediately rather
		// than held reserved for an execution boundary that will never
		// happen on this call path.
		releaseAt := time.Now().UTC().Format(time.RFC3339Nano)
		for _, oid := range pendingOneShotIDs {
			if rerr := observability.ReleasePolicyOverrideReservation(db, oid, releaseAt); rerr != nil {
				return false, "", rerr
			}
		}
		if decision.Blocks() {
			return false, "", nil
		}
	}
	return true, rec.FailureTaxonomy, nil
}

func (r *Runner) recordFallbackAttempt(rootRunID string, rec RunRecord, attempt int, reason string) error {
	db, err := dbOpen(r.Home)
	if err != nil {
		return err
	}
	defer db.Close()
	return observability.RecordFallbackAttempt(db, observability.FallbackAttempt{
		RootRunID:      rootRunID,
		RunID:          rec.ID,
		Attempt:        attempt,
		Backend:        rec.Agent,
		FallbackReason: reason,
		Created:        time.Now().UTC().Format(time.RFC3339Nano),
	})
}

func (r *Runner) runOnce(ctx context.Context, c contracts.Contract) (RunRecord, error) {
	root, err := filepath.Abs(c.Workspace.Root)
	if err != nil {
		return RunRecord{}, err
	}
	// Sol Finding 2 / Session 3: the RunEnvironment is built here, first,
	// before any run decision — before policy.Preflight, before runner
	// resolution, before the lock, before anything that could be construed
	// as "this run has started deciding something." Every execution-critical
	// read of configuration for the rest of this attempt comes from this one
	// frozen snapshot; nothing below calls config.Current() again. See
	// RunEnvironment's doc comment in environment.go for the exploit this
	// closes.
	env, err := buildRunEnvironment()
	if err != nil {
		return RunRecord{}, err
	}
	// env.Containment (rc4 Session 2, Sol10 P0-2) is resolved exactly once,
	// above, alongside everything else RunEnvironment freezes. It is shared
	// by every containment.NewScope call for this run's whole lifetime --
	// the run-level Scope just below and every stage's own Scope
	// (internal/stage.Executor.Run, reached via ctx) -- so Close it exactly
	// once here, after every one of them has finished.
	defer func() { _ = env.Containment.Close() }()
	ctx = containment.WithEnvironment(ctx, env.Containment)
	// id is minted here (rather than just before workspace creation, where it
	// used to live) so the Phase 4 stage checkpoints below — PARSED and
	// PREFLIGHTED happen before any workspace or quota reservation exists —
	// have a run_id to key on from the very first checkpoint. run_stages has
	// no foreign key to runs (like every other run_id-keyed table in this
	// ledger), so recording a stage before the runs row itself is inserted is
	// safe.
	id := fmt.Sprintf("%s-%d", c.JobID, time.Now().UTC().UnixNano())
	runStarted := time.Now().UTC()
	if c.Budget.MaxMinutes > 0 {
		// Sol P1-16 / report §9 attack 21: contracts.Validate now rejects an
		// out-of-range budget.max_minutes before a contract ever reaches
		// here, but a contract built directly in Go (bypassing Validate, as
		// most in-process callers and tests do) has no other guard — a raw
		// time.Duration(minutes)*time.Minute multiply silently overflows and
		// wraps for a large enough value instead of producing the huge
		// timeout the caller asked for. SafeMinutesDuration refuses instead.
		dur, ok := contracts.SafeMinutesDuration(c.Budget.MaxMinutes)
		if !ok {
			return RunRecord{}, fmt.Errorf("budget.max_minutes %d exceeds the safe duration-conversion bound (%d)", c.Budget.MaxMinutes, contracts.MaxSafeBudgetMinutes)
		}
		runCtx, cancel := context.WithTimeout(ctx, dur)
		defer cancel()
		ctx = runCtx
	}
	rtkAnnotation, err := tokenoptimizer.PromptAnnotation()
	if err != nil {
		return RunRecord{}, err
	}
	minimalismAnnotation, err := minimalism.PromptAnnotation()
	if err != nil {
		return RunRecord{}, err
	}
	preflight, err := policy.Preflight(c)
	if err != nil {
		return RunRecord{}, err
	}
	if err := policy.Enforce(preflight, c); err != nil {
		return RunRecord{}, err
	}
	// Sol P1-1/P1-2: resolve the docker image identity before any
	// lock/workspace/quota side effect, then hand that exact resolved object
	// to DockerRunner so launch uses and verifies the same image replay hashed.
	var dockerImage *runner.ImageIdentity
	if c.EffectiveRunner() == "docker" && c.Docker != nil {
		img, ierr := runner.ResolveImageIdentity(ctx, c.Docker.Image, env.Controller)
		if ierr != nil {
			return RunRecord{}, ierr
		}
		dockerImage = &img
	}
	// Runner resolution (Phase 5) happens before any lock/workspace/quota side
	// effect: a docker request Governator can't satisfy must fail closed with
	// a clear error here, never silently fall back to LocalWorktreeRunner and
	// never leave a partially-acquired lock or reservation behind.
	rn, err := runner.New(c.EffectiveRunner(), c.Docker, c.Local, env.CredentialRoots, dockerImage, env.Controller)
	if err != nil {
		return RunRecord{}, err
	}
	release, err := lock(root, r.Home)
	if err != nil {
		return RunRecord{}, err
	}
	defer release()
	db, err := dbOpen(r.Home)
	if err != nil {
		return RunRecord{}, err
	}
	defer db.Close()
	if err := lifecycle.Record(db, id, lifecycle.Parsed, "", lifecycle.Now()); err != nil {
		return RunRecord{}, err
	}
	if err := lifecycle.Record(db, id, lifecycle.Preflighted, "", lifecycle.Now()); err != nil {
		return RunRecord{}, err
	}
	hash, err := contracts.ContractHash(c)
	if err != nil {
		return RunRecord{}, err
	}
	git := isGit(root)
	head := "non-git"
	if git {
		head, err = gitHead(root)
		if err != nil {
			return RunRecord{}, err
		}
	}
	// Sol Critical 1: the replay probe no longer fires here. It moved below
	// every pre-launch trust gate (config, spend, routing, breaker,
	// containment, layered policy, quota, prompt resolution) and now keys on
	// the full ExecutionIdentity hash rather than contract_hash+approved_head,
	// so a stale approval can never bypass current policy, configuration,
	// routing, containment, quota, prompt or backend state.
	//
	// cfg is env.Config (frozen above, at the very top of this function) —
	// not a fresh config.Current() read. Every use of cfg below this line
	// describes the same environment recorded in this run's identity.
	cfg := env.Config
	if err := quota.SeedFromConfig(db, cfg, time.Now().UTC()); err != nil {
		return RunRecord{}, err
	}
	if ok, reason := spend.CheckBudget(cfg, db); !ok {
		refused := RunRecord{
			ID: id, JobID: c.JobID, JobType: c.JobType, Agent: c.Agent, Mode: string(c.Mode),
			Status: "QUARANTINED", Root: root, Created: time.Now().UTC().Format(time.RFC3339Nano),
			Message: "SPEND_CAP: " + reason, FailureTaxonomy: "SPEND_CAP", RepairOf: c.RepairLineage,
		}
		if err := insertRun(db, refused, hash, head); err != nil {
			return refused, err
		}
		if err := observability.RecordIdentity(db, c.JobID, c.JobType, c.Agent, refused.Created); err != nil {
			return refused, err
		}
		if err := observability.RecordCompletion(db, observability.Completion{
			RunID: refused.ID, Agent: refused.Agent, JobType: refused.JobType, Status: refused.Status,
			FailureTaxonomy: refused.FailureTaxonomy, Notes: refused.Message, Violations: []string{"spend_cap: " + reason},
		}); err != nil {
			return refused, err
		}
		if err := lifecycle.Record(db, id, lifecycle.Quarantined, "", lifecycle.Now()); err != nil {
			return refused, err
		}
		return refused, nil
	}
	// Route broker: agent: auto resolves to a concrete backend here, between
	// contract validation and workspace creation. Resolving before any worktree
	// is built means a fail-closed decision (no candidate qualifies) refuses
	// with no orphan workspace or canary left behind. The resolved agent feeds
	// every downstream read (prompt registry, agents.New, identity, run record)
	// so the run reports what actually ran. The contract hash — computed
	// earlier from the authored contract — feeds the ExecutionIdentity (Sol
	// Critical 1) alongside the resolved agent, so an agent: auto resolution
	// that lands on a different backend mints a different identity and never
	// replays an approval obtained under the other backend. An explicit agent
	// skips the broker entirely (rule: the broker validates health but never
	// overrides an explicit choice).
	resolved := c
	if c.Agent == contracts.AgentAuto {
		decision, derr := router.Router{Health: breaker.Store{DB: db}}.Resolve(db, router.RequestFromContract(c), cfg)
		if derr != nil {
			return RunRecord{}, derr
		}
		if decision.Selected == "" {
			return RunRecord{}, fmt.Errorf("%w:\n%s", router.ErrNoCandidate, decision.Format())
		}
		if rerr := observability.RecordRouteDecision(db, routeDecisionRecord(decision, id, time.Now().UTC().Format(time.RFC3339Nano))); rerr != nil {
			return RunRecord{}, rerr
		}
		resolved.Agent = decision.Selected
	} else {
		// Explicit agent: the broker never overrides an operator choice, but a
		// tripped breaker warrants a loud warning (plan Session 2). The run
		// proceeds regardless — operator override is legitimate. A CLOSED or
		// HALF_OPEN breaker is silent; OPEN/DEGRADED is surfaced.
		if snap := breaker.Snapshot(db, c.Agent, time.Now().UTC()); snap.EffectiveState == breaker.Open || snap.EffectiveState == breaker.Degraded {
			fmt.Fprintf(os.Stderr, "warning: backend %q breaker is %s (%s); running anyway (explicit override)\n",
				c.Agent, snap.EffectiveState, snap.FailureKind)
		}
	}
	if err := lifecycle.Record(db, id, lifecycle.Routed, resolved.Agent, lifecycle.Now()); err != nil {
		return RunRecord{}, err
	}
	agent, err := agents.New(resolved.Agent)
	if err != nil {
		return RunRecord{}, err
	}
	// Session 3 containment policy (Phase 2): a risk_class: high contract must
	// not silently resolve to local execution. Qualifying containment is
	// hardened Docker, a backend with a verified native sandbox, or a signed
	// operator override. Checked after the route broker resolves the agent
	// (native sandbox is a backend capability, not a contract claim) and
	// before any quota/workspace side effect, so a failure leaves nothing
	// behind — exactly the "fails before launch" acceptance for high-risk.
	// enforceContainment resolves the backend binary itself, but only when its
	// native-sandbox attestation branch actually needs it (Sol Finding 5 /
	// Session 2) — most contracts reach a containment verdict without ever
	// touching the executable's identity. handle is non-nil only when the
	// native-sandbox attestation branch resolved it; runOnce reuses it below
	// instead of resolving again (Sol P0-6 / Session 3: exactly one
	// agents.ResolveHandle call per run).
	enforceLocalEffectful := containment.LocalEffectfulTieringEnforced(cfg.Containment.LocalEffectfulTiering)
	capabilityAttestID, handle, requiresEnforcementWrap, err := enforceContainment(ctx, db, c, agent, cfg)
	if err != nil {
		return RunRecord{}, err
	}
	// Sol Critical 3 / Phase D: a local worktree is repository isolation only,
	// not host containment. Reject symlinks before launch so a backend cannot
	// write through a tracked link or symlinked write-parent into the host and
	// still present a clean repository fingerprint.
	if c.EffectiveRunner() == "local" {
		if err := validateNoLocalSymlinkEscape(root); err != nil {
			return RunRecord{}, err
		}
	}
	// Session 5 (Sol Phase 4) layered policy gate: evaluated after routing/
	// containment (so the resolved backend and its native-sandbox status are
	// known) and before any quota/workspace side effect (so a DENY or a
	// pending ASK leaves nothing behind — same "fails before launch" posture
	// as enforceContainment above). Candidate targets checked here: network
	// enablement, write outside the contract's declared read scope, and a
	// pre-launch cost estimate versus the operator's daily cap.
	estimatedCostUSD := spend.EstimateCostUSD(resolved.Agent, c.Budget.MaxTokens, nil)
	policyFacts := policy.MergeFacts(policy.BuildContractFacts(c, resolved.Agent), map[string]any{
		policy.FactEstimatedCostUSD: estimatedCostUSD,
		policy.FactDailyCapUSD:      cfg.Spend.DailyCapUSD,
	})
	// Sol P1-3: the bundle is built exactly once, here, before the first gate
	// call — and reused unchanged for computeExecutionIdentity below, even
	// though substantial pre-launch work (spend/quota reservation, prompt
	// resolution, handle resolution) separates the two. Neither call may load
	// project doctrine or contract rules independently; see PolicyBundle's
	// doc comment in policy_gate.go for the race this closes.
	policyBundle, err := loadPolicyBundle(cfg, c, root)
	if err != nil {
		return RunRecord{}, err
	}
	gateDecision, pendingAsks, pendingOneShotIDs, gerr := evaluatePolicyGate(db, cfg, c, policyBundle, id, policyFacts)
	if gerr != nil {
		return RunRecord{}, gerr
	}
	if gateDecision.Blocks() {
		refused, err := r.quarantineForPolicy(db, c, resolved.Agent, root, id, hash, head, gateDecision, pendingAsks)
		return refused, err
	}
	// Sol P1.1 (finding #8): pendingOneShotIDs are one-shot ASK overrides the
	// policy gate reserved and resolved to ALLOW, but has NOT yet consumed —
	// consumption happens only immediately before the governed action
	// crosses its execution boundary (right before rn.Launch below), never
	// at gate-evaluation time. Every return between here and that point is
	// an "execution never begins" abort, so this defer releases any
	// still-reserved one-shot back to available unless oneShotConsumed is
	// set true right after a successful consume just before launch.
	oneShotConsumed := len(pendingOneShotIDs) == 0
	defer func() {
		if oneShotConsumed {
			return
		}
		releaseAt := time.Now().UTC().Format(time.RFC3339Nano)
		for _, oid := range pendingOneShotIDs {
			if rerr := observability.ReleasePolicyOverrideReservation(db, oid, releaseAt); rerr != nil {
				payload, _ := json.Marshal(oneShotOverrideReleasePayload{OverrideID: oid})
				noteOperationalFailure(db, id, opOneShotOverrideRelease, rerr, string(payload))
			}
		}
	}()
	// Sol P1.4 (finding #11): the early spend.CheckBudget above is a cheap
	// pre-flight check only — it reads TodaySpend, which excludes RUNNING
	// rows, so two processes racing it can both pass before either's cost
	// lands. This is the actual atomic cross-process gate: it reserves
	// estimatedCostUSD against the daily cap in one SQLite statement, closing
	// that race the same way quota.Reserve below closes it for quota
	// headroom. Placed after the policy gate (so it never reserves against a
	// DENY/ASK) and before quota.Reserve (mirroring the pre-fix ordering:
	// spend was always checked before quota).
	spendTTL := time.Duration(c.Budget.MaxMinutes+5) * time.Minute
	spendReservation, spendOK, spendReason, serr := spend.ReserveGlobal(db, cfg, id, estimatedCostUSD, spendTTL, time.Now().UTC())
	if serr != nil {
		return RunRecord{}, serr
	}
	if !spendOK {
		refused := RunRecord{
			ID: id, JobID: c.JobID, JobType: c.JobType, Agent: resolved.Agent, Mode: string(c.Mode),
			Status: "QUARANTINED", Root: root, Created: time.Now().UTC().Format(time.RFC3339Nano),
			Message: "SPEND_CAP: " + spendReason, FailureTaxonomy: "SPEND_CAP", RepairOf: c.RepairLineage,
		}
		if err := insertRun(db, refused, hash, head); err != nil {
			return refused, err
		}
		if err := observability.RecordIdentity(db, c.JobID, c.JobType, resolved.Agent, refused.Created); err != nil {
			return refused, err
		}
		if err := observability.RecordCompletion(db, observability.Completion{
			RunID: refused.ID, Agent: refused.Agent, JobType: refused.JobType, Status: refused.Status,
			FailureTaxonomy: refused.FailureTaxonomy, Notes: refused.Message, Violations: []string{"spend_cap: " + spendReason},
		}); err != nil {
			return refused, err
		}
		if err := lifecycle.Record(db, id, lifecycle.Quarantined, "", lifecycle.Now()); err != nil {
			return refused, err
		}
		return refused, nil
	}
	spendSettled := false
	defer func() {
		if spendReservation.ID != 0 && !spendSettled {
			// Best-effort (an unreleased reservation self-heals at its TTL),
			// but the failure itself must not vanish: queue it so `gov
			// reconcile` releases the headroom before the TTL does.
			if rerr := spend.ReleaseGlobal(db, spendReservation.ID, time.Now().UTC()); rerr != nil {
				payload, _ := json.Marshal(spendReleasePayload{ReservationID: spendReservation.ID})
				noteOperationalFailure(db, id, opSpendRelease, rerr, string(payload))
			}
		}
	}()
	quotaUsageEstimate := quota.EstimateUsage(c.Budget.MaxTokens)
	quotaTTL := time.Duration(c.Budget.MaxMinutes+5) * time.Minute
	quotaReservation, qerr := quota.Reserve(db, resolved.Agent, quota.DefaultAccount, id, quotaUsageEstimate, quotaTTL, time.Now().UTC())
	if qerr != nil {
		if errors.Is(qerr, quota.ErrNoHeadroom) {
			refused := RunRecord{
				ID: id, JobID: c.JobID, JobType: c.JobType, Agent: resolved.Agent, Mode: string(c.Mode),
				Status: "QUARANTINED", Root: root, Created: time.Now().UTC().Format(time.RFC3339Nano),
				Message: "QUOTA_EXHAUSTED: " + qerr.Error(), FailureTaxonomy: string(agents.InfraQuotaExhausted),
				Notes: appendNote("quota_reservation_refused", "fallback_worktree_unchanged"), RepairOf: c.RepairLineage,
			}
			if err := insertRun(db, refused, hash, head); err != nil {
				return refused, err
			}
			if err := observability.RecordIdentity(db, c.JobID, c.JobType, resolved.Agent, refused.Created); err != nil {
				return refused, err
			}
			if err := observability.RecordCompletion(db, observability.Completion{
				RunID: refused.ID, Agent: refused.Agent, JobType: refused.JobType, Status: refused.Status,
				FailureTaxonomy: refused.FailureTaxonomy, Notes: refused.Notes, Violations: []string{"quota_exhausted: " + qerr.Error()},
			}); err != nil {
				return refused, err
			}
			if err := breaker.RecordFailure(db, refused.Agent, refused.FailureTaxonomy, time.Now().UTC()); err != nil {
				payload, _ := json.Marshal(breakerFeedbackPayload{Agent: refused.Agent, FailureKind: refused.FailureTaxonomy})
				noteOperationalFailure(db, refused.ID, opBreakerFailure, err, string(payload))
			}
			if err := lifecycle.Record(db, id, lifecycle.Quarantined, "", lifecycle.Now()); err != nil {
				return refused, err
			}
			return refused, nil
		}
		return RunRecord{}, qerr
	}
	if err := lifecycle.Record(db, id, lifecycle.QuotaReserved, "", lifecycle.Now()); err != nil {
		return RunRecord{}, err
	}
	quotaSettled := false
	defer func() {
		if quotaReservation.ID != 0 && !quotaSettled {
			// Best-effort (an unreleased reservation self-heals at its TTL),
			// but per Session 4 the failure itself must not vanish: queue it
			// so `gov reconcile` releases the headroom before the TTL does.
			if rerr := quota.Release(db, quotaReservation.ID, time.Now().UTC()); rerr != nil {
				payload, _ := json.Marshal(quotaReleasePayload{ReservationID: quotaReservation.ID})
				noteOperationalFailure(db, id, opQuotaRelease, rerr, string(payload))
			}
		}
	}()
	// Sol Critical 1 / Phase A: resolve the prompt version and the backend
	// adapter here (before workspace creation and before the replay probe) so
	// the ExecutionIdentity — the replay key — captures the exact prompt and
	// backend any replayed approval was evaluated against. Neither resolution
	// depends on the worktree, so moving them up from their old post-workspace
	// position is safe. The replay probe is intentionally AFTER every
	// pre-launch trust gate (config, spend, routing, breaker, containment,
	// layered policy, quota): a prior approval must clear current policy before
	// it can be reused, and the identity hash ensures any changed trust input
	// (org DENY, backend binary, prompt version, …) simply never matches.
	promptRoot := config.Env("GOV_PROMPTS")
	if promptRoot == "" {
		promptRoot = "prompts"
	}
	promptVersion, err := prompts.Resolve(promptRoot, resolved.Agent, string(c.Mode))
	if err != nil {
		return RunRecord{}, err
	}
	// Sol P0-6 / Session 3: resolve the configured backend binary exactly
	// once for this run — through PATH, symlink-canonicalized, opened, and
	// content-hashed from that one open descriptor — and reuse the single
	// resulting handle for execution identity, replay, and the actual launch
	// below. handle is already set when enforceContainment's native-sandbox
	// attestation branch needed it above; otherwise this is the run's one
	// and only resolution. A bare name (backends.pi.bin: pi) resolved
	// independently at identity time versus launch time let a
	// swapped-then-restored binary pass a stale replay check that never
	// re-verified the file it hashed.
	if handle == nil {
		handle, err = agents.ResolveHandle(ctx, cfg, agent)
		if err != nil {
			return RunRecord{}, err
		}
	}
	defer handle.Close()
	consumedIdentities, err := consumedArtifactIdentities(db, r.Home, c)
	if err != nil {
		return RunRecord{}, err
	}
	validatorToolsetHash, err := resolveValidatorToolset(c, root, env.ToolRegistry)
	if err != nil {
		return RunRecord{}, err
	}
	// Sol9 P0-5: materialize per-validator private executable directories
	// populated with sealed copies of exactly the tools each spec
	// declares, plus the ELF runtime closure read roots each sealed tool
	// needs to actually exec under Landlock. removeSealedValidatorDirs
	// cleans them up when the transaction's validators have finished.
	successValidatorSealed, cleanupValidatorSealed, removeSealedValidatorDirs, err := sealedValidatorToolsets(c, env.ToolRegistry)
	if err != nil {
		return RunRecord{}, err
	}
	defer removeSealedValidatorDirs()
	graphStatus := env.GraphStatus
	preReplayGraph, err := contextgraph.CurrentWithStatus(ctx, root, graphStatus, env.ToolRegistry, env.Controller)
	if err != nil {
		return RunRecord{}, err
	}
	compiledPromptForIdentity, err := contracts.CompilePrompt(c, root)
	if err != nil {
		return RunRecord{}, err
	}
	compiledPromptForIdentity += "\nController canary: .governator-canary must remain byte-for-byte unchanged. Touching it quarantines the run.\n"
	compiledPromptForIdentity += artifactPromptAnnotation(consumedIdentities, c.Produces)
	compiledPromptForIdentity += prompts.Annotation(promptVersion)
	compiledPromptForIdentity += rtkAnnotation
	compiledPromptForIdentity += contextgraph.PromptAnnotation(preReplayGraph)
	compiledPromptForIdentity += minimalismAnnotation
	compiledPromptHash := hashJSON(map[string]string{"prompt": compiledPromptForIdentity})
	graphSnapshotHash := hashJSON(preReplayGraph)
	identity := computeExecutionIdentity(cfg, c, agent, handle.PathResolution, handle.Identity, dockerImage, agents.EnvPolicyHash(handle.AllowedEnv), head, hash, promptVersion, capabilityAttestID, policyBundle, env.Containment, compiledPromptHash, consumedArtifactsHash(consumedIdentities), contextgraph.ProviderIdentityHash(graphStatus), graphSnapshotHash, env.Controller.Hash, validatorToolsetHash)
	identity.ProtectedManifestHash = hashJSON(env.ProtectedPatterns)
	// Sol9 P0-4: build the Assayer execution snapshot HERE, before replay
	// identity is calculated, and thread the one returned *assay.Snapshot
	// through to runAssayStep below -- Evaluate must never rebuild its own
	// or reload the registry/re-resolve python for itself. A configured but
	// unbuildable snapshot is a hard failure, not a silent skip: assay was
	// declared and Governator cannot honestly bind replay identity to code
	// it never actually copied.
	//
	// Gated on c.Assay != nil, not just cfg.Assay.Repo: runAssayStep itself
	// is only ever invoked below when this specific contract declares an
	// assay block (see the `c.Assay != nil` guard at its call site) --
	// building a snapshot whenever the operator's bridge config merely
	// names a repo, regardless of whether this run's contract uses assay
	// at all, would both waste the copy and turn an unrelated contract's
	// run into a hard failure over an assay misconfiguration it never
	// touches.
	var assaySnapshot *assay.Snapshot
	if c.Assay != nil && strings.TrimSpace(cfg.Assay.Repo) != "" {
		assaySnapshot, err = assay.BuildSnapshot(env.ToolRegistry, assay.Config{
			Repo:    cfg.Assay.Repo,
			Python:  cfg.Assay.Python,
			Timeout: time.Duration(cfg.Assay.TimeoutSeconds) * time.Second,
		})
		if err != nil {
			return RunRecord{}, fmt.Errorf("assay: build execution snapshot: %w", err)
		}
		defer assaySnapshot.Close()
	}
	identity.AssayerEnvironmentHash = resolvedAssayerEnvironmentHash(cfg, c, assaySnapshot)
	identity.AssayerProfileHash = identity.AssayerEnvironmentHash
	backendToolIdentity := toolregistry.Identity{Name: resolved.Agent, Kind: toolregistry.KindGovernedBackend, CanonicalPath: handle.CanonicalPath, SHA256: handle.SHA256, OwnerUID: handle.OwnerUID, OwnerGID: handle.OwnerGID, Mode: handle.Mode}
	assayerParticipantHash := ""
	if cfg.Assay.Repo != "" {
		assayerParticipantHash = identity.AssayerEnvironmentHash
	}
	identity.Participants = resolvedParticipants(env.ToolRegistry, backendToolIdentity, graphStatus, env.Controller.Hash, validatorToolsetHash, assayerParticipantHash)
	for role, part := range resolvedAssayerParticipants(cfg.Assay, env.Controller.Hash) {
		identity.Participants[role] = part
	}
	if dockerImage != nil {
		identity.Participants["docker_daemon"] = ExecutableIdentity{Role: "docker_daemon", SHA256: hashJSON(dockerImage), Known: true}
	}
	if len(c.Success.Validators) > 0 && len(c.Success.ValidatorSpecs) == 0 {
		identity.Participants["validator_tools"] = ExecutableIdentity{Role: "validator_tools", Known: false}
		identity.Participants["validator_scripts"] = ExecutableIdentity{Role: "validator_scripts", Known: false}
	}
	if c.Cleanup != nil && len(c.Cleanup.Validators) > 0 && len(c.Cleanup.ValidatorSpecs) == 0 {
		identity.Participants["validator_tools"] = ExecutableIdentity{Role: "validator_tools", Known: false}
		identity.Participants["validator_scripts"] = ExecutableIdentity{Role: "validator_scripts", Known: false}
	}
	identity.ControllerToolsetHash = hashJSON(identity.Participants)
	identity.ExactPromptHash = compiledPromptHash
	identity.CredentialIdentityHash = hashJSON(map[string]any{"roots": env.CredentialRoots, "account": handle.Identity})
	identity.StrictReplayEligible = handle.Identity.Known()
	if !identity.StrictReplayEligible {
		identity.StrictReplayDisabledReason = "backend provider/model/account identity is unknown"
	}
	if perr := validateParticipants(identity.Participants); perr != nil {
		identity.StrictReplayEligible = false
		identity.StrictReplayDisabledReason = perr.Error()
	}
	// Sol9 P0-4 work item 4: a snapshot built from a dirty (uncommitted
	// changes) Assayer checkout cannot be reproduced against a specific
	// commit by a later audit, so strict replay must be disabled for this
	// transaction even though the snapshot itself executed correctly.
	if assaySnapshot != nil && assaySnapshot.Dirty {
		identity.StrictReplayEligible = false
		identity.StrictReplayDisabledReason = assaySnapshot.DirtyReason
	}
	transaction := newTransactionSnapshot(hash, env.ConfigHash, env.ProtectedPatterns, graphSnapshotHash, compiledPromptForIdentity, env.Controller.Hash, identity.CredentialIdentityHash, identity.Participants, consumedIdentities)
	if priorID, perr := replayMatch(db, func() string {
		if identity.StrictReplayEligible {
			return identity.Hash()
		}
		return ""
	}()); perr != nil {
		return RunRecord{}, perr
	} else if priorID != "" {
		replayed, replayErr := Last(priorID)
		replayed.Replayed = true
		return replayed, replayErr
	}
	ws, err := rn.Prepare(ctx, runner.PrepareRequest{Root: root, Home: r.Home, ID: id, Git: git})
	if err != nil {
		return RunRecord{}, err
	}
	cleanupPending := true
	defer func() {
		if cleanupPending {
			// Pre-terminal failures (for example required graph provider failure)
			// transfer no ownership to quarantine; remove both worktree and job
			// branch so reconcile/cleanup has no hidden resource leak.
			destroyWorkspaceWithOutbox(db, id, rn, ws, true)
		}
	}()
	work, branch := ws.Path, ws.Branch
	transcript := filepath.Join(r.Home, "transcripts", id+".jsonl")
	spec := agents.SpecFromContract(c, work)
	rec := RunRecord{ID: id, JobID: c.JobID, JobType: c.JobType, Agent: resolved.Agent, Mode: string(c.Mode), Status: "RUNNING", Root: root, Worktree: work, Branch: branch, Transcript: transcript, Created: time.Now().UTC().Format(time.RFC3339Nano), PromptVersion: promptVersion.ID, Envelope: envelopeJSON(spec, agent.Capabilities()), RepairOf: c.RepairLineage, IdentityHash: identity.Hash()}
	if err = insertRun(db, rec, hash, head); err != nil {
		return rec, err
	}
	// Sol P1.6 (finding #13): WORKSPACE_READY used to carry an empty detail,
	// so a process-crash recovery pass had nothing but RunRecord's bare
	// worktree/branch fields to work with — no container name, no runner
	// kind — and fell back to an ad hoc, container-blind cleanup. Persisting
	// the full descriptor here, before the agent ever launches, means
	// recovery (recovery.go's destroyLeftoverWorkspace) can reconstruct the
	// exact Runner and Workspace this run used and tear it down through the
	// same runner.Destroy path the normal completion flow uses.
	wsDescriptor, err := newWorkspaceDescriptor(c, ws)
	if err != nil {
		return rec, err
	}
	wsDescriptorJSON, err := json.Marshal(wsDescriptor)
	if err != nil {
		return rec, err
	}
	if err := lifecycle.Record(db, id, lifecycle.WorkspaceReady, string(wsDescriptorJSON), lifecycle.Now()); err != nil {
		return rec, err
	}
	// Consume the exact frozen graph snapshot represented by replay identity.
	graphSnapshot := preReplayGraph
	_ = transaction.GraphSnapshotHash
	c.Allowed.Execute = append(c.Allowed.Execute, contextgraph.CommandPatterns(graphSnapshot)...)
	rec.Graph = graphSnapshot
	if graphSnapshot.Warning != "" {
		rec.Notes = appendNote(rec.Notes, "graph_warning: "+graphSnapshot.Warning)
	}
	if err := updateRunGraph(db, rec); err != nil {
		return rec, err
	}
	canaryName := ".governator-canary"
	canaryPath := filepath.Join(work, canaryName)
	if _, statErr := os.Lstat(canaryPath); !os.IsNotExist(statErr) {
		return RunRecord{}, fmt.Errorf("reserved canary path already exists: %s", canaryName)
	}
	if err := os.WriteFile(canaryPath, []byte(id+"\n"), 0400); err != nil {
		return RunRecord{}, fmt.Errorf("create canary: %w", err)
	}
	// Sol10 P0-1: consumed artifacts are staged outside the writable
	// worktree whenever this run's own containment will actually be active
	// -- docker always gets the external store (its read-only bind mount
	// below does not depend on hardening tier), and local gets it exactly
	// when requiresEnforcementWrap (computed by enforceContainment above,
	// before this run's workspace even existed) says the enforce.Plan built
	// further down will be Active. That mirrors NewPlanForExecutable's own
	// fail-closed contract: requiresEnforcementWrap true on a host that
	// cannot actually provide Landlock+unshare refuses the whole run before
	// ever reaching here, rather than silently falling back. Only when local
	// containment is not required at all (operator disabled
	// enforce_local_effectful_tiering) does staging fall back to the legacy
	// mode-bits-in-workspace location -- the same already-accepted reduced
	// posture that setting gives every other control, honestly labelled
	// below rather than left to imply a boundary that isn't there.
	stageDir := filepath.Join(work, ".governator", "consumed")
	consumedBoundary := ""
	externalConsumedStore := false
	if len(transaction.Artifacts) > 0 {
		switch {
		case c.EffectiveRunner() == "docker":
			consumedBoundary = "docker-ro-bind-mount"
		case requiresEnforcementWrap:
			consumedBoundary = "landlock-mount-namespace-ro-bind"
		default:
			consumedBoundary = "mode-bits-degraded"
		}
		externalConsumedStore = consumedBoundary == "docker-ro-bind-mount" || consumedBoundary == "landlock-mount-namespace-ro-bind"
		if externalConsumedStore {
			stageDir = consumedArtifactStoreDir(r.Home, id)
			// The workspace-relative mount point .governator/consumed must
			// already exist, empty, before any of the docker :ro -v, the
			// local backend's ro-bind mount(2) call, or a validator's own
			// ro-bind (see the success/cleanup validator loops below --
			// internal/stage.Executor always runs host-side regardless of
			// runner kind, so a validator that reads a consumed artifact
			// needs this same mount established for ITS OWN launch too, not
			// just the backend's).
			if err := os.MkdirAll(filepath.Join(work, ".governator", "consumed"), 0700); err != nil {
				return RunRecord{}, fmt.Errorf("pre-create consumed-artifact mount point: %w", err)
			}
			if c.EffectiveRunner() == "docker" {
				ws.ConsumedDir = stageDir
			}
		}
	}
	_, err = stageConsumedArtifacts(stageDir, transaction.Artifacts)
	if err != nil {
		return RunRecord{}, err
	}
	if err = observability.RecordIdentity(db, c.JobID, c.JobType, resolved.Agent, rec.Created); err != nil {
		return rec, err
	}
	liveBefore, err := fingerprint(root)
	if err != nil {
		return rec, err
	}
	protectedBefore, err := protectedFingerprint(transaction.ProtectedPatterns)
	if err != nil {
		return rec, err
	}
	workBefore, err := fingerprint(work)
	if err != nil {
		return rec, err
	}
	gitControlBefore, err := gitControlFingerprint(work)
	if err != nil {
		return rec, err
	}
	// The model receives exactly the prompt bytes represented by replay identity.
	prompt := transaction.ExactPrompt
	// The AGENT_RUNNING checkpoint carries a digest of workBefore (the
	// worktree's pre-launch fingerprint) as its detail so a recovery pass
	// (gov run resume/recover --stale) run against a later crashed process can
	// tell "the agent never touched the worktree" (digest still matches) from
	// "the agent was mid-edit when it died" (digest no longer matches) without
	// needing that in-memory snapshot to have survived the crash.
	agentRunningDetail, _ := json.Marshal(map[string]string{"worktree_digest": snapshotDigest(workBefore)})
	if err := lifecycle.Record(db, id, lifecycle.AgentRunning, string(agentRunningDetail), lifecycle.Now()); err != nil {
		return rec, err
	}
	// Session 2 (P0-4): construct the descendant-owning containment scope
	// before launch, exactly once, and thread it via ctx to whichever
	// executor rn.Launch ends up calling. Extinguish (below, after Observe)
	// is the DESCENDANTS_TERMINATED lifecycle stage -- it runs
	// unconditionally on every path (success, backend error, timeout), and
	// approval is impossible without a recorded successful extinction proof.
	requireStrongDescendants := containment.RequiresStrongDescendantContainment(c, enforceLocalEffectful)
	descendants, descScopeErr := containment.NewScope(id, requireStrongDescendants, env.Containment)
	if descScopeErr != nil {
		return RunRecord{}, fmt.Errorf("descendant containment: %w", descScopeErr)
	}
	ctx = containment.WithScope(ctx, descendants)
	// Session 5 (Sol P0-3): the externally enforced sandbox (Landlock +
	// network namespace) requiring construction is exactly the condition
	// enforceContainment already evaluated once above (requiresEnforcementWrap)
	// -- not recomputed here. NewPlan refuses outright for a high-risk run on
	// a host that cannot actually provide it, the same fail-closed posture as
	// containment.NewScope just above for the descendant-owning primitive.
	enforcePlan, enforcePlanErr := enforce.NewPlanForExecutable(requiresEnforcementWrap, work, spec.Sandbox == agents.SandboxReadOnly, spec.Network, requiresEnforcementWrap, handle.CanonicalPath, append(localReadRoots(c.Local), env.CredentialRoots...))
	if enforcePlanErr != nil {
		return RunRecord{}, fmt.Errorf("external enforcement: %w", enforcePlanErr)
	}
	// Sol v9 P0-1/P0-2: enforcePlan may hold open descriptors (Governor's
	// own self-exe, the verified unshare handle) it launches through
	// instead of reopening by path -- release them once this run's launch
	// (further below, still within this function) has started, mirroring
	// handle.Close() just above for the backend's own resolved handle.
	defer func() { _ = enforcePlan.Close() }()
	if enforcePlan.Active && enforcePlan.ReadOnly {
		// Sol v7 S9: a read-only-mode contract's own compiled prompt still
		// instructs the backend to "write RESULT.json in the worktree" (every
		// mode, unconditionally), and a Produces-declaring contract (panel
		// members/comparison/judge) needs to land its artifact too --
		// Landlock's readOnly ruleset otherwise denies both with no
		// carve-out, so read-only jobs could never actually complete under
		// real enforcement. Both paths are pre-created here (host-side,
		// unconfined) because Landlock binds a rule to an already-opened
		// path; a not-yet-created directory or file can't be granted a rule
		// in advance.
		var writeDirs, writeFiles []string
		resultPath := filepath.Join(work, "RESULT.json")
		if _, err := os.Stat(resultPath); os.IsNotExist(err) {
			if err := os.WriteFile(resultPath, nil, 0644); err != nil {
				return RunRecord{}, fmt.Errorf("pre-create RESULT.json for read-only enforcement: %w", err)
			}
		}
		writeFiles = append(writeFiles, resultPath)
		if len(c.Produces) > 0 {
			artifactsDir := filepath.Join(work, ".governator", "artifacts")
			if err := os.MkdirAll(artifactsDir, 0755); err != nil {
				return RunRecord{}, fmt.Errorf("pre-create .governator/artifacts for read-only enforcement: %w", err)
			}
			writeDirs = append(writeDirs, artifactsDir)
		}
		enforcePlan = enforcePlan.WithWriteRoots(writeDirs, writeFiles)
	}
	if consumedBoundary == "landlock-mount-namespace-ro-bind" {
		enforcePlan = enforcePlan.WithReadOnlyBinds(enforce.ROBind{
			Src: stageDir,
			Dst: filepath.Join(work, ".governator", "consumed"),
		})
	}
	ctx = enforce.WithPlan(ctx, enforcePlan)
	// Sol P0-6 / Session 3: thread the run's single resolved handle to
	// whichever executor rn.Launch ends up calling (agents.defaultExecutor
	// or runner.LocalWorktreeRunner's executor both read it via
	// agents.HandleFromContext), so the launch execs the exact descriptor
	// already hashed above rather than a bare path a second time.
	ctx = agents.ContextWithHandle(ctx, handle)

	agentTimeout := remainingRunBudget(ctx)
	var ar agents.Result
	var aerr error
	if agentTimeout <= 0 {
		aerr = context.DeadlineExceeded
		ar.TimedOut = true
		// Nothing was ever launched on this path, so there is nothing for
		// the backend's own stage-level descendant scope to have failed to
		// extinguish (Sol redteam v7 S1 gap-closure) -- the zero value
		// would otherwise read as "extinction failed" below.
		ar.DescendantsGone = true
	} else {
		// Sol P1.1 (finding #8) / Sol P1-5 (attack 18): this is the governed
		// action's execution boundary — the last point before the backend
		// process actually starts. Consume every one-shot override the
		// policy gate resolved to ALLOW right here, as a single atomic
		// transaction (ConsumePolicyOverrideReservations), never one at a
		// time. Consuming the set one id per top-level statement let an
		// earlier id in the set be durably burned even when a later id's
		// consume failed and the whole launch aborted — an approval spent
		// for an execution that never happened. Atomic consume-all means a
		// single lost reservation (released/expired by a race — e.g. this
		// run's own TTL reclaim on a pathologically slow workspace-prep
		// path) leaves every id in the set exactly as it was: the run
		// returns an error and the deferred release above cleans up
		// whatever did stay reserved.
		consumeAt := time.Now().UTC().Format(time.RFC3339Nano)
		if cerr := observability.ConsumePolicyOverrideReservations(db, pendingOneShotIDs, consumeAt); cerr != nil {
			return rec, cerr
		}
		oneShotConsumed = true
		// Sol10 P0-1 checkpoint 1/4: verify every consumed artifact
		// immediately before the untrusted backend actually starts.
		if len(transaction.Artifacts) > 0 {
			if verr := verifyConsumedArtifacts(stageDir, transaction.Artifacts); verr != nil {
				return RunRecord{}, verr
			}
		}
		ar, aerr = rn.Launch(ctx, ws, runner.LaunchRequest{Agent: agent, Request: agents.Request{
			Prompt: prompt, Workdir: work, Transcript: transcript,
			Timeout: agentTimeout,
			Spec:    spec,
			// Sol Finding 5: hand the host launch the exact canonical path
			// already resolved above, instead of letting exec.Command silently
			// re-resolve the bare configured name through PATH a second time at
			// Start() — a second, independent resolution taken moments later is
			// the TOCTOU window the finding closes. Ignored by DockerRunner's
			// executor, which correctly launches the bare in-container name.
			ResolvedBin: handle.CanonicalPath,
		}})
	}
	// Session 3a: surface runner observations — limits/provenance as notes,
	// and output truncation as a loud OUTPUT_TRUNCATED ledger event. A run
	// requiring a complete transcript (docker.require_complete_transcript)
	// that was capped is turned into a blocking violation below, so a
	// truncated evidence trail can never be approved.
	obs, oerr := rn.Observe(ctx, ws)
	if oerr == nil {
		if obs.Notes != "" {
			rec.Notes = appendNote(rec.Notes, obs.Notes)
		}
		if obs.OutputTruncated {
			truncDetail := fmt.Sprintf("accepted=%d discarded=%d", obs.BytesAccepted, obs.BytesDiscarded)
			if err := lifecycle.Record(db, id, lifecycle.OutputTruncated, truncDetail, lifecycle.Now()); err != nil {
				payload, _ := json.Marshal(stageEventPayload{RunID: id, Stage: "OUTPUT_TRUNCATED", Detail: truncDetail})
				noteOperationalFailure(db, id, opStageEvent, err, string(payload))
			}
			rec.Notes = appendNote(rec.Notes, fmt.Sprintf("output_truncated: %d bytes discarded of %d total", obs.BytesDiscarded, obs.BytesAccepted+obs.BytesDiscarded))
		}
	}
	// Session 2 (P0-4): DESCENDANTS_TERMINATED. Freeze, kill, and wait for
	// kernel-confirmed extinction of the whole owned process tree -- setsid,
	// double fork, nohup, all of it -- before any final-state validation
	// runs. This must happen on every path (normal completion, backend
	// error, timeout alike); "the process exited" is never treated as proof
	// on its own. A failed/unconfirmed extinction is a hard stop: the run
	// never reaches S1's final-state fingerprint/tree capture.
	descProof, descErr := descendants.Extinguish(ctx, containment.DefaultExtinctionDeadline, work)
	descDetail, _ := json.Marshal(descProof)
	if err := lifecycle.Record(db, id, lifecycle.DescendantsTerminated, string(descDetail), lifecycle.Now()); err != nil {
		return rec, err
	}
	if descErr != nil {
		return RunRecord{}, fmt.Errorf("descendant containment: extinction not confirmed before final-state capture: %w", descErr)
	}
	// Sol redteam v7 S1 gap-closure: the backend launch itself now routes
	// through internal/stage.Executor (agents.LaunchStaged) when a Scope is
	// present, which builds and extinguishes its OWN independent per-stage
	// scope rather than registering into the run-level `descendants` scope
	// above -- the same shape shellStage's validators already use. This
	// run-level check therefore no longer covers the backend's own
	// descendants; ar.DescendantsGone (populated by every agents.Executor
	// implementation) is the equivalent proof for the backend specifically,
	// and must block the run exactly as strictly as descErr does above.
	if !ar.DescendantsGone {
		return RunRecord{}, fmt.Errorf("descendant containment: backend stage did not confirm descendant extinction")
	}
	// Sol10 P0-1 checkpoint 2/4: verify every consumed artifact immediately
	// after the backend's own descendant tree is kernel-confirmed extinct.
	if len(transaction.Artifacts) > 0 {
		if verr := verifyConsumedArtifacts(stageDir, transaction.Artifacts); verr != nil {
			return RunRecord{}, verr
		}
	}
	// Sol P0-3/P1-15 (Session 5) effect ledger: when this launch went through
	// Governator's own externally enforced sandbox, record what that
	// enforcement actually was and what the kernel observed -- independent
	// of anything the backend's own transcript claims. A best-effort,
	// non-blocking write: this is audit evidence, not a gate, so a ledger
	// write failure must never turn an otherwise-successful run into a
	// failure.
	if enforcePlan.Active {
		method := "landlock"
		if !enforcePlan.AllowNetwork {
			method = "landlock+netns"
		}
		enforcedNetwork := "deny"
		if enforcePlan.AllowNetwork {
			enforcedNetwork = "allow"
		}
		enfRec := observability.EnforcementRecord{
			RunID:                     id,
			Method:                    method,
			NetworkNamespaced:         !enforcePlan.AllowNetwork,
			ProcessesObservedPeak:     descProof.ProcessesObservedPeak,
			LandlockABI:               enforcePlan.LandlockABI,
			KernelReadEnvelope:        append([]string(nil), enforcePlan.ReadRoots...),
			DeclaredNetworkPolicy:     enforcedNetwork,
			EnforcedNetworkPolicy:     enforcedNetwork,
			NetworkAttemptObservation: "unavailable",
			NetworkDenialMechanism:    networkDenialMechanism(enforcePlan.Active, enforcePlan.AllowNetwork),
			DeclaredWriteRoots:        append(append([]string(nil), enforcePlan.WriteDirs...), enforcePlan.WriteFiles...),
			DeclaredCredentialPolicy:  declaredCredentialPolicy(c),
			ObservedCredentialAccess:  "unavailable",
			OutputConsequence:         "unobserved",
			ConsumedArtifactBoundary:  consumedBoundary,
			Created:                   time.Now().UTC().Format(time.RFC3339Nano),
		}
		if err := observability.RecordEnforcement(db, enfRec); err != nil {
			payload, _ := json.Marshal(enfRec)
			noteOperationalFailure(db, id, opStageEvent, err, string(payload))
		}
	} else if consumedBoundary != "" {
		// Sol10 P0-1: docker (and the mode-bits-degraded fallback) never go
		// through the enforcePlan.Active branch above at all, but the
		// consumed-artifact boundary mechanism must still be recorded
		// evidence regardless of which runner provided it.
		enfRec := observability.EnforcementRecord{RunID: id, ConsumedArtifactBoundary: consumedBoundary, Created: time.Now().UTC().Format(time.RFC3339Nano)}
		if err := observability.RecordEnforcement(db, enfRec); err != nil {
			payload, _ := json.Marshal(enfRec)
			noteOperationalFailure(db, id, opStageEvent, err, string(payload))
		}
	}
	// Sol redteam v4 S9 unified effect ledger: process_creation and
	// executable_launch rows are recorded for every run (descProof and
	// handle are always available once a backend actually launched),
	// independent of whether enforcePlan.Active gated this particular run —
	// EnforcementRecord above stays scoped to "was this run sandboxed and
	// how," this ledger is the lower-level "what did the kernel actually
	// see." file_write rows land later, once the workspace diff is final
	// (see the FINAL_VALIDATION_BARRIER block below) — changed/deleted
	// aren't known yet at this point in the pipeline. Same best-effort,
	// non-blocking posture as every other post-hoc ledger write in this
	// function.
	{
		now := time.Now().UTC().Format(time.RFC3339Nano)
		effects := make([]observability.EffectRecord, 0, 2)
		effects = append(effects, observability.EffectRecord{
			RunID: id, Kind: observability.EffectProcessCreation, Detail: string(descDetail), Created: now,
		})
		if handle != nil {
			launchDetail, _ := json.Marshal(handle.PathResolution)
			effects = append(effects, observability.EffectRecord{
				RunID: id, Kind: observability.EffectExecutableLaunch, Detail: string(launchDetail), Created: now,
			})
		}
		netDetail, _ := json.Marshal(map[string]bool{"namespaced": enforcePlan.Active && !enforcePlan.AllowNetwork})
		effects = append(effects, observability.EffectRecord{
			RunID: id, Kind: observability.EffectNetwork, Detail: string(netDetail), Created: now,
		})
		if err := observability.RecordEffects(db, effects); err != nil {
			payload, _ := json.Marshal(effects)
			noteOperationalFailure(db, id, opStageEvent, err, string(payload))
		}
	}
	redactErr := redact(transcript)
	audit := auditTranscript(transcript, agent.Capabilities().TranscriptFormat, work, c, env.ProtectedPatterns, env.Config.Doctrine.UnenforceableRuleAction, env.Config.Doctrine.TranscriptConformanceAction)
	if err := lifecycle.Record(db, id, lifecycle.Audited, "", lifecycle.Now()); err != nil {
		return rec, err
	}
	if len(audit.RuleViolations) > 0 {
		created := time.Now().UTC().Format(time.RFC3339Nano)
		ruleRows := make([]observability.PolicyRuleEventRecord, len(audit.RuleViolations))
		for i, rv := range audit.RuleViolations {
			ruleRows[i] = observability.PolicyRuleEventRecord{
				RunID: id, Rule: rv.Rule, Verdict: string(rv.Verdict), Detail: rv.Detail,
				CauseSeq: rv.CauseSeq, TriggerSeq: rv.TriggerSeq, Created: created,
			}
		}
		// Best-effort, like the assay bridge's evaluation write: a ledger
		// failure here must never block a run whose outcome was already
		// decided by the (already-applied) audit.Violations above. Session 4:
		// a failure no longer just vanishes — noteOperationalFailure durably
		// queues the write for `gov reconcile`.
		if err := observability.RecordPolicyRuleEvents(db, ruleRows); err != nil {
			payload, _ := json.Marshal(policyRuleEventsPayload{Rows: ruleRows})
			noteOperationalFailure(db, id, opPolicyRuleEvents, err, string(payload))
		}
	}
	rec.CostUSD = audit.CostUSD
	rec.Usage = audit.Usage
	rec.ToolCalls = audit.ToolCalls
	rec.TranscriptBytes = audit.TranscriptBytes
	if audit.CostUnavailable {
		rec.Notes = appendNote(rec.Notes, "cost_unavailable")
	}
	if !audit.Usage.Available {
		rec.Notes = appendNote(rec.Notes, "usage_unavailable")
	}
	// Infra classification (Session 2): a backend that could not be reached or
	// could not serve the request (rate limit, quota, auth, missing binary,
	// transient upstream) is an infrastructure failure, distinct from a quality
	// failure. It takes precedence over the quality taxonomy: a rate-limited
	// run produces no real work, so the gate's "required file missing" style
	// violations would otherwise mislabel it VALIDATION_FAILED. The infra kind
	// drives the circuit breaker; it is recorded in runs but never booked to
	// agent_profiles (rule 3). A success / quality failure stays InfraNone and
	// is handled by the breaker as "backend reachable" (RecordSuccess).
	infraKind := agents.ClassifyInfra(resolved.Agent, ar.ExitCode, aerr, transcriptTail(transcript, 4096))
	if infraKind != agents.InfraNone {
		rec.Notes = appendNote(rec.Notes, "infra_failure: "+string(infraKind))
	}
	workAfter, werr := fingerprint(work)
	liveAfter, lerr := fingerprint(root)
	protectedAfter, perr := protectedFingerprint(transaction.ProtectedPatterns)
	gitControlAfter, gcerr := gitControlFingerprint(work)
	violations := append([]string{}, audit.Violations...)
	violations = appendRuntimePathScanViolation(violations, "after agent execution", work)
	violations = append(violations, telemetryViolations(c, audit)...)
	violations = append(violations, effectLedgerViolations(handle)...)
	if redactErr != nil {
		violations = append(violations, "transcript redaction failed: "+redactErr.Error())
	}
	// Session 3a: a run whose transcript was capped is a blocking violation
	// when it required a complete (evidence-bearing) transcript — such a run
	// is quarantined, never approved on an incomplete audit trail. Non-
	// requiring runs still had the truncation recorded loudly above.
	// "Requiring" is not only the explicit opt-in flag: a blocking-assay run
	// is evidence-bearing by definition (its verdict gates the merge), so it
	// must never be approved on a capped transcript just because the operator
	// forgot to also set require_complete_transcript. And when Observe itself
	// failed we cannot PROVE the transcript is complete, which for a
	// completeness-requiring run is the same as incomplete (fail closed) —
	// the old `oerr == nil &&` guard silently skipped the whole check.
	//
	// Session 6 (Sol High 8/10): DockerRunner.Observe now also returns a
	// non-nil oerr whenever the docker config declared itself hardened and
	// Observe could not verify the applied container configuration actually
	// matched (inspection failure or a mismatch) — an unverified hardened
	// claim must never be approved. That case is unconditional, not gated
	// behind require_complete_transcript: a hardened run with no separate
	// completeness requirement must still not be approved on a hardened
	// claim it can't back up. A completeness-requiring run keeps the more
	// specific message below (it's the same oerr either way).
	switch {
	case oerr != nil && requiresCompleteTranscript(c):
		violations = append(violations, "runner observation failed: cannot verify transcript completeness (complete transcript required): "+oerr.Error())
	case oerr != nil:
		violations = append(violations, "docker hardened observation failed: "+oerr.Error())
	case obs.OutputTruncated && requiresCompleteTranscript(c):
		violations = append(violations, fmt.Sprintf(
			"output truncated: %d of %d transcript bytes discarded (complete transcript required)",
			obs.BytesDiscarded, obs.BytesAccepted+obs.BytesDiscarded))
	}
	var selfReviewJSON string
	rec.SelfReview, selfReviewJSON = readSelfReview(work)
	if before, ok := workBefore[canaryName]; !ok || workAfter[canaryName] != before {
		violations = append(violations, "canary mutation: "+canaryName)
	}
	if err := cleanupCanary(canaryPath); err != nil {
		violations = append(violations, "canary cleanup failed: "+err.Error())
	} else {
		delete(workBefore, canaryName)
		delete(workAfter, canaryName)
	}
	if aerr != nil {
		// A timeout produces BOTH a non-nil error (context.DeadlineExceeded)
		// and ExitCode -1 with TimedOut=true. Reporting all three inflates the
		// violation list and double-counts the same event in failure taxonomy.
		// Collapse to a single unambiguous "agent timeout" when the timer
		// fired; every other error path keeps its existing message.
		if ar.TimedOut {
			violations = append(violations, "agent timeout: exceeded budget.max_minutes")
		} else {
			violations = append(violations, "agent: "+aerr.Error())
			if ar.ExitCode != 0 {
				violations = append(violations, fmt.Sprintf("agent exit code %d", ar.ExitCode))
			}
		}
	} else if ar.ExitCode != 0 {
		violations = append(violations, fmt.Sprintf("agent exit code %d", ar.ExitCode))
	}
	if werr != nil {
		violations = append(violations, "worktree fingerprint: "+werr.Error())
	}
	if lerr != nil {
		violations = append(violations, "live fingerprint: "+lerr.Error())
	}
	if perr != nil {
		violations = append(violations, "protected fingerprint: "+perr.Error())
	}
	if gcerr != nil {
		violations = append(violations, "git control-plane fingerprint: "+gcerr.Error())
	} else if snapshotDigest(gitControlBefore) != snapshotDigest(gitControlAfter) {
		violations = append(violations, "git control-plane mutation")
	}
	protectedChanged, protectedDeleted := changes(protectedBefore, protectedAfter)
	if len(protectedChanged)+len(protectedDeleted) > 0 {
		violations = append(violations, "protected path mutation: "+strings.Join(append(protectedChanged, protectedDeleted...), ","))
	}
	rawChanged, rawDeleted := changes(workBefore, workAfter)
	if len(rawChanged)+len(rawDeleted) == 0 {
		rec.Notes = appendNote(rec.Notes, "fallback_worktree_unchanged")
	}
	var artifactRecords []observability.ArtifactRecord
	changed, deleted := filterSourceChanges(rawChanged, rawDeleted)
	liveChanged, liveDeleted := changes(liveBefore, liveAfter)
	if len(liveChanged)+len(liveDeleted) > 0 {
		violations = append(violations, "out-of-worktree mutation: "+strings.Join(append(liveChanged, liveDeleted...), ","))
	}
	for _, p := range append(append([]string{}, changed...), deleted...) {
		if !matchesAny(c.Allowed.Write, p) && p != "RESULT.json" {
			violations = append(violations, "write outside allowlist: "+p)
		}
		if matchesAny(c.Forbidden.Paths, p) {
			violations = append(violations, "forbidden path: "+p)
		}
		if !policy.MatchesAny(c.Preflight.IntendedWrites, p) && p != "RESULT.json" {
			violations = append(violations, "write outside intended_writes: "+p)
		}
	}
	// Sol P1-15 (Session 5): the backend's self-reported RESULT.json
	// files_changed is explanatory evidence only -- every enforcement
	// decision above and below already keys off changed/deleted, the
	// EXTERNALLY measured worktree diff, never the transcript's claim.
	// Surfaced as a note, not a blocking violation: an undisclosed path that
	// is ALSO out of scope is already caught (and blocks) via the
	// allowlist/forbidden/intended-writes checks above, on the external diff
	// alone -- this note exists for a permitted change the backend simply
	// never bothered to list, which is sloppy bookkeeping, not evidence of
	// concealment, and turning it into a hard quarantine would make an
	// incomplete self-report as costly as a malicious one.
	if undisclosed := undisclosedChanges(rec.SelfReview, changed, deleted); len(undisclosed) > 0 {
		rec.Notes = appendNote(rec.Notes, "transcript_effect_mismatch: self-reported files_changed omitted "+strings.Join(undisclosed, ","))
	}
	if len(changed)+len(deleted) > c.Budget.MaxFilesChanged {
		violations = append(violations, "max_files_changed exceeded")
	}
	if len(deleted) > c.Budget.MaxDeleted {
		violations = append(violations, "max_deleted exceeded")
	}
	metrics := measureDiff(root, work, git, workBefore, changed, deleted)
	if metrics.Lines > c.Budget.MaxLinesChanged {
		violations = append(violations, fmt.Sprintf("max_lines_changed exceeded: %d > %d", metrics.Lines, c.Budget.MaxLinesChanged))
	}
	if metrics.NewFiles > c.Budget.MaxNewFiles {
		violations = append(violations, fmt.Sprintf("max_new_files exceeded: %d > %d", metrics.NewFiles, c.Budget.MaxNewFiles))
	}
	for _, p := range c.Success.RequiredFiles {
		found := false
		for n := range workAfter {
			if glob(p, n) {
				found = true
				break
			}
		}
		if !found {
			violations = append(violations, "required file missing: "+p)
		}
	}
	if err := lifecycle.Record(db, id, lifecycle.Validating, "", lifecycle.Now()); err != nil {
		return rec, err
	}
	// Sol10 P0-1 checkpoint 3/4: verify every consumed artifact immediately
	// before the validator phase a validator that reads it might run in.
	if len(transaction.Artifacts) > 0 {
		if verr := verifyConsumedArtifacts(stageDir, transaction.Artifacts); verr != nil {
			violations = append(violations, verr.Error())
		}
	}
	for validatorIndex, v := range c.Success.Validators {
		vctx, cancel, deadlineErr := stageTimeout(ctx, "success validator")
		if deadlineErr != nil {
			violations = append(violations, deadlineErr.Error())
			break
		}
		// Sol9 P0-5: a structured validator (one whose spec declared
		// tools, materialized into a sealed dir above) runs with PATH =
		// that sealed dir alone -- no ambient base PATH, no auto-added
		// git directory. A legacy/structured-no-tools validator (nil
		// entry here) keeps the pre-fix ambient behavior, exactly as
		// shellStage's structured flag below decides.
		var toolDirs []string
		var sealedReadRoots []string
		if validatorIndex < len(successValidatorSealed) && successValidatorSealed[validatorIndex] != nil {
			sealed := successValidatorSealed[validatorIndex]
			toolDirs = []string{sealed.Path}
			sealedReadRoots = sealed.ReadRoots
			// Sol9 P1-4: re-verify every sealed tool copy immediately
			// before the validator process that will find them through
			// PATH=sealed.Path starts -- a private read-only copy is not
			// kernel-immutable, so this is the last point Governator can
			// catch a same-UID tamper before launch.
			verifyFailed := false
			for _, cp := range sealed.Copies {
				if verr := cp.Verify(); verr != nil {
					violations = append(violations, "verify sealed validator tool before launch: "+verr.Error())
					verifyFailed = true
				}
			}
			if verifyFailed {
				cancel()
				break
			}
		}
		var validatorSpec *contracts.ValidatorSpec
		if validatorIndex < len(c.Success.ValidatorSpecs) {
			validatorSpec = &c.Success.ValidatorSpecs[validatorIndex]
		}
		authority := validatorAuthority(work, validatorSpec, false, requireStrongDescendants)
		authority.ReadRoots = append(authority.ReadRoots, sealedReadRoots...)
		if externalConsumedStore {
			// Sol10 P0-1: internal/stage.Executor compiles its own fresh
			// enforce.Plan for this validator launch, independent of the
			// backend's -- it needs its own ro-bind to see consumed
			// artifacts at all now that they no longer live under work.
			authority.ROBinds = append(authority.ROBinds, enforce.ROBind{Src: stageDir, Dst: filepath.Join(work, ".governator", "consumed")})
		}
		code, out, e, extinctionErr := shellStage(vctx, id, "success-validator", work, v, authority, env.Controller, toolDirs, env.ToolRegistry)
		cancel()
		if extinctionErr != nil {
			violations = append(violations, "success validator descendant containment: "+extinctionErr.Error())
		}
		if e != nil {
			out += "\n" + e.Error()
		}
		recordValidatorEvidence(db, id, v, code, out, "success")
		beforeScan := len(violations)
		violations = appendRuntimePathScanViolation(violations, "after success validator", work)
		if len(violations) > beforeScan {
			break
		}
		if code != 0 || e != nil {
			if errors.Is(e, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
				violations = append(violations, fmt.Sprintf("run deadline exceeded during success validator: %s", v))
			} else {
				violations = append(violations, fmt.Sprintf("validator failed (%d): %s", code, v))
			}
		}
	}
	// Cleanup runs as a distinct pre-merge stage once every success validator
	// has passed (doctrine gap #5): a lint/format/temp-file tidy pass with
	// its own ledger rows (stage='cleanup') instead of being folded into
	// success.validators. Required governs whether a failure blocks the
	// merge like a success validator; unset (the default) records the run
	// for visibility without gating it.
	if len(violations) == 0 && c.Cleanup != nil {
		for i, v := range c.Cleanup.Validators {
			vctx, cancel, deadlineErr := stageTimeout(ctx, "cleanup validator")
			if deadlineErr != nil {
				if c.Cleanup.Required {
					violations = append(violations, deadlineErr.Error())
				}
				break
			}
			// Sol9 P0-5: same structured-validator PATH policy as the
			// success loop above. A structured cleanup validator runs
			// with PATH = its sealed dir alone; legacy cleanup
			// validators keep the ambient behavior.
			var toolDirs []string
			var sealedReadRoots []string
			if i < len(cleanupValidatorSealed) && cleanupValidatorSealed[i] != nil {
				sealed := cleanupValidatorSealed[i]
				toolDirs = []string{sealed.Path}
				sealedReadRoots = sealed.ReadRoots
				// Sol9 P1-4: same immediately-before-launch re-verification
				// as the success loop above. Unconditional regardless of
				// c.Cleanup.Required, matching the extinction-failure
				// posture below -- a same-UID tamper of a sealed tool is a
				// security event, never merely "the lint pass had a bad
				// day."
				verifyFailed := false
				for _, cp := range sealed.Copies {
					if verr := cp.Verify(); verr != nil {
						violations = append(violations, "verify sealed cleanup validator tool before launch: "+verr.Error())
						verifyFailed = true
					}
				}
				if verifyFailed {
					cancel()
					break
				}
			}
			var validatorSpec *contracts.ValidatorSpec
			if i < len(c.Cleanup.ValidatorSpecs) {
				validatorSpec = &c.Cleanup.ValidatorSpecs[i]
			}
			authority := validatorAuthority(work, validatorSpec, true, requireStrongDescendants)
			authority.ReadRoots = append(authority.ReadRoots, sealedReadRoots...)
			if externalConsumedStore {
				// Sol10 P0-1: same reasoning as the success-validator loop
				// above -- and read-only regardless of this cleanup
				// validator's own write authority elsewhere in the
				// workspace, since the ro-bind's RODirs rule is bound to a
				// separate mount Landlock governs independently of the
				// workspace's write grants.
				authority.ROBinds = append(authority.ROBinds, enforce.ROBind{Src: stageDir, Dst: filepath.Join(work, ".governator", "consumed")})
			}
			code, out, e, extinctionErr := shellStage(vctx, id, "cleanup-validator", work, v, authority, env.Controller, toolDirs, env.ToolRegistry)
			cancel()
			// Sol redteam v7 S1 cleanup-specific fail-open defect: Required
			// governs whether a nonzero cleanup EXIT CODE blocks the merge
			// (line below) -- it must never also govern whether a failure to
			// PROVE DESCENDANT EXTINCTION is acceptable. "Cleanup is
			// optional" means "we don't care if the lint/format pass itself
			// failed," never "we don't care whether something it spawned is
			// still alive and unaccounted for." Unconditional regardless of
			// c.Cleanup.Required.
			if extinctionErr != nil {
				violations = append(violations, "cleanup validator descendant containment: "+extinctionErr.Error())
			}
			if e != nil {
				out += "\n" + e.Error()
			}
			recordValidatorEvidence(db, id, v, code, out, "cleanup")
			beforeScan := len(violations)
			violations = appendRuntimePathScanViolation(violations, "after cleanup validator", work)
			if len(violations) > beforeScan {
				break
			}
			if (code != 0 || e != nil) && c.Cleanup.Required {
				if errors.Is(e, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
					violations = append(violations, fmt.Sprintf("run deadline exceeded during cleanup validator: %s", v))
				} else {
					violations = append(violations, fmt.Sprintf("cleanup validator failed (%d): %s", code, v))
				}
			}
		}
	}
	// PostRunValidate is the in-process extension of the validator gate above
	// for checks too structured for a shell one-liner (e.g. `gov plan`'s
	// PLAN.yaml post-gate). It only runs once every shell validator has
	// already passed, and — like them — strictly before the merge below, so
	// a failure here blocks the merge exactly as a failed shell validator
	// would.
	if len(violations) == 0 && c.PostRunValidate != nil {
		if err := c.PostRunValidate(work); err != nil {
			violations = append(violations, "post-run validation failed: "+err.Error())
		}
		violations = appendRuntimePathScanViolation(violations, "after post-run validation", work)
	}
	// Assay (Phase 3A: Governator<->Assayer synchronous bridge). Runs in the
	// same position as the validators above — after every shell/PostRunValidate
	// check has passed, strictly before the merge below — so a blocking
	// FAIL/ERROR verdict quarantines the run through the exact same
	// `violations` mechanism a failed validator uses (reused, not
	// duplicated). advisory/telemetry verdicts are ledgered but never
	// appended to violations, so they never affect the merge decision.
	// c.Assay == nil (every job YAML predating this field) skips this block
	// entirely — no ledger row, no behavior change. c.Assay != nil but assay
	// not configured in Governator's own config still writes a
	// VerdictSkipped row, so "skipped" is always visible and distinguishable
	// from "never asked for" in the ledger.
	// Sol10 P0-1 checkpoint 4/4: verify every consumed artifact after all
	// validation (success validators, cleanup validators, PostRunValidate,
	// Assay) has run, immediately before the final structural barrier and
	// merge decision below.
	if len(violations) == 0 && len(transaction.Artifacts) > 0 {
		if verr := verifyConsumedArtifacts(stageDir, transaction.Artifacts); verr != nil {
			violations = append(violations, verr.Error())
		}
	}
	var approvedFinal finalStateMeasurement
	if len(violations) == 0 {
		var finalViolations []string
		approvedFinal, finalViolations = finalValidationMeasurement(ctx, r.Home, root, work, id, git, c, env.ProtectedPatterns, workBefore, liveBefore, protectedBefore, gitControlBefore)
		// Preserve the final barrier's remeasured evidence even when that
		// measurement produces a quarantining violation. Artifact schema failures,
		// for example, must still ledger the recollected artifact with
		// schema_ok=false so operators can inspect the exact rejected payload.
		changed = approvedFinal.changed
		deleted = approvedFinal.deleted
		artifactRecords = approvedFinal.artifactRecords
		if approvedFinal.diff != "" {
			rec.Diff = approvedFinal.diff
		}
		violations = append(violations, finalViolations...)
	}
	if len(violations) == 0 && c.Assay != nil {
		if err := lifecycle.Record(db, id, lifecycle.Assaying, "", lifecycle.Now()); err != nil {
			return rec, err
		}
		runAssayStep(ctx, db, cfg, c, id, hash, rec.Agent, artifactRecords, &violations, assaySnapshot)
	}
	if len(violations) == 0 {
		finalAfterAssay, finalViolations := finalValidationMeasurement(ctx, r.Home, root, work, id, git, c, env.ProtectedPatterns, workBefore, liveBefore, protectedBefore, gitControlBefore)
		changed = finalAfterAssay.changed
		deleted = finalAfterAssay.deleted
		artifactRecords = finalAfterAssay.artifactRecords
		if finalAfterAssay.diff != "" {
			rec.Diff = finalAfterAssay.diff
		}
		violations = append(violations, finalViolations...)
		if len(finalViolations) == 0 && c.Assay != nil {
			violations = append(violations, finalStateDeltaViolations(approvedFinal, finalAfterAssay)...)
		}
		if len(violations) == 0 {
			detail, _ := json.Marshal(map[string]any{"worktree_digest": snapshotDigest(finalAfterAssay.work), "paths": append(append([]string{}, changed...), deleted...)})
			if err := lifecycle.Record(db, id, lifecycle.FinalValidationBarrier, string(detail), lifecycle.Now()); err != nil {
				violations = append(violations, "final barrier ledger: "+err.Error())
			}
		}
	}
	if rec.Diff == "" {
		rec.Diff = workspaceDiff(root, work, git, changed, deleted)
	}
	rootCommitted := false
	if len(violations) == 0 {
		if git {
			mergePaths := append(append([]string{}, changed...), deleted...)
			if err := requireCleanLiveRoot(ctx, root); err != nil {
				violations = append(violations, err.Error())
			}
			if len(violations) == 0 {
				detail, _ := json.Marshal(map[string]any{"previous_head": head, "paths": mergePaths})
				if err := lifecycle.Record(db, id, lifecycle.MergeIntent, string(detail), lifecycle.Now()); err != nil {
					violations = append(violations, "merge intent ledger: "+err.Error())
				}
			}
			// Sol redteam v4 S1: the merge tree is built and independently
			// verified via internal/gitplumb, in an isolated index outside any
			// worktree — never `git add`/`git commit` in repository context
			// (P0-1: no hook, filter, or signing program can run with
			// Governator's authority; P0-2/P1-9: every path is literal, never a
			// pathspec, checked byte-wise, never shell-parsed).
			var mergeResult *approvedMergeResult
			if len(violations) == 0 {
				built, err := buildApprovedMergeTree(ctx, root, work, head, changed, deleted)
				if err != nil {
					violations = append(violations, err.Error())
				} else {
					mergeResult = built
				}
			}
			if len(violations) == 0 {
				cm := fmt.Sprintf("Governator job %s\n\nGov-Run: %s", c.JobID, id)
				commit, err := commitAndSyncRoot(ctx, mergeResult, root, work, head, cm, changed, deleted)
				if err != nil {
					violations = append(violations, err.Error())
				} else {
					rec.Commit = commit
				}
			} else if mergeResult != nil {
				mergeResult.session.Close()
			}
			if len(violations) == 0 {
				if err := lifecycle.Record(db, id, lifecycle.MergeApplied, "", lifecycle.Now()); err != nil {
					violations = append(violations, "merge applied ledger: "+err.Error())
				}
			}
			if len(violations) > 0 {
				if err := rollbackLiveRoot(ctx, root, head, liveBefore, mergePaths); err != nil {
					violations = append(violations, "merge rollback: "+err.Error())
				}
			}
			if len(violations) == 0 {
				rootCommitted = true
				if err := lifecycle.Record(db, id, lifecycle.RootCommitted, rec.Commit, lifecycle.Now()); err != nil {
					payload, _ := json.Marshal(stageEventPayload{RunID: id, Stage: "ROOT_COMMITTED", Detail: rec.Commit})
					noteOperationalFailure(db, id, opStageEvent, err, string(payload))
				}
			}
		} else {
			if err := captureRecall(r.Home, id, root, append(append([]string{}, changed...), deleted...)); err != nil {
				violations = append(violations, "recall snapshot: "+err.Error())
			}
			// Sol P1-8 / report §9 attack 23: mergeCopyChanged applies
			// changed paths to the live (non-git) root sequentially with no
			// atomicity -- an error partway through (a destination parent
			// blocked by a plain file, disk full, permission denied) used to
			// leave the root with only some of the approved changes landed:
			// a QUARANTINED run that still mutated the live root, never an
			// all-or-nothing merge (the guarantee the git branch above
			// already has via buildApprovedMergeTree + rollbackLiveRoot).
			// Fixed by wiring the recall snapshot captured just above into
			// an automatic rollback on any violation from the copy/delete
			// loops, mirroring the git branch's rollback-on-violation shape.
			// captureRecall must have succeeded first (checked below) -- a
			// failed snapshot means there is nothing safe to roll back to,
			// so nothing gets copied at all rather than risking an
			// unrecoverable partial merge.
			if len(violations) == 0 {
				violations = append(violations, mergeCopyChanged(work, root, changed)...)
				for _, p := range deleted {
					if err := os.Remove(filepath.Join(root, filepath.FromSlash(p))); err != nil && !os.IsNotExist(err) {
						violations = append(violations, "merge delete: "+err.Error())
					}
				}
				if len(violations) > 0 {
					if err := restoreRecall(r.Home, id, root); err != nil {
						violations = append(violations, "non-git merge rollback: "+err.Error())
					}
				}
			}
		}
		if len(violations) == 0 {
			if err := lifecycle.Record(db, id, lifecycle.Merged, "", lifecycle.Now()); err != nil {
				if rootCommitted {
					payload, _ := json.Marshal(stageEventPayload{RunID: id, Stage: "MERGED", Detail: ""})
					noteOperationalFailure(db, id, opStageEvent, err, string(payload))
				} else {
					return rec, err
				}
			}
		}
	}
	files := make([]observability.FileFact, 0, len(changed)+len(deleted))
	for _, path := range changed {
		changeType := "new"
		if _, existed := workBefore[path]; existed {
			changeType = "modified"
		}
		files = append(files, observability.FileFact{Path: path, ChangeType: changeType})
	}
	for _, path := range deleted {
		files = append(files, observability.FileFact{Path: path, ChangeType: "deleted"})
	}
	commands := make([]observability.CommandFact, 0, len(audit.Commands))
	for _, command := range audit.Commands {
		classification := "execute shell"
		if class := policy.ClassifyShellCommand(command, false); class != nil {
			classification = class.Verb + " " + class.Resource
		}
		commands = append(commands, observability.CommandFact{Command: command, Classification: classification})
	}
	if RuntimeGOOS == "darwin" {
		violations = append(violations, "darwin builds are feature-limited and may not approve or merge governed runs")
	}
	if len(violations) == 0 && infraKind == agents.InfraNone {
		rec.Status = "APPROVED"
		rec.Message = "merge gate passed"
		rec.ValidOutput = true
	} else {
		rec.Status = "QUARANTINED"
		rec.Message = strings.Join(violations, "; ")
		if infraKind != agents.InfraNone {
			// Infra takes precedence: the backend did not produce real work,
			// so the gate violations (required file missing, etc.) describe
			// the symptom, not the cause.
			rec.FailureTaxonomy = string(infraKind)
		} else {
			rec.FailureTaxonomy = observability.ClassifyFailure(violations)
		}
		if git {
			commit, err := preserveQuarantineWorktree(ctx, work, head, id)
			if err != nil {
				rec.Message = strings.TrimSpace(rec.Message + "; " + err.Error())
			} else {
				rec.Commit = commit
			}
		}
	}
	ledgerPending := func(opKind string, opErr error, payload string) (RunRecord, error) {
		noteOperationalFailure(db, id, opKind, opErr, payload)
		rec.Status = "MERGED_LEDGER_PENDING"
		rec.Message = "root committed; ledger finalization pending: " + opErr.Error()
		_, _ = db.Exec(`UPDATE runs SET status=?,message=?,commit_hash=?,identity_hash=? WHERE id=?`, rec.Status, rec.Message, rec.Commit, rec.IdentityHash, rec.ID)
		_ = lifecycle.Record(db, id, lifecycle.MergedLedgerPending, opKind+": "+opErr.Error(), lifecycle.Now())
		return rec, nil
	}
	if rootCommitted {
		if err := lifecycle.Record(db, id, lifecycle.LedgerFinalizing, "", lifecycle.Now()); err != nil {
			payload, _ := json.Marshal(stageEventPayload{RunID: id, Stage: "LEDGER_FINALIZING", Detail: ""})
			return ledgerPending(opStageEvent, err, string(payload))
		}
	}
	if err := lifecycle.Record(db, id, lifecycle.Stage(rec.Status), "", lifecycle.Now()); err != nil {
		if rootCommitted {
			payload, _ := json.Marshal(stageEventPayload{RunID: id, Stage: rec.Status, Detail: ""})
			return ledgerPending(opStageEvent, err, string(payload))
		}
		return rec, err
	}
	approved := head
	if rec.Status == "APPROVED" && git {
		approved, _ = gitHead(root)
	}
	// Finalize the ExecutionIdentity's ApprovedHead to the post-merge HEAD for
	// an approved git run (mirroring the approved_head column): a subsequent
	// run whose current HEAD equals this post-merge HEAD then matches the
	// identity and replays. For non-git or non-approved runs the pre-launch
	// head stands. Recomputing the hash here (rather than at insertRun) is
	// what makes the stored identity reflect the commit the approval landed
	// on, not the commit the run started from.
	identity.ApprovedHead = approved
	rec.IdentityHash = identity.Hash()
	if err := updateRun(db, rec, approved); err != nil {
		if rootCommitted {
			payload, _ := json.Marshal(runUpdatePayload{Record: rec, Approved: approved})
			return ledgerPending(opRunUpdate, err, string(payload))
		}
		return rec, err
	}
	remaining := remainingRunBudget(ctx)
	if remaining > 0 {
		rec.Notes = appendNote(rec.Notes, fmt.Sprintf("run_wall_time_ms=%d remaining_budget_ms=%d", time.Since(runStarted).Milliseconds(), remaining.Milliseconds()))
	} else {
		rec.Notes = appendNote(rec.Notes, fmt.Sprintf("run_wall_time_ms=%d remaining_budget_ms=0", time.Since(runStarted).Milliseconds()))
	}
	completion := observability.Completion{
		RunID:           rec.ID,
		Agent:           rec.Agent,
		JobType:         rec.JobType,
		Status:          rec.Status,
		CostUSD:         rec.CostUSD,
		ValidOutput:     rec.ValidOutput,
		FailureTaxonomy: rec.FailureTaxonomy,
		SelfReviewJSON:  selfReviewJSON,
		Notes:           rec.Notes,
		Files:           files,
		Commands:        commands,
		Violations:      violations,
		Usage:           rec.Usage,
		ToolCalls:       rec.ToolCalls,
		TranscriptBytes: rec.TranscriptBytes,
	}
	if err := observability.RecordCompletion(db, completion); err != nil {
		if rootCommitted {
			payload, _ := json.Marshal(completionPayload{Record: completion})
			return ledgerPending(opRunCompletion, err, string(payload))
		}
		return rec, err
	}
	if enforcePlan.Active {
		method := "landlock"
		if !enforcePlan.AllowNetwork {
			method = "landlock+netns"
		}
		enforcedNetwork := "deny"
		if enforcePlan.AllowNetwork {
			enforcedNetwork = "allow"
		}
		actualWriteSet := make([]string, 0, len(files))
		for _, file := range files {
			actualWriteSet = append(actualWriteSet, file.Path)
		}
		outputConsequence := "complete"
		if obs.OutputTruncated {
			if requiresCompleteTranscript(c) {
				outputConsequence = "truncated_blocks_approval"
			} else {
				outputConsequence = "truncated_nonblocking"
			}
		}
		enfRec := observability.EnforcementRecord{
			RunID:                     id,
			Method:                    method,
			NetworkNamespaced:         !enforcePlan.AllowNetwork,
			ProcessesObservedPeak:     descProof.ProcessesObservedPeak,
			LandlockABI:               enforcePlan.LandlockABI,
			KernelReadEnvelope:        append([]string(nil), enforcePlan.ReadRoots...),
			DeclaredNetworkPolicy:     enforcedNetwork,
			EnforcedNetworkPolicy:     enforcedNetwork,
			NetworkAttemptObservation: "unavailable",
			NetworkDenialMechanism:    networkDenialMechanism(enforcePlan.Active, enforcePlan.AllowNetwork),
			DeclaredWriteRoots:        append(append([]string(nil), enforcePlan.WriteDirs...), enforcePlan.WriteFiles...),
			ActualWriteSet:            actualWriteSet,
			DeclaredCredentialPolicy:  declaredCredentialPolicy(c),
			ObservedCredentialAccess:  "unavailable",
			OutputConsequence:         outputConsequence,
			Created:                   time.Now().UTC().Format(time.RFC3339Nano),
		}
		if err := observability.RecordEnforcement(db, enfRec); err != nil {
			payload, _ := json.Marshal(enfRec)
			noteOperationalFailure(db, id, opStageEvent, err, string(payload))
		}
	}
	artifactsCreated := time.Now().UTC().Format(time.RFC3339Nano)
	if err := observability.RecordArtifacts(db, artifactRecords, artifactsCreated); err != nil {
		if rootCommitted {
			payload, _ := json.Marshal(artifactsPayload{Records: artifactRecords, Created: artifactsCreated})
			return ledgerPending(opRunArtifacts, err, string(payload))
		}
		return rec, err
	}
	if quotaReservation.ID != 0 {
		measuredQuota := quotaUsageEstimate
		if rec.Usage.Available && rec.Usage.TotalTokens > 0 {
			measuredQuota = float64(rec.Usage.TotalTokens)
		}
		if err := quota.Settle(db, quotaReservation.ID, measuredQuota, time.Now().UTC()); err != nil {
			if rootCommitted {
				payload, _ := json.Marshal(quotaSettlePayload{ReservationID: quotaReservation.ID, Measured: measuredQuota})
				return ledgerPending(opQuotaSettle, err, string(payload))
			}
			return rec, err
		}
		quotaSettled = true
	}
	if spendReservation.ID != 0 {
		costAvailable := !audit.CostUnavailable
		if err := spend.SettleGlobal(db, spendReservation.ID, rec.CostUSD, costAvailable, time.Now().UTC()); err != nil {
			if rootCommitted {
				payload, _ := json.Marshal(spendSettlePayload{ReservationID: spendReservation.ID, ActualUSD: rec.CostUSD, CostAvailable: costAvailable})
				return ledgerPending(opSpendSettle, err, string(payload))
			}
			return rec, err
		}
		spendSettled = true
	}
	if infraKind == agents.InfraQuotaExhausted || infraKind == agents.InfraRateLimit {
		if resetAt, ok := agents.ResetHint(transcriptTail(transcript, 4096), time.Now().UTC()); ok {
			if err := quota.ApplyResetHint(db, rec.Agent, quota.DefaultAccount, resetAt, time.Now().UTC()); err != nil {
				payload, _ := json.Marshal(quotaResetHintPayload{Agent: rec.Agent, Account: quota.DefaultAccount, ResetAt: resetAt})
				noteOperationalFailure(db, rec.ID, opQuotaResetHint, err, string(payload))
			}
		}
	}
	// Circuit-breaker feedback (Session 2). A run that proved the backend was
	// reachable — APPROVED, or a quality quarantine (the backend answered but
	// produced bad work) — closes a probe / clears DEGRADED. Only an infra
	// failure opens or extends a breaker (rule 3). A SPEND_CAP refusal never
	// reaches here (it returns before the workspace is created). Breaker write
	// errors are non-fatal — a failed audit row must not quarantine an
	// otherwise approved run (the decision already landed) — but since
	// Session 4 they are durably queued via noteOperationalFailure instead of
	// being swallowed outright.
	if infraKind != agents.InfraNone {
		if err := breaker.RecordFailure(db, rec.Agent, string(infraKind), time.Now().UTC()); err != nil {
			payload, _ := json.Marshal(breakerFeedbackPayload{Agent: rec.Agent, FailureKind: string(infraKind)})
			noteOperationalFailure(db, rec.ID, opBreakerFailure, err, string(payload))
		}
	} else if rec.FailureTaxonomy != "SPEND_CAP" {
		if err := breaker.RecordSuccess(db, rec.Agent, time.Now().UTC()); err != nil {
			payload, _ := json.Marshal(breakerFeedbackPayload{Agent: rec.Agent})
			noteOperationalFailure(db, rec.ID, opBreakerSuccess, err, string(payload))
		}
	}
	if err := spend.MaybeHalt(cfg, db); err != nil {
		noteOperationalFailure(db, rec.ID, opSpendHaltCheck, err, "{}")
	}
	if rootCommitted {
		if err := lifecycle.Record(db, id, lifecycle.Complete, "", lifecycle.Now()); err != nil {
			payload, _ := json.Marshal(stageEventPayload{RunID: id, Stage: "COMPLETE", Detail: ""})
			noteOperationalFailure(db, id, opStageEvent, err, string(payload))
		}
	}
	runApproved := rec.Status == "APPROVED"
	destroyWorkspaceWithOutbox(db, rec.ID, rn, ws, runApproved)
	cleanupPending = false
	return rec, nil
}

func captureRecall(home, id, root string, paths []string) error {
	dir := filepath.Join(home, "recall", id)
	state := map[string]bool{}
	for _, p := range paths {
		src := filepath.Join(root, filepath.FromSlash(p))
		if _, err := os.Stat(src); err == nil {
			state[p] = true
			dst := filepath.Join(dir, "files", filepath.FromSlash(p))
			if err := os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
				return err
			}
			if err := copyFile(src, dst); err != nil {
				return err
			}
		} else if os.IsNotExist(err) {
			state[p] = false
		} else {
			return err
		}
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	b, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "manifest.json"), b, 0600)
}

func restoreRecall(home, id, root string) error {
	dir := filepath.Join(home, "recall", id)
	b, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return err
	}
	state := map[string]bool{}
	if err := json.Unmarshal(b, &state); err != nil {
		return err
	}
	for p, existed := range state {
		dst := filepath.Join(root, filepath.FromSlash(p))
		if !existed {
			if err := os.Remove(dst); err != nil && !os.IsNotExist(err) {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
			return err
		}
		if err := copyFile(filepath.Join(dir, "files", filepath.FromSlash(p)), dst); err != nil {
			return err
		}
	}
	return nil
}

// mergeCopyChanged copies every changed path from the disposable worktree
// back into the live (non-git) root and returns one "merge copy: ..."
// violation per path that failed, instead of dropping the failure.
func mergeCopyChanged(work, root string, changed []string) []string {
	var violations []string
	for _, p := range changed {
		src := filepath.Join(work, filepath.FromSlash(p))
		dst := filepath.Join(root, filepath.FromSlash(p))
		copyErr := os.MkdirAll(filepath.Dir(dst), 0755)
		if copyErr == nil {
			copyErr = copyFile(src, dst)
		}
		if copyErr != nil {
			violations = append(violations, "merge copy: "+copyErr.Error())
		}
	}
	return violations
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	st, err := in.Stat()
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, st.Mode())
	if err != nil {
		return err
	}
	_, e := io.Copy(out, in)
	ce := out.Close()
	if e != nil {
		return e
	}
	return ce
}

func Rollback(ctx context.Context, id string) (RunRecord, error) {
	r, err := Last(id)
	if err != nil {
		return r, err
	}
	if r.Status != "APPROVED" {
		return r, fmt.Errorf("run %s is not approved", r.ID)
	}
	if r.Commit == "" {
		release, lockErr := lock(r.Root, Home())
		if lockErr != nil {
			return r, lockErr
		}
		defer release()
		if restoreErr := restoreRecall(Home(), r.ID, r.Root); restoreErr != nil {
			return r, restoreErr
		}
		db, openErr := dbOpen(Home())
		if openErr != nil {
			return r, openErr
		}
		defer db.Close()
		_, openErr = db.Exec(`UPDATE runs SET status='ROLLED_BACK',message=? WHERE id=?`, "restored recall snapshot", r.ID)
		r.Status, r.Message = "ROLLED_BACK", "restored recall snapshot"
		if openErr == nil {
			openErr = lifecycle.Record(db, r.ID, lifecycle.RolledBack, "", lifecycle.Now())
		}
		return r, openErr
	}
	release, err := lock(r.Root, Home())
	if err != nil {
		return r, err
	}
	defer release()
	code, out, e := shell(ctx, r.Root, "git revert --no-edit "+shQuote(r.Commit))
	if e != nil || code != 0 {
		return r, fmt.Errorf("git revert: %s", out)
	}
	db, e := dbOpen(Home())
	if e != nil {
		return r, e
	}
	defer db.Close()
	_, e = db.Exec(`UPDATE runs SET status='ROLLED_BACK',message=? WHERE id=?`, "reverted "+r.Commit, r.ID)
	if e == nil {
		e = lifecycle.Record(db, r.ID, lifecycle.RolledBack, "", lifecycle.Now())
	}
	r.Status = "ROLLED_BACK"
	r.Message = "reverted " + r.Commit
	return r, e
}

func MarshalRecord(r RunRecord) string { b, _ := json.MarshalIndent(r, "", "  "); return string(b) }

// routeDecisionRecord maps a broker Decision to its persistence shape: one
// row per candidate (excluded ones included with their reason) so the ledger
// alone fully explains every routing decision. preview is false here — a real
// launch always records a non-preview decision; `gov route --explain` is the
// print-only path and writes nothing.
func routeDecisionRecord(d router.Decision, runID, created string) observability.RouteDecisionRecord {
	rows := make([]observability.RouteDecisionRow, 0, len(d.Candidates))
	for _, c := range d.Candidates {
		rows = append(rows, observability.RouteDecisionRow{
			Candidate:            c.Agent,
			ValidRateScore:       c.ValidRateScore,
			FailureSeverityScore: c.FailureSeverityScore,
			CostScore:            c.CostScore,
			BreakerScore:         c.BreakerScore,
			QuotaScore:           c.QuotaScore,
			RepairAffinityScore:  c.RepairAffinityScore,
			AssayQualityScore:    c.AssayQualityScore,
			Total:                c.Total,
			Excluded:             c.Excluded,
			ExclusionReason:      c.ExclusionReason,
			Selected:             c.Selected,
		})
	}
	return observability.RouteDecisionRecord{
		RunID:      runID,
		JobID:      d.JobID,
		JobType:    d.JobType,
		Objective:  d.Objective,
		PolicyHash: d.PolicyHash,
		Preview:    false,
		Created:    created,
		Rows:       rows,
	}
}
