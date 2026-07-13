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
	"github.com/cousingary/governator/internal/minimalism"
	"github.com/cousingary/governator/internal/observability"
	"github.com/cousingary/governator/internal/policy"
	"github.com/cousingary/governator/internal/prompts"
	"github.com/cousingary/governator/internal/protectedpaths"
	"github.com/cousingary/governator/internal/quota"
	"github.com/cousingary/governator/internal/router"
	"github.com/cousingary/governator/internal/runner"
	"github.com/cousingary/governator/internal/spend"
	"github.com/cousingary/governator/internal/tokenoptimizer"
)

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
	cmd := exec.CommandContext(ctx, "bash", "-lc", command)
	cmd.Dir = dir
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	out, err := cmd.CombinedOutput()
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

func gitHead(root string) (string, error) {
	c, o, e := shell(context.Background(), root, "git rev-parse HEAD")
	if e != nil || c != 0 {
		return "", fmt.Errorf("git rev-parse: %s", strings.TrimSpace(o))
	}
	return strings.TrimSpace(o), nil
}
func isGit(root string) bool {
	c, _, _ := shell(context.Background(), root, "git rev-parse --is-inside-work-tree")
	return c == 0
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
		return nil
	})
}

// enforceContainment applies the Session 3 (Phase 2) risk-class containment
// policy. It resolves the backend's native-sandbox capability (a verified
// agent-layer fact, not a contract claim) and the operator override key from
// config, then delegates to containment.Enforce. Non-high-risk contracts are
// a no-op. The check runs before quota/workspace acquisition so a denied
// high-risk run leaves no side effects.
//
// agent is the single Agent instance the caller already built for this run
// (via agents.New) — enforceContainment builds no Agent of its own. It DOES
// resolve the backend binary itself (Sol Finding 5 / Session 2's
// agents.ResolvePath), but only inside the native-sandbox branch below: most
// contracts (non-high-risk, non-native-sandbox, Docker-runner, or signed
// override) never need the executable's identity to reach a containment
// verdict, and resolving unconditionally here would force every high-risk
// contract — including ones correctly rejected on containment grounds alone —
// to have its backend CLI actually installed just to fail closed for an
// unrelated reason.
func enforceContainment(db *sql.DB, c contracts.Contract, agent agents.Agent, cfg config.Config) (string, error) {
	if strings.TrimSpace(c.RiskClass) != "high" {
		return "", nil
	}
	nativeSandbox := agent.Capabilities().NativeSandbox
	var attestationID string
	// Sol Critical 4 / Phase E: a backend name is never sufficient evidence of
	// native host containment. High-risk local jobs may count a native sandbox
	// only when the current executable hash/config/model has a fresh ledgered
	// capability attestation whose probes passed. Docker and signed overrides
	// keep their existing paths inside containment.Enforce.
	if c.EffectiveRunner() == "local" && nativeSandbox && !containment.VerifyOverride(c, cfg.Containment.OverridePublicKey) {
		resolution, err := agents.ResolvePath(agent)
		if err != nil {
			return "", err
		}
		id, err := attest.VerifyHighRiskNative(db, cfg, agent, resolution)
		if err != nil {
			return "", err
		}
		attestationID = id
	}
	return attestationID, containment.Enforce(c, nativeSandbox, cfg.Containment.OverridePublicKey)
}

// requiresCompleteTranscript reports whether c may never be approved on an
// incomplete (capped or unverifiable) transcript: either the operator opted
// in explicitly (docker.require_complete_transcript, or local's equivalent
// require_complete_transcript for runner: local — Sol High 11) or the run is
// evidence-bearing by construction — a blocking assay's verdict gates the
// merge, so the audit trail behind that verdict must be whole.
func requiresCompleteTranscript(c contracts.Contract) bool {
	if c.Docker != nil && c.Docker.RequireCompleteTranscript {
		return true
	}
	if c.Local != nil && c.Local.RequireCompleteTranscript {
		return true
	}
	return c.Assay != nil && c.Assay.Enforcement == assay.EnforcementBlocking
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

func gitStatusPorcelain(ctx context.Context, root string) (string, error) {
	code, out, err := shell(ctx, root, "git status --porcelain")
	if err != nil || code != 0 {
		return out, fmt.Errorf("git status --porcelain: %s", strings.TrimSpace(out))
	}
	return strings.TrimSpace(out), nil
}

func requireCleanLiveRoot(ctx context.Context, root string) error {
	status, err := gitStatusPorcelain(ctx, root)
	if err != nil {
		return err
	}
	if status != "" {
		return fmt.Errorf("live root dirty before merge: %s", status)
	}
	return nil
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
	status, err := gitStatusPorcelain(ctx, root)
	if err != nil {
		return err
	}
	if status != "" {
		return fmt.Errorf("rollback left live root dirty: %s", status)
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
	b.WriteString("^")
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

func auditTranscript(path, format, work string, c contracts.Contract, protectedPatterns []string, unenforceableRuleAction string) transcriptAudit {
	data, err := os.ReadFile(path)
	if err != nil {
		return transcriptAudit{Violations: []string{"transcript audit: " + err.Error()}, CostUnavailable: true}
	}
	audit := transcriptAudit{TranscriptBytes: int64(len(data))}
	usage := newUsageAccumulator()
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

type diffMetrics struct {
	Lines    int
	NewFiles int
}

func countLines(path string) int {
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
		decision, _, gerr := evaluatePolicyGate(db, cfg, c, root, rec.ID, facts)
		if gerr != nil {
			return false, "", gerr
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
		runCtx, cancel := context.WithTimeout(ctx, time.Duration(c.Budget.MaxMinutes)*time.Minute)
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
	// Runner resolution (Phase 5) happens before any lock/workspace/quota side
	// effect: a docker request Governator can't satisfy must fail closed with
	// a clear error here, never silently fall back to LocalWorktreeRunner and
	// never leave a partially-acquired lock or reservation behind.
	rn, err := runner.New(c.EffectiveRunner(), c.Docker, c.Local, env.CredentialRoots)
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
	if err := observability.RecordStage(db, id, "PARSED", "", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return RunRecord{}, err
	}
	if err := observability.RecordStage(db, id, "PREFLIGHTED", "", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
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
		if err := observability.RecordStage(db, id, "QUARANTINED", "", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
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
	if err := observability.RecordStage(db, id, "ROUTED", resolved.Agent, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
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
	// touching the executable's identity.
	capabilityAttestID, err := enforceContainment(db, c, agent, cfg)
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
	policyFacts := policy.MergeFacts(policy.BuildContractFacts(c, resolved.Agent), map[string]any{
		policy.FactEstimatedCostUSD: spend.EstimateCostUSD(resolved.Agent, c.Budget.MaxTokens, nil),
		policy.FactDailyCapUSD:      cfg.Spend.DailyCapUSD,
	})
	gateDecision, pendingAsks, gerr := evaluatePolicyGate(db, cfg, c, root, id, policyFacts)
	if gerr != nil {
		return RunRecord{}, gerr
	}
	if gateDecision.Blocks() {
		refused, err := r.quarantineForPolicy(db, c, resolved.Agent, root, id, hash, head, gateDecision, pendingAsks)
		return refused, err
	}
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
			if err := observability.RecordStage(db, id, "QUARANTINED", "", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
				return refused, err
			}
			return refused, nil
		}
		return RunRecord{}, qerr
	}
	if err := observability.RecordStage(db, id, "QUOTA_RESERVED", "", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
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
	// Sol Finding 5 / Session 2: resolve the configured backend binary exactly
	// once here — through PATH, symlink-canonicalized, content-hashed — and
	// reuse this single record for execution identity, replay, and the actual
	// launch below. A bare name (backends.pi.bin: pi) resolved independently
	// at identity time versus launch time let a swapped-then-restored binary
	// pass a stale replay check that never re-verified the file it hashed.
	resolution, err := agents.ResolvePath(agent)
	if err != nil {
		return RunRecord{}, err
	}
	identity := computeExecutionIdentity(cfg, c, agent, resolution, root, head, hash, promptVersion, capabilityAttestID)
	if priorID, perr := replayMatch(db, identity.Hash()); perr != nil {
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
	if err := observability.RecordStage(db, id, "WORKSPACE_READY", "", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return rec, err
	}
	graphSnapshot, err := contextgraph.Prepare(ctx, work)
	if err != nil {
		return rec, err
	}
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
	stagedArtifacts, err := stageConsumedArtifacts(db, work, c)
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
	protectedBefore, err := protectedFingerprint(env.ProtectedPatterns)
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
	prompt, err := contracts.CompilePrompt(c, work)
	if err != nil {
		return rec, err
	}
	prompt += "\nController canary: " + canaryName + " must remain byte-for-byte unchanged. Touching it quarantines the run.\n"
	prompt += artifactPromptAnnotation(stagedArtifacts, c.Produces)
	prompt += prompts.Annotation(promptVersion)
	prompt += rtkAnnotation
	prompt += contextgraph.PromptAnnotation(graphSnapshot)
	prompt += minimalismAnnotation
	// The AGENT_RUNNING checkpoint carries a digest of workBefore (the
	// worktree's pre-launch fingerprint) as its detail so a recovery pass
	// (gov run resume/recover --stale) run against a later crashed process can
	// tell "the agent never touched the worktree" (digest still matches) from
	// "the agent was mid-edit when it died" (digest no longer matches) without
	// needing that in-memory snapshot to have survived the crash.
	agentRunningDetail, _ := json.Marshal(map[string]string{"worktree_digest": snapshotDigest(workBefore)})
	if err := observability.RecordStage(db, id, "AGENT_RUNNING", string(agentRunningDetail), time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return rec, err
	}
	agentTimeout := remainingRunBudget(ctx)
	var ar agents.Result
	var aerr error
	if agentTimeout <= 0 {
		aerr = context.DeadlineExceeded
		ar.TimedOut = true
	} else {
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
			ResolvedBin: resolution.CanonicalPath,
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
			if err := observability.RecordStage(db, id, "OUTPUT_TRUNCATED", truncDetail, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
				payload, _ := json.Marshal(stageEventPayload{RunID: id, Stage: "OUTPUT_TRUNCATED", Detail: truncDetail})
				noteOperationalFailure(db, id, opStageEvent, err, string(payload))
			}
			rec.Notes = appendNote(rec.Notes, fmt.Sprintf("output_truncated: %d bytes discarded of %d total", obs.BytesDiscarded, obs.BytesAccepted+obs.BytesDiscarded))
		}
	}
	redactErr := redact(transcript)
	audit := auditTranscript(transcript, agent.Capabilities().TranscriptFormat, work, c, env.ProtectedPatterns, env.Config.Doctrine.UnenforceableRuleAction)
	if err := observability.RecordStage(db, id, "AUDITED", "", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
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
	protectedAfter, perr := protectedFingerprint(env.ProtectedPatterns)
	gitControlAfter, gcerr := gitControlFingerprint(work)
	violations := append([]string{}, audit.Violations...)
	violations = append(violations, telemetryViolations(c, audit)...)
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
	artifactRecords, artifactViolations := collectProducedArtifacts(r.Home, work, id, c.Produces)
	violations = append(violations, artifactViolations...)
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
	if err := observability.RecordStage(db, id, "VALIDATING", "", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return rec, err
	}
	for _, v := range c.Success.Validators {
		vctx, cancel, deadlineErr := stageTimeout(ctx, "success validator")
		if deadlineErr != nil {
			violations = append(violations, deadlineErr.Error())
			break
		}
		code, out, e := shell(vctx, work, v)
		cancel()
		if e != nil {
			out += "\n" + e.Error()
		}
		recordValidatorEvidence(db, id, v, code, out, "success")
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
		for _, v := range c.Cleanup.Validators {
			vctx, cancel, deadlineErr := stageTimeout(ctx, "cleanup validator")
			if deadlineErr != nil {
				if c.Cleanup.Required {
					violations = append(violations, deadlineErr.Error())
				}
				break
			}
			code, out, e := shell(vctx, work, v)
			cancel()
			if e != nil {
				out += "\n" + e.Error()
			}
			recordValidatorEvidence(db, id, v, code, out, "cleanup")
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
	if c.Assay != nil {
		if err := observability.RecordStage(db, id, "ASSAYING", "", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			return rec, err
		}
		runAssayStep(ctx, db, cfg, c, id, hash, rec.Agent, artifactRecords, &violations)
	}
	rec.Diff = workspaceDiff(root, work, git, changed, deleted)
	rootCommitted := false
	if len(violations) == 0 {
		if git {
			mergePaths := append(append([]string{}, changed...), deleted...)
			if err := requireCleanLiveRoot(ctx, root); err != nil {
				violations = append(violations, err.Error())
			}
			if len(violations) == 0 {
				detail, _ := json.Marshal(map[string]any{"previous_head": head, "paths": mergePaths})
				if err := observability.RecordStage(db, id, "MERGE_INTENT", string(detail), time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
					violations = append(violations, "merge intent ledger: "+err.Error())
				}
			}
			_, _, _ = shell(ctx, work, "git add -A -- . ':(exclude).codegraph' ':(exclude).governator'")
			cm := fmt.Sprintf("Governator job %s\n\nGov-Run: %s", c.JobID, id)
			if len(violations) == 0 {
				code, out, e := shell(ctx, work, "git commit --allow-empty -m "+shQuote(cm))
				if e != nil || code != 0 {
					violations = append(violations, "branch commit: "+out)
				}
			}
			if len(violations) == 0 {
				code, out, e := shell(ctx, root, "git merge --squash "+shQuote(branch))
				if e != nil || code != 0 {
					violations = append(violations, "squash merge: "+out)
				}
			}
			if len(violations) == 0 {
				if err := observability.RecordStage(db, id, "MERGE_APPLIED", "", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
					violations = append(violations, "merge applied ledger: "+err.Error())
				}
			}
			if len(violations) == 0 {
				code, out, e := shell(ctx, root, "git commit --allow-empty -m "+shQuote(cm))
				if e != nil || code != 0 {
					violations = append(violations, "merge commit: "+out)
				}
			}
			if len(violations) > 0 {
				if err := rollbackLiveRoot(ctx, root, head, liveBefore, mergePaths); err != nil {
					violations = append(violations, "merge rollback: "+err.Error())
				}
			}
			if len(violations) == 0 {
				rootCommitted = true
				rec.Commit, _ = gitHead(root)
				if err := observability.RecordStage(db, id, "ROOT_COMMITTED", rec.Commit, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
					payload, _ := json.Marshal(stageEventPayload{RunID: id, Stage: "ROOT_COMMITTED", Detail: rec.Commit})
					noteOperationalFailure(db, id, opStageEvent, err, string(payload))
				}
			}
		} else {
			if err := captureRecall(r.Home, id, root, append(append([]string{}, changed...), deleted...)); err != nil {
				violations = append(violations, "recall snapshot: "+err.Error())
			}
			violations = append(violations, mergeCopyChanged(work, root, changed)...)
			for _, p := range deleted {
				if err := os.Remove(filepath.Join(root, filepath.FromSlash(p))); err != nil && !os.IsNotExist(err) {
					violations = append(violations, "merge delete: "+err.Error())
				}
			}
		}
		if len(violations) == 0 {
			if err := observability.RecordStage(db, id, "MERGED", "", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
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
			_, _, _ = shell(ctx, work, "git add -A -- . ':(exclude).codegraph' ':(exclude).governator'")
			_, _, _ = shell(ctx, work, "git commit --allow-empty -m "+shQuote("Quarantined Governator run "+id))
		}
	}
	ledgerPending := func(opKind string, opErr error, payload string) (RunRecord, error) {
		noteOperationalFailure(db, id, opKind, opErr, payload)
		rec.Status = "MERGED_LEDGER_PENDING"
		rec.Message = "root committed; ledger finalization pending: " + opErr.Error()
		_, _ = db.Exec(`UPDATE runs SET status=?,message=?,commit_hash=?,identity_hash=? WHERE id=?`, rec.Status, rec.Message, rec.Commit, rec.IdentityHash, rec.ID)
		_ = observability.RecordStage(db, id, "MERGED_LEDGER_PENDING", opKind+": "+opErr.Error(), time.Now().UTC().Format(time.RFC3339Nano))
		return rec, nil
	}
	if rootCommitted {
		if err := observability.RecordStage(db, id, "LEDGER_FINALIZING", "", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			payload, _ := json.Marshal(stageEventPayload{RunID: id, Stage: "LEDGER_FINALIZING", Detail: ""})
			return ledgerPending(opStageEvent, err, string(payload))
		}
	}
	if err := observability.RecordStage(db, id, rec.Status, "", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
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
		if err := observability.RecordStage(db, id, "COMPLETE", "", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
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
			openErr = observability.RecordStage(db, r.ID, "ROLLED_BACK", "", time.Now().UTC().Format(time.RFC3339Nano))
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
		e = observability.RecordStage(db, r.ID, "ROLLED_BACK", "", time.Now().UTC().Format(time.RFC3339Nano))
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
