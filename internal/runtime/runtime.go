package runtime

import (
	"bufio"
	"context"
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
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cousingary/governator/internal/agents"
	"github.com/cousingary/governator/internal/contracts"
	"github.com/cousingary/governator/internal/observability"
	"github.com/cousingary/governator/internal/policy"
	"github.com/cousingary/governator/internal/prompts"
	"github.com/cousingary/governator/internal/protectedpaths"
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
	CostUSD         float64                   `json:"cost_usd"`
	ValidOutput     bool                      `json:"valid_output"`
	FailureTaxonomy string                    `json:"failure_taxonomy,omitempty"`
	SelfReview      *contracts.ResultDocument `json:"self_review,omitempty"`
	PromptVersion   string                    `json:"prompt_version,omitempty"`
}

type Runner struct{ Home string }

func Home() string {
	if p := os.Getenv("GOV_HOME"); p != "" {
		return p
	}
	h, _ := os.UserHomeDir()
	return filepath.Join(h, ".governator")
}

func New() *Runner { return &Runner{Home: Home()} }

func dbOpen(home string) (*sql.DB, error) {
	return observability.Open(home)
}

func insertRun(db *sql.DB, r RunRecord, ch, head string) error {
	_, err := db.Exec(`INSERT INTO runs(id,job_id,job_type,agent,mode,status,root,worktree,branch,contract_hash,base_head,diff,transcript,message,created,prompt_version)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, r.ID, r.JobID, r.JobType, r.Agent, r.Mode, r.Status, r.Root, r.Worktree, r.Branch, ch, head, r.Diff, r.Transcript, r.Message, r.Created, r.PromptVersion)
	return err
}

func updateRun(db *sql.DB, r RunRecord, approved string) error {
	_, err := db.Exec(`UPDATE runs SET status=?,approved_head=?,diff=?,message=?,commit_hash=? WHERE id=?`,
		r.Status, approved, r.Diff, r.Message, r.Commit, r.ID)
	return err
}

func Last(id string) (RunRecord, error) {
	db, err := dbOpen(Home())
	if err != nil {
		return RunRecord{}, err
	}
	defer db.Close()
	q := `SELECT id,job_id,COALESCE(job_type,''),COALESCE(agent,''),COALESCE(mode,''),status,root,worktree,branch,diff,transcript,message,commit_hash,created,cost_usd,valid_output,failure_taxonomy,result_json,COALESCE(prompt_version,'') FROM runs`
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
	rows, err := db.Query(`SELECT id,job_id,COALESCE(job_type,''),COALESCE(agent,''),COALESCE(mode,''),status,root,worktree,branch,diff,transcript,message,commit_hash,created,cost_usd,valid_output,failure_taxonomy,result_json,COALESCE(prompt_version,'') FROM runs WHERE status='QUARANTINED' ORDER BY created DESC`)
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
	err := row.Scan(&r.ID, &r.JobID, &r.JobType, &r.Agent, &r.Mode, &r.Status, &r.Root, &r.Worktree, &r.Branch, &r.Diff, &r.Transcript, &r.Message, &r.Commit, &r.Created, &r.CostUSD, &r.ValidOutput, &r.FailureTaxonomy, &resultJSON, &r.PromptVersion)
	if err == nil && resultJSON != "" {
		var review contracts.ResultDocument
		if json.Unmarshal([]byte(resultJSON), &review) == nil {
			r.SelfReview = &review
		}
	}
	return r, err
}

func lock(root, home string) (func(), error) {
	sum := sha1.Sum([]byte(root))
	dir := filepath.Join(home, "locks")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	p := filepath.Join(dir, hex.EncodeToString(sum[:])+".lock")
	for tries := 0; tries < 2; tries++ {
		f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err == nil {
			fmt.Fprint(f, os.Getpid())
			f.Close()
			return func() { _ = os.Remove(p) }, nil
		}
		b, _ := os.ReadFile(p)
		pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
		if pid > 0 && syscall.Kill(pid, 0) == nil {
			return nil, fmt.Errorf("workspace locked by pid %d", pid)
		}
		_ = os.Remove(p)
	}
	return nil, errors.New("cannot acquire workspace lock")
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
		if rel == ".git" || strings.HasPrefix(rel, ".git/") {
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

func protectedFingerprint() (snapshot, error) {
	patterns, err := protectedpaths.Patterns()
	if err != nil {
		return nil, err
	}
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

func createWorkspace(root, home, id string, git bool) (string, string, error) {
	p := filepath.Join(home, "worktrees", id)
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		return "", "", err
	}
	branch := "gov/job/" + id
	if git {
		c, o, e := shell(context.Background(), root, fmt.Sprintf("git worktree add -b %s %s HEAD", shQuote(branch), shQuote(p)))
		if e != nil || c != 0 {
			return "", "", fmt.Errorf("git worktree: %s", o)
		}
		return p, branch, nil
	}
	if err := os.MkdirAll(p, 0700); err != nil {
		return "", "", err
	}
	c, o, e := shell(context.Background(), root, fmt.Sprintf("cp -a --reflink=auto ./. %s", shQuote(p)))
	if e != nil || c != 0 {
		return "", "", fmt.Errorf("copy workspace: %s", o)
	}
	return p, "", nil
}
func shQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }

func workspaceDiff(root, work string, git bool, changed, deleted []string) string {
	if git {
		_, o, _ := shell(context.Background(), work, "git diff --binary --no-ext-diff HEAD; git ls-files --others --exclude-standard | sed 's/^/UNTRACKED /'")
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
	Violations []string
	Commands   []string
	CostUSD    float64
}

func auditTranscript(path string, c contracts.Contract) transcriptAudit {
	data, err := os.ReadFile(path)
	if err != nil {
		return transcriptAudit{Violations: []string{"transcript audit: " + err.Error()}}
	}
	audit := transcriptAudit{}
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case []any:
			for _, item := range x {
				walk(item)
			}
		case map[string]any:
			if x["type"] == "tool_use" {
				name, _ := x["name"].(string)
				input, _ := x["input"].(map[string]any)
				command, _ := input["command"].(string)
				if name == "Bash" && command != "" {
					audit.Commands = append(audit.Commands, command)
				}
			}
			for _, key := range []string{"total_cost_usd", "cost_usd"} {
				if cost, ok := x[key].(float64); ok && cost > audit.CostUSD {
					audit.CostUSD = cost
				}
			}
			for _, item := range x {
				walk(item)
			}
		}
	}
	for _, line := range strings.Split(string(data), "\n") {
		var v any
		if json.Unmarshal([]byte(line), &v) == nil {
			walk(v)
		}
	}
	if len(audit.Commands) > c.Budget.MaxCommands {
		audit.Violations = append(audit.Violations, "max_commands exceeded")
	}
	for _, command := range audit.Commands {
		if class := policy.ClassifyShellCommand(command, false); class != nil {
			audit.Violations = append(audit.Violations, fmt.Sprintf("destructive command classified as %s %s: %s", class.Verb, class.Resource, command))
		}
		allowed := false
		for _, pattern := range c.Allowed.Execute {
			if commandMatches(pattern, command) {
				allowed = true
				break
			}
		}
		if !allowed {
			audit.Violations = append(audit.Violations, "command outside allowlist: "+command)
		}
		for _, forbidden := range c.Forbidden.Commands {
			if strings.Contains(command, forbidden) {
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
	return audit
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
	root, err := filepath.Abs(c.Workspace.Root)
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
	var prior string
	if db.QueryRow(`SELECT id FROM runs WHERE contract_hash=? AND approved_head=? AND status='APPROVED' ORDER BY created DESC LIMIT 1`, hash, head).Scan(&prior) == nil {
		replayed, replayErr := Last(prior)
		replayed.Replayed = true
		return replayed, replayErr
	}
	id := fmt.Sprintf("%s-%d", c.JobID, time.Now().UTC().UnixNano())
	work, branch, err := createWorkspace(root, r.Home, id, git)
	if err != nil {
		return RunRecord{}, err
	}
	canaryName := ".governator-canary"
	canaryPath := filepath.Join(work, canaryName)
	if _, statErr := os.Lstat(canaryPath); !os.IsNotExist(statErr) {
		return RunRecord{}, fmt.Errorf("reserved canary path already exists: %s", canaryName)
	}
	if err := os.WriteFile(canaryPath, []byte(id+"\n"), 0400); err != nil {
		return RunRecord{}, fmt.Errorf("create canary: %w", err)
	}
	transcript := filepath.Join(r.Home, "transcripts", id+".jsonl")
	promptRoot := os.Getenv("GOV_PROMPTS")
	if promptRoot == "" {
		promptRoot = "prompts"
	}
	promptVersion, err := prompts.Resolve(promptRoot, c.Agent, string(c.Mode))
	if err != nil {
		return RunRecord{}, err
	}
	rec := RunRecord{ID: id, JobID: c.JobID, JobType: c.JobType, Agent: c.Agent, Mode: string(c.Mode), Status: "RUNNING", Root: root, Worktree: work, Branch: branch, Transcript: transcript, Created: time.Now().UTC().Format(time.RFC3339Nano), PromptVersion: promptVersion.ID}
	if err = insertRun(db, rec, hash, head); err != nil {
		return rec, err
	}
	if err = observability.RecordIdentity(db, c.JobID, c.JobType, c.Agent, rec.Created); err != nil {
		return rec, err
	}
	liveBefore, err := fingerprint(root)
	if err != nil {
		return rec, err
	}
	protectedBefore, err := protectedFingerprint()
	if err != nil {
		return rec, err
	}
	workBefore, err := fingerprint(work)
	if err != nil {
		return rec, err
	}
	prompt, err := contracts.CompilePrompt(c, work)
	if err != nil {
		return rec, err
	}
	prompt += "\nController canary: " + canaryName + " must remain byte-for-byte unchanged. Touching it quarantines the run.\n"
	prompt += prompts.Annotation(promptVersion)
	agent, err := agents.New(c.Agent)
	if err != nil {
		return rec, err
	}
	ar, aerr := agent.Run(ctx, agents.Request{
		Prompt: prompt, Workdir: work, Transcript: transcript,
		Timeout: time.Duration(c.Budget.MaxMinutes) * time.Minute,
		Spec:    agents.SpecFromContract(c, work),
	})
	_ = redact(transcript)
	audit := auditTranscript(transcript, c)
	rec.CostUSD = audit.CostUSD
	workAfter, werr := fingerprint(work)
	liveAfter, lerr := fingerprint(root)
	protectedAfter, perr := protectedFingerprint()
	violations := append([]string{}, audit.Violations...)
	var selfReviewJSON string
	rec.SelfReview, selfReviewJSON = readSelfReview(work)
	if before, ok := workBefore[canaryName]; !ok || workAfter[canaryName] != before {
		violations = append(violations, "canary mutation: "+canaryName)
	}
	_ = os.Chmod(canaryPath, 0600)
	_ = os.Remove(canaryPath)
	delete(workBefore, canaryName)
	delete(workAfter, canaryName)
	if aerr != nil {
		violations = append(violations, "agent: "+aerr.Error())
	}
	if ar.ExitCode != 0 {
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
	protectedChanged, protectedDeleted := changes(protectedBefore, protectedAfter)
	if len(protectedChanged)+len(protectedDeleted) > 0 {
		violations = append(violations, "protected path mutation: "+strings.Join(append(protectedChanged, protectedDeleted...), ","))
	}
	changed, deleted := changes(workBefore, workAfter)
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
	for _, v := range c.Success.Validators {
		vctx, cancel := context.WithTimeout(ctx, time.Duration(c.Budget.MaxMinutes)*time.Minute)
		code, out, e := shell(vctx, work, v)
		cancel()
		if e != nil {
			out += "\n" + e.Error()
		}
		_, _ = db.Exec(`INSERT INTO validators(run_id,command,exit_code,output) VALUES(?,?,?,?)`, id, v, code, out)
		if code != 0 || e != nil {
			violations = append(violations, fmt.Sprintf("validator failed (%d): %s", code, v))
		}
	}
	rec.Diff = workspaceDiff(root, work, git, changed, deleted)
	if len(violations) == 0 {
		if git {
			_, _, _ = shell(ctx, work, "git add -A")
			cm := fmt.Sprintf("Governator job %s\n\nGov-Run: %s", c.JobID, id)
			code, out, e := shell(ctx, work, "git commit --allow-empty -m "+shQuote(cm))
			if e != nil || code != 0 {
				violations = append(violations, "branch commit: "+out)
			}
			if len(violations) == 0 {
				code, out, e = shell(ctx, root, "git merge --squash "+shQuote(branch))
				if e != nil || code != 0 {
					violations = append(violations, "squash merge: "+out)
				}
			}
			if len(violations) == 0 {
				code, out, e = shell(ctx, root, "git commit --allow-empty -m "+shQuote(cm))
				if e != nil || code != 0 {
					violations = append(violations, "merge commit: "+out)
				}
			}
			if len(violations) == 0 {
				rec.Commit, _ = gitHead(root)
			}
		} else {
			if err := captureRecall(r.Home, id, root, append(append([]string{}, changed...), deleted...)); err != nil {
				violations = append(violations, "recall snapshot: "+err.Error())
			}
			for _, p := range changed {
				src := filepath.Join(work, filepath.FromSlash(p))
				dst := filepath.Join(root, filepath.FromSlash(p))
				if err := os.MkdirAll(filepath.Dir(dst), 0755); err == nil {
					err = copyFile(src, dst)
				}
				if err != nil {
					violations = append(violations, "merge copy: "+err.Error())
				}
			}
			for _, p := range deleted {
				if err := os.Remove(filepath.Join(root, filepath.FromSlash(p))); err != nil && !os.IsNotExist(err) {
					violations = append(violations, "merge delete: "+err.Error())
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
	if len(violations) == 0 {
		rec.Status = "APPROVED"
		rec.Message = "merge gate passed"
		rec.ValidOutput = true
	} else {
		rec.Status = "QUARANTINED"
		rec.Message = strings.Join(violations, "; ")
		rec.FailureTaxonomy = observability.ClassifyFailure(violations)
		if git {
			_, _, _ = shell(ctx, work, "git add -A")
			_, _, _ = shell(ctx, work, "git commit --allow-empty -m "+shQuote("Quarantined Governator run "+id))
		}
	}
	approved := head
	if rec.Status == "APPROVED" && git {
		approved, _ = gitHead(root)
	}
	if err := updateRun(db, rec, approved); err != nil {
		return rec, err
	}
	if err := observability.RecordCompletion(db, observability.Completion{
		RunID:           rec.ID,
		Agent:           rec.Agent,
		JobType:         rec.JobType,
		Status:          rec.Status,
		CostUSD:         rec.CostUSD,
		ValidOutput:     rec.ValidOutput,
		FailureTaxonomy: rec.FailureTaxonomy,
		SelfReviewJSON:  selfReviewJSON,
		Files:           files,
		Commands:        commands,
		Violations:      violations,
	}); err != nil {
		return rec, err
	}
	if git {
		_, _, _ = shell(context.Background(), root, "git worktree remove --force "+shQuote(work))
		if rec.Status == "APPROVED" {
			_, _, _ = shell(context.Background(), root, "git branch -D "+shQuote(branch))
		}
	} else {
		_ = os.RemoveAll(work)
	}
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
	r.Status = "ROLLED_BACK"
	r.Message = "reverted " + r.Commit
	return r, e
}

func MarshalRecord(r RunRecord) string { b, _ := json.MarshalIndent(r, "", "  "); return string(b) }
