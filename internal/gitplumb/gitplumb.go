// Package gitplumb is Governator's low-level Git plumbing layer (Sol
// redteam v4 S1, P0-1/P0-2/P1-6/P1-9). It exists to answer one question
// safely: "commit exactly these approved paths, and nothing else" —
// without ever letting Git execute arbitrary code (hooks, filters, signing
// programs) with Governator's authority, and without letting a filename
// that looks like pathspec magic reach further than its own bytes.
//
// Every operation in this package:
//   - runs git as exec.Command argv (never a shell string) so a hostile
//     filename can't be reinterpreted by shell quoting;
//   - runs with a neutralized environment (no global/system config, an
//     empty hooks directory, filters/signing disabled) so ambient operator
//     state (a hostile global core.hooksPath, a configured clean filter)
//     can never influence what gets committed;
//   - builds the merge tree in an isolated temporary index outside any
//     worktree, never the real .git/index, so a concurrently running
//     backend can't observe or mutate it mid-build (P1-6);
//   - treats every machine-generated path as a literal path, never a
//     pathspec (P0-2), and parses `git status --porcelain=v2 -z`
//     byte-wise on NUL with no shell-style unquoting (P1-9).
package gitplumb

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/cousingary/governator/internal/controllerenv"
)

// Session is one isolated Git plumbing workspace: a temporary index file
// outside any worktree and an empty hooks directory, both scoped to a
// single merge/commit operation and torn down by Close.
type Session struct {
	// GitDir is the repository's common Git directory (resolved via
	// --git-common-dir, correct for both the main worktree and a linked
	// worktree), used as the object database every operation reads from
	// and writes to.
	GitDir string

	// WorkDir is the worktree (or main root) NewSession was given.
	// Index/tree-mutating commands (update-index, read-tree, write-tree)
	// are run with this as cmd.Dir: some of them refuse to run outside a
	// work tree even with GIT_INDEX_FILE pointed elsewhere, even though
	// they never touch WorkDir's actual working files.
	WorkDir string

	tmpDir        string
	indexFile     string
	emptyHooksDir string
}

// NewSession resolves dir's common Git directory and creates the isolated
// index file path and empty hooks directory this session's operations
// will use. Nothing on disk is shared with any worktree's real index.
func NewSession(ctx context.Context, dir string) (*Session, error) {
	out, err := runCapture(ctx, dir, nil, "rev-parse", "--git-common-dir")
	if err != nil {
		return nil, fmt.Errorf("gitplumb: resolve git-common-dir: %w", err)
	}
	gitDir := strings.TrimSpace(out)
	if !filepath.IsAbs(gitDir) {
		gitDir = filepath.Join(dir, gitDir)
	}
	tmpDir, err := os.MkdirTemp("", "gov-gitplumb-")
	if err != nil {
		return nil, fmt.Errorf("gitplumb: create session temp dir: %w", err)
	}
	emptyHooks := filepath.Join(tmpDir, "empty-hooks")
	if err := os.MkdirAll(emptyHooks, 0700); err != nil {
		_ = os.RemoveAll(tmpDir)
		return nil, fmt.Errorf("gitplumb: create empty hooks dir: %w", err)
	}
	return &Session{
		GitDir:        gitDir,
		WorkDir:       dir,
		tmpDir:        tmpDir,
		indexFile:     filepath.Join(tmpDir, "index"),
		emptyHooksDir: emptyHooks,
	}, nil
}

// Close removes every temporary file this session created. The isolated
// index and empty-hooks directory never held anything of value past the
// operation they backed.
func (s *Session) Close() error {
	if s == nil || s.tmpDir == "" {
		return nil
	}
	return os.RemoveAll(s.tmpDir)
}

// neutralEnv returns a copy of the current process environment with every
// setting that could let ambient operator state influence a plumbing
// command overridden: no global or system Git config, no inherited
// GIT_INDEX_FILE. extra is applied on top (e.g. this session's own
// GIT_INDEX_FILE for index-mutating commands).
func neutralEnv(extra map[string]string) []string {
	controlled := map[string]string{
		"GIT_CONFIG_GLOBAL":   "/dev/null",
		"GIT_CONFIG_SYSTEM":   "/dev/null",
		"GIT_CONFIG_NOSYSTEM": "1",
		"GIT_TERMINAL_PROMPT": "0",
	}
	for k, v := range extra {
		controlled[k] = v
	}
	return controllerenv.With(controlled)
}

// neutralArgs are the global options applied to every plumbing invocation:
// literal pathspecs everywhere, no repository/global hooks, no clean/
// smudge filters or EOL conversion, no signing, no side-effecting locks.
func neutralArgs(hooksDir string) []string {
	return []string{
		"--literal-pathspecs",
		"-c", "core.hooksPath=" + hooksDir,
		"-c", "commit.gpgsign=false",
		"-c", "core.autocrlf=false",
		"-c", "core.safecrlf=false",
		"--no-optional-locks",
	}
}

func runCmd(ctx context.Context, dir string, extraEnv map[string]string, hooksDir string, args ...string) (*exec.Cmd, *bytes.Buffer, *bytes.Buffer, error) {
	gitPath, err := TrustedGitPath()
	if err != nil {
		return nil, nil, nil, err
	}
	full := append(append([]string{}, neutralArgs(hooksDir)...), args...)
	cmd := exec.CommandContext(ctx, gitPath, full...)
	cmd.Dir = dir
	cmd.Env = neutralEnv(extraEnv)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	return cmd, &stdout, &stderr, nil
}

// runCapture runs a neutralized git command with no session-scoped hooks
// dir override (an ephemeral one is created and discarded — used for
// read-only bootstrap operations like resolving --git-common-dir, before a
// Session exists).
func runCapture(ctx context.Context, dir string, extraEnv map[string]string, args ...string) (string, error) {
	tmpHooks, err := os.MkdirTemp("", "gov-gitplumb-boot-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmpHooks)
	cmd, stdout, stderr, err := runCmd(ctx, dir, extraEnv, tmpHooks, args...)
	if err != nil {
		return "", err
	}
	if err := runAndWait(ctx, cmd); err != nil {
		return stdout.String(), fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

func runAndWait(ctx context.Context, cmd *exec.Cmd) error {
	if err := cmd.Start(); err != nil {
		return err
	}
	err := cmd.Wait()
	if ctx.Err() != nil && cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	return err
}

// run executes a neutralized git command in dir with this session's empty
// hooks dir, optionally with GIT_INDEX_FILE pointed at the session's
// isolated temporary index.
func (s *Session) run(ctx context.Context, dir string, useIndex bool, args ...string) (string, error) {
	var extraEnv map[string]string
	if useIndex {
		extraEnv = map[string]string{"GIT_INDEX_FILE": s.indexFile}
	}
	cmd, stdout, stderr, err := runCmd(ctx, dir, extraEnv, s.emptyHooksDir, args...)
	if err != nil {
		return "", err
	}
	if err := runAndWait(ctx, cmd); err != nil {
		return stdout.String(), fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

// HashObjectFile hashes and writes path's exact on-disk bytes as a blob —
// --no-filters --literally means no clean filter, no .gitattributes text
// conversion, and no interpretation of the path as anything but a literal
// file to read (P0-1's clean-filter mutation vector). Returns the blob's
// object ID.
func (s *Session) HashObjectFile(ctx context.Context, path string) (string, error) {
	out, err := s.run(ctx, s.WorkDir, false, "hash-object", "-w", "--no-filters", "--literally", "--", path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// ReadTreeIntoIndex populates this session's isolated temporary index from
// treeish, discarding whatever (if anything) was there before. Every
// subsequent UpdateIndex/WriteTree call in this session operates on this
// index, never the repository's real one.
func (s *Session) ReadTreeIntoIndex(ctx context.Context, treeish string) error {
	if err := os.RemoveAll(s.indexFile); err != nil {
		return err
	}
	_, err := s.run(ctx, s.WorkDir, true, "read-tree", "--", treeish)
	return err
}

// SyncRealIndex points dir's real (non-isolated) index at tree —
// index-only, no working-tree write of any kind, so this can never
// trigger a clean/smudge filter or line-ending conversion. Callers that
// need the working tree itself to reflect tree must materialize it
// themselves (a plain byte copy, not `git checkout`/`read-tree -u`) before
// calling this, so the real index and the real working tree agree once
// this returns.
func (s *Session) SyncRealIndex(ctx context.Context, dir, tree string) error {
	_, err := s.run(ctx, dir, false, "read-tree", "--", tree)
	return err
}

// modeFor returns the Git tree entry mode for a regular file on disk:
// 100755 if any execute bit is set, 100644 otherwise. Callers only ever
// pass paths that finalValidationMeasurement already proved are regular
// files (symlinks/special files are rejected earlier in the pipeline).
func modeFor(info os.FileInfo) string {
	if info.Mode()&0111 != 0 {
		return "100755"
	}
	return "100644"
}

// UpdateIndexAddFile hashes path's current on-disk content (no filters)
// and stages it into the isolated index at literalPath — a cacheinfo
// entry, which Git always treats as a literal path, never a pathspec,
// regardless of what characters literalPath contains (P0-2/P1-9).
func (s *Session) UpdateIndexAddFile(ctx context.Context, diskPath, literalPath string) error {
	info, err := os.Stat(diskPath)
	if err != nil {
		return err
	}
	hash, err := s.HashObjectFile(ctx, diskPath)
	if err != nil {
		return err
	}
	cacheinfo := modeFor(info) + "," + hash + "," + literalPath
	_, err = s.run(ctx, s.WorkDir, true, "update-index", "--add", "--cacheinfo", cacheinfo)
	return err
}

// UpdateIndexRemove removes literalPath from the isolated index. A no-op
// (not an error) if the path isn't present, matching --force-remove's
// semantics for a path git update-index has never seen.
func (s *Session) UpdateIndexRemove(ctx context.Context, literalPath string) error {
	_, err := s.run(ctx, s.WorkDir, true, "update-index", "--force-remove", "--", literalPath)
	return err
}

// WriteTree writes the isolated index's current contents as a tree object
// and returns its object ID.
func (s *Session) WriteTree(ctx context.Context) (string, error) {
	out, err := s.run(ctx, s.WorkDir, true, "write-tree")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// LsTreePaths lists every path in tree, recursively, exactly as Git
// stored it — NUL-delimited so a hostile filename (embedded newlines,
// leading pathspec-magic syntax) is never misparsed the way a
// human-readable, newline-split listing could be (P1-9).
func (s *Session) LsTreePaths(ctx context.Context, tree string) ([]string, error) {
	out, err := s.run(ctx, s.WorkDir, false, "ls-tree", "-r", "--name-only", "-z", tree)
	if err != nil {
		return nil, err
	}
	return splitNULNonEmpty(out), nil
}

// DiffTreePaths reports every path that differs between two trees —
// added, modified, or deleted — NUL-delimited (git diff --name-status -z),
// so the caller can assert the diff is exactly the approved change set and
// nothing else (the independent verification P0-1/P0-2 require: don't
// trust write-tree's output blindly, compare it against what was
// approved).
func (s *Session) DiffTreePaths(ctx context.Context, treeA, treeB string) ([]string, error) {
	out, err := s.run(ctx, s.WorkDir, false, "diff", "--no-renames", "--name-only", "-z", treeA, treeB)
	if err != nil {
		return nil, err
	}
	return splitNULNonEmpty(out), nil
}

// CommitTree creates a commit object for tree with the given parent (empty
// parent means a root commit) and message, using a neutralized environment
// (no gpgsign, no hooks — commit-tree never runs commit hooks in the first
// place, but the neutralized config still applies) and the message passed
// via stdin so an arbitrary message never has to survive argv quoting.
func (s *Session) CommitTree(ctx context.Context, tree, parent, message string) (string, error) {
	args := []string{"commit-tree", tree}
	if parent != "" {
		args = append(args, "-p", parent)
	}
	cmd, stdout, stderr, err := runCmd(ctx, s.GitDir, nil, s.emptyHooksDir, args...)
	if err != nil {
		return "", err
	}
	cmd.Stdin = strings.NewReader(message)
	if err := runAndWait(ctx, cmd); err != nil {
		return "", fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}

// UpdateRefCAS atomically advances ref from oldVal to newVal — a
// compare-and-swap that fails if anything else moved ref in between
// (P1-6: the final index/tree/commit is worthless as an authority if the
// branch pointer can be raced out from under it). ref is typically "HEAD",
// which Git's update-ref resolves through to whatever branch HEAD
// currently points at (attached or detached), so callers never need to
// resolve the symbolic ref themselves.
func (s *Session) UpdateRefCAS(ctx context.Context, dir, ref, newVal, oldVal string) error {
	_, err := s.run(ctx, dir, false, "update-ref", ref, newVal, oldVal)
	return err
}

// LooseObjectInGitDir reports whether oid exists as a loose object in this
// session's intended repository object database, without consulting any
// inherited GIT_OBJECT_DIRECTORY or alternates environment. This is the
// post-write check required by Sol v6 S5/P0-7: a successful git command is
// not enough if the object was redirected outside .git/objects.
func (s *Session) LooseObjectInGitDir(oid string) (bool, error) {
	oid = strings.TrimSpace(oid)
	if len(oid) < 4 || strings.ContainsAny(oid, "/\\") {
		return false, fmt.Errorf("gitplumb: invalid object id %q", oid)
	}
	path := filepath.Join(s.GitDir, "objects", oid[:2], oid[2:])
	info, err := os.Stat(path)
	if err == nil {
		return info.Mode().IsRegular(), nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

// RequireLooseObjectInGitDir fails closed unless oid is present in the
// repository's own object database. It intentionally does not use git
// cat-file, because cat-file can succeed via alternates; this check is about
// proving that newly approved/quarantined objects were not written elsewhere.
func (s *Session) RequireLooseObjectInGitDir(oid string) error {
	ok, err := s.LooseObjectInGitDir(oid)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("gitplumb: object %s missing from intended object database %s", oid, filepath.Join(s.GitDir, "objects"))
	}
	return nil
}

// RevParseTree resolves commit's tree object ID (commit^{tree}) — used to
// re-verify, after CommitTree and UpdateRefCAS, that the commit actually
// landed carries exactly the tree that was approved (P0-1's step 9: "verify
// the resulting commit tree exactly matches the approved tree").
func (s *Session) RevParseTree(ctx context.Context, commit string) (string, error) {
	out, err := s.run(ctx, s.WorkDir, false, "rev-parse", commit+"^{tree}")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

func splitNULNonEmpty(s string) []string {
	var out []string
	for _, p := range strings.Split(s, "\x00") {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
