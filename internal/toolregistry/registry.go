// Package toolregistry is Governator's trusted-tool registry (Sol redteam
// v4 S4, P0-5). Report finding: internal/contextgraph/graph.go ran a
// PATH-resolved codegraph helper directly on the host, before the backend
// and before baseline measurement -- bypassing every containment/policy
// mechanism the contract selected. The same concern applies to any
// controller-invoked external process (git, docker, bash, formatters,
// linters, validators): a bare PATH lookup trusts whatever ambient PATH
// currently resolves to, with no verification and no memory across calls.
//
// The registry inverts that default: an external tool must have an
// explicit trust declaration -- shipped (git) or operator-added
// (~/.governator/tools.yaml) -- before Governator will execute it at all.
// Absence from the registry is "outside the trust model," not "trust
// whatever PATH finds." A declared entry is then verified every time it
// resolves: canonical (symlink-evaluated) path, content hash, owner,
// mode, non-writable parent directories, and (when the entry pins one) an
// exact path or content-hash match -- reject on any mismatch.
package toolregistry

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"gopkg.in/yaml.v3"
)

// Kind classifies exactly what authority a trusted-tool entry may carry.
// Report S4: "classify every external process as exactly one of: trusted
// controller component / sandboxed untrusted helper / governed backend."
// This registry only governs the first class today (git, and any operator-
// registered controller helper such as a context-graph provider); a
// "governed backend" is the coding-agent CLI itself, resolved and verified
// separately by agents.BackendExecutionHandle (Session 3) since it carries
// model/provider identity this registry has no concept of.
type Kind string

const (
	KindTrustedController Kind = "trusted_controller"
	KindSandboxedHelper   Kind = "sandboxed_helper"
	KindGovernedBackend   Kind = "governed_backend"
)

// Entry is one operator- or Governator-declared trust registration.
// Path/SHA256 are optional stronger pins: when Path is set, Resolve never
// performs an ambient PATH lookup for this tool again -- every resolution
// verifies that exact file. When SHA256 is set, a content mismatch fails
// closed regardless of how the path was found.
type Entry struct {
	Name       string   `yaml:"name"`
	Kind       Kind     `yaml:"kind"`
	Path       string   `yaml:"path,omitempty"`
	SHA256     string   `yaml:"sha256,omitempty"`
	AllowedEnv []string `yaml:"allowed_env,omitempty"`
}

type fileFormat struct {
	Tools []Entry `yaml:"tools"`
}

// Identity is everything verified about a resolved, trusted external tool
// -- the shape callers bind into a run record so an audit can see exactly
// what ran, not just that "git" or "codegraph" was invoked.
type Identity struct {
	Name           string
	Kind           Kind
	CanonicalPath  string
	SHA256         string
	OwnerUID       uint32
	OwnerGID       uint32
	Mode           os.FileMode
	ParentWritable bool
	AllowedEnv     []string
}

// defaultEntries ships baseline trust for the one controller tool
// Governator cannot function without: git. Everything else -- including any
// configured context-graph provider -- has no shipped default and requires
// an explicit operator registration; an unregistered tool must never
// execute with controller authority (report attack 9).
var defaultEntries = []Entry{
	{Name: "git", Kind: KindTrustedController},
}

// Registry is an immutable, loaded view of tools.yaml merged over the
// shipped defaults. Load a fresh Registry per resolution rather than
// caching one process-wide: callers (tests, and any future `gov tools`
// mutation) must see the current file, not a stale snapshot from an
// earlier point in the process's life.
type Registry struct {
	entries map[string]Entry
	path    string
}

// FilePath returns the registry file this process will read/write:
// $GOV_TOOLREGISTRY_FILE if set (test/override hook, mirrors GOV_CONFIG),
// else ~/.governator/tools.yaml.
func FilePath() string {
	if v := strings.TrimSpace(os.Getenv("GOV_TOOLREGISTRY_FILE")); v != "" {
		return v
	}
	home := strings.TrimSpace(os.Getenv("HOME"))
	if home == "" {
		if h, err := os.UserHomeDir(); err == nil {
			home = h
		}
	}
	return filepath.Join(home, ".governator", "tools.yaml")
}

// Load reads the registry file (if present) merged over the shipped
// defaults. A missing file is not an error -- the defaults alone are a
// valid registry, exactly the state a fresh install starts from.
func Load() (*Registry, error) {
	path := FilePath()
	entries := make(map[string]Entry, len(defaultEntries))
	for _, e := range defaultEntries {
		entries[e.Name] = e
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Registry{entries: entries, path: path}, nil
		}
		return nil, fmt.Errorf("read tool registry %s: %w", path, err)
	}
	var parsed fileFormat
	if err := yaml.Unmarshal(data, &parsed); err != nil {
		return nil, fmt.Errorf("parse tool registry %s: %w", path, err)
	}
	for _, e := range parsed.Tools {
		if strings.TrimSpace(e.Name) == "" {
			return nil, fmt.Errorf("tool registry %s: entry with empty name", path)
		}
		if e.Kind == "" {
			e.Kind = KindTrustedController
		}
		entries[e.Name] = e
	}
	return &Registry{entries: entries, path: path}, nil
}

// Entry reports whether name has an explicit trust registration (shipped
// default or operator-declared).
func (r *Registry) Entry(name string) (Entry, bool) {
	e, ok := r.entries[name]
	return e, ok
}

// Resolve verifies that name is a registered trusted tool, resolves its
// executable (the entry's pinned Path, or requestedBin via ambient PATH
// lookup when Path is empty), and checks baseline hygiene: canonical
// (symlink-resolved) identity, content hash, owner, mode, and non-writable
// parent directories. Fails closed on any of: unregistered name, missing
// binary, untrusted owner, a group/world-writable file or parent
// directory, or (when the entry pins one) a content-hash mismatch.
//
// An entry with no Path set performs a fresh ambient lookup on every call
// -- by itself this does not defend against a PATH substitution present
// from the very first resolution (there is no prior trust to compare
// against). Pinning Path (see Pin) is what closes that gap: once pinned,
// Resolve never looks at PATH again for this tool.
func (r *Registry) Resolve(name, requestedBin string) (Identity, error) {
	entry, ok := r.Entry(name)
	if !ok {
		return Identity{}, fmt.Errorf("tool %q has no entry in the trusted-tool registry (%s); refusing to execute an unregistered external tool", name, r.path)
	}
	bin := entry.Path
	if bin == "" {
		bin = requestedBin
	}
	if strings.TrimSpace(bin) == "" {
		return Identity{}, fmt.Errorf("tool %q: no executable path configured", name)
	}
	resolved := bin
	if !filepath.IsAbs(resolved) {
		looked, err := exec.LookPath(resolved)
		if err != nil {
			return Identity{}, fmt.Errorf("resolve tool %q: %w", name, err)
		}
		resolved = looked
	}
	abs, err := filepath.Abs(resolved)
	if err != nil {
		return Identity{}, fmt.Errorf("resolve tool %q: %w", name, err)
	}
	canonical := abs
	if eval, everr := filepath.EvalSymlinks(abs); everr == nil {
		canonical = eval
	}
	f, err := os.Open(canonical)
	if err != nil {
		return Identity{}, fmt.Errorf("resolve tool %q: open %s: %w", name, canonical, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return Identity{}, fmt.Errorf("resolve tool %q: stat %s: %w", name, canonical, err)
	}
	var ownerUID, ownerGID uint32
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		ownerUID, ownerGID = st.Uid, st.Gid
	}
	euid := os.Geteuid()
	if int(ownerUID) != euid && ownerUID != 0 {
		return Identity{}, fmt.Errorf("resolve tool %q: %s is owned by uid %d, not this process (%d) or root", name, canonical, ownerUID, euid)
	}
	if info.Mode()&0o022 != 0 {
		return Identity{}, fmt.Errorf("resolve tool %q: %s is group- or world-writable", name, canonical)
	}
	if parentWritable(canonical) {
		return Identity{}, fmt.Errorf("resolve tool %q: %s has a group- or world-writable parent directory owned by an untrusted party", name, canonical)
	}
	sum := sha256.New()
	if _, err := io.Copy(sum, f); err != nil {
		return Identity{}, fmt.Errorf("resolve tool %q: hash %s: %w", name, canonical, err)
	}
	sha := hex.EncodeToString(sum.Sum(nil))
	if entry.SHA256 != "" && entry.SHA256 != sha {
		return Identity{}, fmt.Errorf("resolve tool %q: %s content hash %s does not match registry pin %s", name, canonical, sha, entry.SHA256)
	}
	return Identity{
		Name: name, Kind: entry.Kind, CanonicalPath: canonical, SHA256: sha,
		OwnerUID: ownerUID, OwnerGID: ownerGID, Mode: info.Mode(),
		ParentWritable: false, AllowedEnv: entry.AllowedEnv,
	}, nil
}

// Pin persists path as name's registered Path, creating a default
// trusted-controller entry if none exists yet and preserving every other
// entry already in the file. This is Governator's own trust-on-first-use
// step (report attack 10): `gov doctor` calls it right after successfully
// resolving git, so every later resolution -- in this process and any
// future one -- verifies that exact file instead of repeating an ambient
// PATH lookup a subsequently poisoned PATH could redirect.
func Pin(name, path string) error {
	target := FilePath()
	var parsed fileFormat
	if data, err := os.ReadFile(target); err == nil {
		if uerr := yaml.Unmarshal(data, &parsed); uerr != nil {
			return fmt.Errorf("parse tool registry %s: %w", target, uerr)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("read tool registry %s: %w", target, err)
	}
	found := false
	for i := range parsed.Tools {
		if parsed.Tools[i].Name == name {
			parsed.Tools[i].Path = path
			if parsed.Tools[i].Kind == "" {
				parsed.Tools[i].Kind = KindTrustedController
			}
			found = true
			break
		}
	}
	if !found {
		kind := KindTrustedController
		for _, d := range defaultEntries {
			if d.Name == name {
				kind = d.Kind
			}
		}
		parsed.Tools = append(parsed.Tools, Entry{Name: name, Kind: kind, Path: path})
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(target), err)
	}
	out, err := yaml.Marshal(parsed)
	if err != nil {
		return fmt.Errorf("marshal tool registry: %w", err)
	}
	if err := os.WriteFile(target, out, 0o600); err != nil {
		return fmt.Errorf("write tool registry %s: %w", target, err)
	}
	return nil
}

// parentWritable reports whether any directory in path's ancestry is
// writable by a party other than its owner -- group- or world-writable,
// where the owner is not this process's effective user and not root.
// Mirrors agents.parentTrustState's semantics (Session 3); duplicated
// rather than imported to keep this package decoupled from internal/agents.
func parentWritable(path string) bool {
	euid := os.Geteuid()
	dir := filepath.Dir(path)
	for {
		info, err := os.Lstat(dir)
		if err != nil {
			return true
		}
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			untrustedOwner := int(st.Uid) != euid && st.Uid != 0
			groupOrWorldWritable := info.Mode()&0o022 != 0
			if groupOrWorldWritable && untrustedOwner {
				return true
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return false
		}
		dir = parent
	}
}
