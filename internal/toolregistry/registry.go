// Package toolregistry is Governator's trusted-tool registry (Sol redteam
// v4 S4, extended by Sol redteam v6 S2). Controller tools are not trusted
// by name, PATH position, or first use. They must be administratively
// enrolled with a complete file identity before any ordinary governed
// execution may invoke them.
package toolregistry

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"gopkg.in/yaml.v3"
)

type Kind string

const (
	KindTrustedController Kind = "trusted_controller"
	KindSandboxedHelper   Kind = "sandboxed_helper"
	KindGovernedBackend   Kind = "governed_backend"
)

type Entry struct {
	Name       string   `yaml:"name"`
	Kind       Kind     `yaml:"kind"`
	Path       string   `yaml:"path,omitempty"`
	SHA256     string   `yaml:"sha256,omitempty"`
	OwnerUID   uint32   `yaml:"owner_uid,omitempty"`
	OwnerGID   uint32   `yaml:"owner_gid,omitempty"`
	Mode       string   `yaml:"mode,omitempty"`
	Device     uint64   `yaml:"device,omitempty"`
	Inode      uint64   `yaml:"inode,omitempty"`
	AllowedEnv []string `yaml:"allowed_env,omitempty"`
}

type fileFormat struct {
	Generation int     `yaml:"generation,omitempty"`
	Tools      []Entry `yaml:"tools"`
}

type Identity struct {
	Name           string
	Kind           Kind
	CanonicalPath  string
	SHA256         string
	OwnerUID       uint32
	OwnerGID       uint32
	Mode           os.FileMode
	Device         uint64
	Inode          uint64
	ParentWritable bool
	AllowedEnv     []string
}

var defaultEntries = []Entry{
	{Name: "git", Kind: KindTrustedController},
	{Name: "unshare", Kind: KindTrustedController},
	{Name: "systemd-run", Kind: KindTrustedController},
	{Name: "bash", Kind: KindTrustedController},
	{Name: "docker", Kind: KindTrustedController},
	{Name: "python3", Kind: KindTrustedController},
}

type Registry struct {
	entries    map[string]Entry
	path       string
	generation int
}

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

func Load() (*Registry, error) {
	path := FilePath()
	entries := make(map[string]Entry, len(defaultEntries))
	for _, e := range defaultEntries {
		entries[e.Name] = e
	}
	parsed, exists, err := readRegistryFile(path)
	if err != nil {
		return nil, err
	}
	if !exists {
		return &Registry{entries: entries, path: path}, nil
	}
	seen := map[string]bool{}
	for _, e := range parsed.Tools {
		if err := validateEntry(path, e); err != nil {
			return nil, err
		}
		if seen[e.Name] {
			return nil, fmt.Errorf("tool registry %s: duplicate tool name %q", path, e.Name)
		}
		seen[e.Name] = true
		entries[e.Name] = e
	}
	return &Registry{entries: entries, path: path, generation: parsed.Generation}, nil
}

func (r *Registry) Entry(name string) (Entry, bool) {
	e, ok := r.entries[name]
	return e, ok
}

func (r *Registry) Generation() int { return r.generation }

func (r *Registry) Entries() []Entry {
	out := make([]Entry, 0, len(r.entries))
	for _, e := range r.entries {
		out = append(out, e)
	}
	return out
}

func (r *Registry) Resolve(name, requestedBin string) (Identity, error) {
	entry, ok := r.Entry(name)
	if !ok {
		return Identity{}, fmt.Errorf("tool %q has no entry in the trusted-tool registry (%s); refusing to execute an unregistered external tool", name, r.path)
	}
	_ = requestedBin
	if strings.TrimSpace(entry.Path) == "" {
		return Identity{}, fmt.Errorf("tool %q has no enrolled path in %s; run `gov tools enroll %s <absolute-path>` before execution", name, r.path, name)
	}
	if strings.TrimSpace(entry.SHA256) == "" {
		return Identity{}, fmt.Errorf("tool %q has no enrolled sha256 in %s", name, r.path)
	}
	if !filepath.IsAbs(entry.Path) {
		return Identity{}, fmt.Errorf("tool %q: enrolled path %q is not absolute", name, entry.Path)
	}
	identity, err := inspectPath(name, entry.Path)
	if err != nil {
		return Identity{}, err
	}
	if identity.SHA256 != strings.ToLower(entry.SHA256) {
		return Identity{}, fmt.Errorf("resolve tool %q: %s content hash %s does not match registry pin %s", name, identity.CanonicalPath, identity.SHA256, entry.SHA256)
	}
	if entry.OwnerUID != 0 && identity.OwnerUID != entry.OwnerUID {
		return Identity{}, fmt.Errorf("resolve tool %q: owner uid changed from %d to %d", name, entry.OwnerUID, identity.OwnerUID)
	}
	if entry.OwnerGID != 0 && identity.OwnerGID != entry.OwnerGID {
		return Identity{}, fmt.Errorf("resolve tool %q: owner gid changed from %d to %d", name, entry.OwnerGID, identity.OwnerGID)
	}
	if entry.Mode != "" {
		wantMode, err := strconv.ParseUint(strings.TrimPrefix(entry.Mode, "0"), 8, 32)
		if err != nil {
			return Identity{}, fmt.Errorf("tool %q: invalid enrolled mode %q", name, entry.Mode)
		}
		if identity.Mode.Perm() != os.FileMode(wantMode) {
			return Identity{}, fmt.Errorf("resolve tool %q: mode changed from %s to %04o", name, entry.Mode, identity.Mode.Perm())
		}
	}
	if entry.Device != 0 && identity.Device != entry.Device {
		return Identity{}, fmt.Errorf("resolve tool %q: device changed from %d to %d", name, entry.Device, identity.Device)
	}
	if entry.Inode != 0 && identity.Inode != entry.Inode {
		return Identity{}, fmt.Errorf("resolve tool %q: inode changed from %d to %d", name, entry.Inode, identity.Inode)
	}
	identity.AllowedEnv = entry.AllowedEnv
	return identity, nil
}

func ResolveTrusted(name, requestedBin string) (Identity, error) {
	registry, err := Load()
	if err != nil {
		return Identity{}, fmt.Errorf("load trusted-tool registry: %w", err)
	}
	return registry.Resolve(name, requestedBin)
}

func Enroll(name, path string) (Identity, error) {
	if strings.TrimSpace(name) == "" {
		return Identity{}, errors.New("tool name is required")
	}
	kind := KindTrustedController
	if r, err := Load(); err == nil {
		if e, ok := r.Entry(name); ok && e.Kind != "" {
			kind = e.Kind
		}
	}
	identity, err := inspectPath(name, path)
	if err != nil {
		return Identity{}, err
	}
	entry := Entry{
		Name: name, Kind: kind, Path: identity.CanonicalPath, SHA256: identity.SHA256,
		OwnerUID: identity.OwnerUID, OwnerGID: identity.OwnerGID, Mode: fmt.Sprintf("%04o", identity.Mode.Perm()),
		Device: identity.Device, Inode: identity.Inode,
	}
	if err := updateRegistry(func(ff *fileFormat) error {
		replaceEntry(ff, entry)
		return nil
	}); err != nil {
		return Identity{}, err
	}
	return identity, nil
}

func Pin(name, path string) error {
	_, err := Enroll(name, path)
	return err
}

func Verify(name string) (Identity, error) {
	registry, err := Load()
	if err != nil {
		return Identity{}, err
	}
	return registry.Resolve(name, "")
}

func Rotate(name, path string) (Identity, error) { return Enroll(name, path) }

func inspectPath(name, path string) (Identity, error) {
	if strings.TrimSpace(path) == "" {
		return Identity{}, fmt.Errorf("tool %q: path is required", name)
	}
	if !filepath.IsAbs(path) {
		return Identity{}, fmt.Errorf("tool %q: path %q is not absolute", name, path)
	}
	canonical := path
	if eval, everr := filepath.EvalSymlinks(path); everr == nil {
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
	if info.IsDir() || info.Mode()&0o111 == 0 {
		return Identity{}, fmt.Errorf("resolve tool %q: %s is not executable", name, canonical)
	}
	var ownerUID, ownerGID uint32
	var dev, ino uint64
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		ownerUID, ownerGID = st.Uid, st.Gid
		dev, ino = uint64(st.Dev), uint64(st.Ino)
	}
	euid := os.Geteuid()
	if int(ownerUID) != euid && ownerUID != 0 {
		return Identity{}, fmt.Errorf("resolve tool %q: %s is owned by uid %d, not this process (%d) or root", name, canonical, ownerUID, euid)
	}
	if info.Mode()&0o022 != 0 {
		return Identity{}, fmt.Errorf("resolve tool %q: %s is group- or world-writable", name, canonical)
	}
	if parentWritable(canonical) {
		return Identity{}, fmt.Errorf("resolve tool %q: %s has a group- or world-writable executable ancestor", name, canonical)
	}
	sum := sha256.New()
	if _, err := io.Copy(sum, f); err != nil {
		return Identity{}, fmt.Errorf("resolve tool %q: hash %s: %w", name, canonical, err)
	}
	return Identity{Name: name, Kind: KindTrustedController, CanonicalPath: canonical, SHA256: hex.EncodeToString(sum.Sum(nil)), OwnerUID: ownerUID, OwnerGID: ownerGID, Mode: info.Mode(), Device: dev, Inode: ino}, nil
}

func validateEntry(path string, e Entry) error {
	if strings.TrimSpace(e.Name) == "" {
		return fmt.Errorf("tool registry %s: entry with empty name", path)
	}
	if e.Kind == "" {
		return fmt.Errorf("tool registry %s: tool %q missing kind", path, e.Name)
	}
	if e.Kind != KindTrustedController && e.Kind != KindSandboxedHelper && e.Kind != KindGovernedBackend {
		return fmt.Errorf("tool registry %s: tool %q has invalid kind %q", path, e.Name, e.Kind)
	}
	if e.Path != "" {
		if !filepath.IsAbs(e.Path) {
			return fmt.Errorf("tool registry %s: tool %q path must be absolute", path, e.Name)
		}
		if strings.TrimSpace(e.SHA256) == "" {
			return fmt.Errorf("tool registry %s: tool %q path is enrolled without mandatory sha256", path, e.Name)
		}
		if _, err := hex.DecodeString(e.SHA256); err != nil || len(e.SHA256) != 64 {
			return fmt.Errorf("tool registry %s: tool %q has invalid sha256", path, e.Name)
		}
	}
	return nil
}

func readRegistryFile(path string) (fileFormat, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fileFormat{}, false, nil
		}
		return fileFormat{}, false, fmt.Errorf("read tool registry %s: %w", path, err)
	}
	if info, err := os.Stat(path); err == nil {
		if info.Mode().Perm()&0o022 != 0 {
			return fileFormat{}, false, fmt.Errorf("tool registry %s is group- or world-writable", path)
		}
	}
	var node yaml.Node
	if err := yaml.Unmarshal(data, &node); err != nil {
		return fileFormat{}, false, fmt.Errorf("parse tool registry %s: %w", path, err)
	}
	if err := rejectDuplicateYAMLKeys(&node, path); err != nil {
		return fileFormat{}, false, err
	}
	var parsed fileFormat
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&parsed); err != nil {
		return fileFormat{}, false, fmt.Errorf("parse tool registry %s: %w", path, err)
	}
	return parsed, true, nil
}

func rejectDuplicateYAMLKeys(n *yaml.Node, path string) error {
	if n == nil {
		return nil
	}
	if n.Kind == yaml.MappingNode {
		seen := map[string]bool{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			key := n.Content[i].Value
			if seen[key] {
				return fmt.Errorf("tool registry %s: duplicate YAML key %q", path, key)
			}
			seen[key] = true
			if err := rejectDuplicateYAMLKeys(n.Content[i+1], path); err != nil {
				return err
			}
		}
		return nil
	}
	for _, c := range n.Content {
		if err := rejectDuplicateYAMLKeys(c, path); err != nil {
			return err
		}
	}
	return nil
}

func updateRegistry(mut func(*fileFormat) error) error {
	target := FilePath()
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(target), err)
	}
	lockPath := target + ".lock"
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open registry lock %s: %w", lockPath, err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("lock tool registry %s: %w", lockPath, err)
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)

	ff, exists, err := readRegistryFile(target)
	if err != nil {
		return err
	}
	if !exists {
		ff = fileFormat{Tools: []Entry{}}
	}
	if err := mut(&ff); err != nil {
		return err
	}
	ff.Generation++
	out, err := yaml.Marshal(ff)
	if err != nil {
		return fmt.Errorf("marshal tool registry: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(target), ".tools-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp registry: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod temp registry: %w", err)
	}
	if _, err := tmp.Write(out); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp registry: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("fsync temp registry: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp registry: %w", err)
	}
	if err := os.Rename(tmpName, target); err != nil {
		return fmt.Errorf("rename tool registry %s: %w", target, err)
	}
	if dir, err := os.Open(filepath.Dir(target)); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}

func replaceEntry(ff *fileFormat, entry Entry) {
	for i := range ff.Tools {
		if ff.Tools[i].Name == entry.Name {
			ff.Tools[i] = entry
			return
		}
	}
	ff.Tools = append(ff.Tools, entry)
}

func parentWritable(path string) bool {
	dir := filepath.Dir(path)
	for {
		info, err := os.Lstat(dir)
		if err != nil {
			return true
		}
		if info.Mode()&0o022 != 0 {
			return true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return false
		}
		dir = parent
	}
}
