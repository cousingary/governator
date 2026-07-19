package toolregistry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
)

// Handle pins the verified-open executable object used by controller stages.
type Handle struct {
	Identity  Identity
	file      *os.File
	sealedDir string
}

func (r *Registry) ResolveHandle(name, requestedBin string, want Kind) (*Handle, error) {
	id, err := r.Resolve(name, requestedBin)
	if err != nil {
		return nil, err
	}
	if want != "" && id.Kind != want {
		return nil, fmt.Errorf("tool %q has kind %q, call site requires %q", name, id.Kind, want)
	}
	f, err := os.Open(id.CanonicalPath)
	if err != nil {
		return nil, fmt.Errorf("open verified tool %q: %w", name, err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
		}
	}()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("fstat verified tool %q: %w", name, err)
	}
	if st, yes := info.Sys().(*syscall.Stat_t); yes && (uint64(st.Dev) != id.Device || uint64(st.Ino) != id.Inode) {
		return nil, fmt.Errorf("tool %q changed between verification and handle open", name)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	sum := sha256.New()
	if _, err := io.Copy(sum, f); err != nil {
		return nil, err
	}
	if hex.EncodeToString(sum.Sum(nil)) != id.SHA256 {
		return nil, fmt.Errorf("tool %q content changed between verification and handle open", name)
	}
	ok = true
	return &Handle{Identity: id, file: f}, nil
}

func (h *Handle) Close() error {
	if h == nil || h.file == nil {
		return nil
	}
	err := h.file.Close()
	h.file = nil
	return err
}

// Command launches the held executable object, never its mutable enrolled path.
func (h *Handle) Command(ctx context.Context, args ...string) (*exec.Cmd, error) {
	if h == nil || h.file == nil {
		return nil, fmt.Errorf("tool handle is closed")
	}
	if runtime.GOOS == "linux" {
		cmd := exec.CommandContext(ctx, "/proc/self/fd/3", args...)
		cmd.ExtraFiles = []*os.File{h.file}
		return cmd, nil
	}
	return nil, fmt.Errorf("sealed controller-tool launch is unsupported on %s", runtime.GOOS)
}

// File returns the handle's held, already-verified file descriptor for a
// caller that must compose it into a launch chain with more than one
// descriptor-backed executable of its own (see enforce.Plan.Wrap, which
// chains a verified unshare object ahead of a verified Governator self-exec
// -- CommandWith only threads a single descriptor through one build
// callback, not two independent ones into the same exec.Cmd.ExtraFiles).
// The handle retains ownership: the caller must not close the returned
// file directly, only Handle.Close, and must not use it after Close.
func (h *Handle) File() *os.File {
	if h == nil {
		return nil
	}
	return h.file
}

// CommandWith composes fd-backed launch with a caller-owned scope/wrapper.
func (h *Handle) CommandWith(ctx context.Context, args []string, build func(context.Context, string, []string) *exec.Cmd) (*exec.Cmd, error) {
	if h == nil || h.file == nil {
		return nil, fmt.Errorf("tool handle is closed")
	}
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("sealed controller-tool launch is unsupported on %s", runtime.GOOS)
	}
	cmd := build(ctx, "/proc/self/fd/3", append([]string(nil), args...))
	cmd.ExtraFiles = []*os.File{h.file}
	return cmd, nil
}

// SealedExecutablePath copies the verified-open controller tool into a
// private immutable directory for wrapper-based launches that cannot rely on
// /proc/self/fd/<n> surviving all the way to the final exec.
func (h *Handle) SealedExecutablePath() (string, error) {
	if h == nil || h.file == nil {
		return "", fmt.Errorf("tool handle is closed")
	}
	if h.sealedDir != "" {
		return filepath.Join(h.sealedDir, filepath.Base(h.Identity.CanonicalPath)), nil
	}
	dir, err := os.MkdirTemp("", "governator-tool-exec-*")
	if err != nil {
		return "", fmt.Errorf("create sealed tool dir: %w", err)
	}
	outPath, err := h.sealInto(dir)
	if err != nil {
		_ = os.RemoveAll(dir)
		return "", err
	}
	if err := os.Chmod(dir, 0500); err != nil {
		_ = os.RemoveAll(dir)
		return "", fmt.Errorf("chmod sealed tool dir: %w", err)
	}
	h.sealedDir = dir
	return outPath, nil
}

// SealedExecutablePathIn copies the verified-open controller tool into the
// caller-supplied directory dir, returning the path to the sealed copy
// inside it. Used to populate a per-stage shared executable directory for
// structured validator toolsets (Sol9 P0-5): the directory becomes the
// validator's sole PATH entry, with one sealed object per declared tool,
// so declaring "go" can never expose python3/perl/curl/ssh/git/sh through
// PATH the way filepath.Dir(canonical) + ambient PATH did before. The
// caller owns dir and is responsible for removing it; this Handle retains
// no reference to it (a later SealedExecutablePath call still creates the
// handle's own private dir, unchanged). The sealed copy is created with
// O_CREAT|O_EXCL so a name collision inside dir -- two declared tools
// resolving to the same basename -- is rejected rather than silently
// overwriting one with the other.
func (h *Handle) SealedExecutablePathIn(dir string) (string, error) {
	if h == nil || h.file == nil {
		return "", fmt.Errorf("tool handle is closed")
	}
	if strings.TrimSpace(dir) == "" {
		return "", fmt.Errorf("sealed tool directory is empty")
	}
	return h.sealInto(dir)
}

// sealInto is the shared copy-verified-bytes-into-path primitive both
// SealedExecutablePath (private dir per handle) and SealedExecutablePathIn
// (shared caller dir for a structured validator toolset) drive. The
// caller owns the directory's lifecycle (creation, chmod, removal);
// sealInto only writes one exclusive file inside it.
func (h *Handle) sealInto(dir string) (string, error) {
	outPath := filepath.Join(dir, filepath.Base(h.Identity.CanonicalPath))
	out, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0500)
	if err != nil {
		return "", fmt.Errorf("create sealed tool copy: %w", err)
	}
	if _, err := h.file.Seek(0, io.SeekStart); err != nil {
		_ = out.Close()
		_ = os.Remove(outPath)
		return "", fmt.Errorf("rewind verified tool fd: %w", err)
	}
	_, copyErr := io.Copy(out, h.file)
	closeErr := out.Close()
	if copyErr != nil {
		_ = os.Remove(outPath)
		return "", fmt.Errorf("copy verified tool: %w", copyErr)
	}
	if closeErr != nil {
		_ = os.Remove(outPath)
		return "", fmt.Errorf("close sealed tool copy: %w", closeErr)
	}
	if err := os.Chmod(outPath, 0500); err != nil {
		_ = os.Remove(outPath)
		return "", fmt.Errorf("chmod sealed tool copy: %w", err)
	}
	return outPath, nil
}
