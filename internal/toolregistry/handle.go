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
	Identity Identity
	file     *os.File
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
		cmd := exec.CommandContext(ctx, "/proc/self/fd/3", args...) // govratchet:exec-allow(production_launch_factory) -- this is the fd-based launch primitive itself
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

// SealedCopy is a private copy of a verified controller tool's bytes,
// published at a real filesystem path so PATH-based lookup by another
// process (bash finding "git" through PATH) or Landlock's path-based rule
// construction can reference it (Sol9 P0-5/P0-6/P1-4).
//
// Sol9 P1-4: a chmod(0500) private copy denies writes from a correctly
// confined stage but not from another process sharing the same UID -- that
// process can chmod the directory/file back open, overwrite the file in
// place, or unlink and recreate the directory entry with different
// content. Kernel content sealing (memfd_create + F_ADD_SEALS) would close
// this for good, but it cannot be combined with a real, PATH-discoverable
// pathname: linkat(2) publishing a memfd's anonymous shmem-backed inode
// into a real directory fails with EXDEV (cross-device link), because the
// two live on different filesystems/superblocks -- verified empirically
// against this deployment's kernel, not assumed from documentation. The
// FS_IMMUTABLE_FL ("chattr +i") route was checked too and requires
// CAP_LINUX_IMMUTABLE, which Governator does not run with.
//
// So for every call site that needs a real pathname, this is the report's
// documented fallback: "at minimum, verify the sealed object again
// immediately before launch and retain its descriptor throughout
// execution." SealedCopy retains an open read-only descriptor to the
// published file from the moment it is written, and Verify -- which every
// caller MUST invoke immediately before the launch that will reference
// Path by name -- re-checks both that the directory entry still resolves
// to the exact inode published (catches unlink+recreate) and that the
// bytes reachable through the retained descriptor still match what was
// published (catches an in-place overwrite). A caller that skips Verify
// has no better guarantee than a bare chmod-only copy did.
//
// This is a private read-only copy, not a cryptographically or kernel
// sealed object -- name and document it that way, never as "sealed."
type SealedCopy struct {
	Path string

	dir     string
	ownsDir bool
	file    *os.File
	dev     uint64
	ino     uint64
	sha256  string
}

// Verify re-checks, immediately before a launch that will reference Path
// by name, that the published copy has not been tampered with by a
// same-UID process since it was created. Any mismatch must be treated as
// a same-UID tamper attempt: the caller must fail closed, never launch.
func (s *SealedCopy) Verify() error {
	if s == nil || s.file == nil {
		return fmt.Errorf("sealed copy is not held")
	}
	info, err := os.Stat(s.Path)
	if err != nil {
		return fmt.Errorf("verify sealed copy %q: %w", s.Path, err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("verify sealed copy %q: platform does not expose inode identity", s.Path)
	}
	if uint64(st.Dev) != s.dev || uint64(st.Ino) != s.ino {
		return fmt.Errorf("sealed copy %q: directory entry replaced since publish (dev/inode mismatch)", s.Path)
	}
	if _, err := s.file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("verify sealed copy %q: rewind retained descriptor: %w", s.Path, err)
	}
	sum := sha256.New()
	if _, err := io.Copy(sum, s.file); err != nil {
		return fmt.Errorf("verify sealed copy %q: read retained descriptor: %w", s.Path, err)
	}
	if hex.EncodeToString(sum.Sum(nil)) != s.sha256 {
		return fmt.Errorf("sealed copy %q: content changed since publish", s.Path)
	}
	return nil
}

// Close releases the retained descriptor. If this SealedCopy owns its
// private directory (created by SealedExecutablePath, as opposed to
// SealedExecutablePathIn's caller-owned shared directory), Close also
// removes it.
func (s *SealedCopy) Close() error {
	if s == nil {
		return nil
	}
	var err error
	if s.file != nil {
		err = s.file.Close()
		s.file = nil
	}
	if s.ownsDir && s.dir != "" {
		_ = os.RemoveAll(s.dir)
		s.dir = ""
	}
	return err
}

// SealedExecutablePath copies the verified-open controller tool into a
// private directory for wrapper-based launches that cannot rely on
// /proc/self/fd/<n> surviving all the way to the final exec (Landlock's
// path-based rule construction, or another process finding the tool by
// name through PATH). The caller owns the returned SealedCopy: it MUST
// call Verify immediately before the launch that will reference Path, and
// MUST call Close once that launch has finished (Close removes the
// private directory this call created).
func (h *Handle) SealedExecutablePath() (*SealedCopy, error) {
	if h == nil || h.file == nil {
		return nil, fmt.Errorf("tool handle is closed")
	}
	dir, err := os.MkdirTemp("", "governator-tool-exec-*")
	if err != nil {
		return nil, fmt.Errorf("create sealed tool dir: %w", err)
	}
	sc, err := h.sealInto(dir)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	if err := os.Chmod(dir, 0500); err != nil {
		_ = sc.Close()
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("chmod sealed tool dir: %w", err)
	}
	sc.dir = dir
	sc.ownsDir = true
	return sc, nil
}

// SealedExecutablePathIn copies the verified-open controller tool into the
// caller-supplied directory dir. Used to populate a per-stage shared
// executable directory for structured validator toolsets (Sol9 P0-5): the
// directory becomes the validator's sole PATH entry, with one private copy
// per declared tool, so declaring "go" can never expose
// python3/perl/curl/ssh/git/sh through PATH the way filepath.Dir(canonical)
// + ambient PATH did before. The caller owns dir's lifecycle (creation,
// chmod, removal); the returned SealedCopy's Close only releases its
// retained descriptor, it never removes dir. The copy is created with
// O_CREAT|O_EXCL so a name collision inside dir -- two declared tools
// resolving to the same basename -- is rejected rather than silently
// overwriting one with the other. As with SealedExecutablePath, the caller
// MUST call Verify on the returned SealedCopy immediately before the
// launch that will reference Path.
func (h *Handle) SealedExecutablePathIn(dir string) (*SealedCopy, error) {
	if h == nil || h.file == nil {
		return nil, fmt.Errorf("tool handle is closed")
	}
	if strings.TrimSpace(dir) == "" {
		return nil, fmt.Errorf("sealed tool directory is empty")
	}
	return h.sealInto(dir)
}

// sealInto is the shared copy-verified-bytes-into-path primitive both
// SealedExecutablePath (private dir per handle) and SealedExecutablePathIn
// (shared caller dir for a structured validator toolset) drive. The caller
// owns the directory's lifecycle (creation, chmod, removal); sealInto only
// writes one exclusive file inside it, then opens and retains a read-only
// descriptor to that file plus its golden dev/inode/sha256 record so the
// returned SealedCopy.Verify can detect later same-UID tampering.
func (h *Handle) sealInto(dir string) (*SealedCopy, error) {
	outPath := filepath.Join(dir, filepath.Base(h.Identity.CanonicalPath))
	out, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0500)
	if err != nil {
		return nil, fmt.Errorf("create sealed tool copy: %w", err)
	}
	if _, err := h.file.Seek(0, io.SeekStart); err != nil {
		_ = out.Close()
		_ = os.Remove(outPath)
		return nil, fmt.Errorf("rewind verified tool fd: %w", err)
	}
	sum := sha256.New()
	if _, err := io.Copy(io.MultiWriter(out, sum), h.file); err != nil {
		_ = out.Close()
		_ = os.Remove(outPath)
		return nil, fmt.Errorf("copy verified tool: %w", err)
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(outPath)
		return nil, fmt.Errorf("close sealed tool copy: %w", err)
	}
	if err := os.Chmod(outPath, 0500); err != nil {
		_ = os.Remove(outPath)
		return nil, fmt.Errorf("chmod sealed tool copy: %w", err)
	}
	retained, err := os.OpenFile(outPath, os.O_RDONLY, 0)
	if err != nil {
		_ = os.Remove(outPath)
		return nil, fmt.Errorf("open retained descriptor for sealed tool copy: %w", err)
	}
	info, err := retained.Stat()
	if err != nil {
		_ = retained.Close()
		_ = os.Remove(outPath)
		return nil, fmt.Errorf("stat sealed tool copy: %w", err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		_ = retained.Close()
		_ = os.Remove(outPath)
		return nil, fmt.Errorf("sealed tool copy %q: platform does not expose inode identity", outPath)
	}
	return &SealedCopy{
		Path:   outPath,
		file:   retained,
		dev:    uint64(st.Dev),
		ino:    uint64(st.Ino),
		sha256: hex.EncodeToString(sum.Sum(nil)),
	}, nil
}
