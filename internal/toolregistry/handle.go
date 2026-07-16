package toolregistry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
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
		cmd := exec.CommandContext(ctx, "/proc/self/fd/3", args...)
		cmd.ExtraFiles = []*os.File{h.file}
		return cmd, nil
	}
	return nil, fmt.Errorf("sealed controller-tool launch is unsupported on %s", runtime.GOOS)
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
