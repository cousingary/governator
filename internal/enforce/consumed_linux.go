//go:build linux

package enforce

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// mountConsumedArtifacts mounts a fresh, private tmpfs directly at dst and
// writes each spec's ("fdpath=name") sealed memfd content into dst/name,
// then remounts dst read-only -- all inside the private mount namespace Wrap
// already unshared for this launch (Sol11 P0-7). Called by RunSandboxExec,
// before the Landlock ruleset is applied, mirroring bindMountReadOnly's own
// ordering contract.
//
// dst never binds from a real host source directory: the only path the
// artifact bytes are ever written through is this fresh tmpfs, which comes
// into existence and stops existing entirely within this one launch's own
// mount namespace -- no other same-UID process, in the host namespace or any
// other launch's namespace, ever has a path into it.
func mountConsumedArtifacts(dst string, specs []string) error {
	if err := syscall.Mount("tmpfs", dst, "tmpfs", 0, "mode=0500"); err != nil {
		return fmt.Errorf("mount private tmpfs onto %q: %w", dst, err)
	}
	for _, spec := range specs {
		fdPath, name, ok := strings.Cut(spec, "=")
		if !ok || fdPath == "" || name == "" {
			return fmt.Errorf("malformed --consumed-fd (want fdpath=name): %s", spec)
		}
		if name != filepath.Base(name) || name == "." || name == ".." {
			return fmt.Errorf("consumed artifact name %q is not a safe basename", name)
		}
		src, err := os.Open(fdPath)
		if err != nil {
			return fmt.Errorf("open sealed consumed-artifact descriptor %q: %w", fdPath, err)
		}
		out, err := os.OpenFile(filepath.Join(dst, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
		if err != nil {
			_ = src.Close()
			return fmt.Errorf("create consumed artifact %q in private tmpfs: %w", name, err)
		}
		_, copyErr := io.Copy(out, src)
		_ = src.Close()
		closeErr := out.Close()
		if copyErr != nil {
			return fmt.Errorf("write consumed artifact %q into private tmpfs: %w", name, copyErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close consumed artifact %q in private tmpfs: %w", name, closeErr)
		}
	}
	if err := syscall.Mount("", dst, "", syscall.MS_REMOUNT|syscall.MS_RDONLY, ""); err != nil {
		return fmt.Errorf("remount %q read-only: %w", dst, err)
	}
	return nil
}
