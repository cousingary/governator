//go:build linux

package enforce

import (
	"fmt"
	"syscall"
)

// bindMountReadOnly bind-mounts src onto dst (which must already exist as an
// empty directory -- mount(2) requires the target to exist) and remounts
// that bind read-only. A single MS_BIND,MS_RDONLY mount(2) call does not
// itself make the mount read-only; the kernel requires the separate
// MS_REMOUNT pass Linux's own bind-mount documentation describes. Called by
// RunSandboxExec, from inside the private mount namespace Wrap already
// unshared for this launch, before the Landlock ruleset is applied.
func bindMountReadOnly(src, dst string) error {
	if err := syscall.Mount(src, dst, "", syscall.MS_BIND, ""); err != nil {
		return fmt.Errorf("bind %q onto %q: %w", src, dst, err)
	}
	if err := syscall.Mount("", dst, "", syscall.MS_BIND|syscall.MS_REMOUNT|syscall.MS_RDONLY, ""); err != nil {
		return fmt.Errorf("remount %q read-only: %w", dst, err)
	}
	return nil
}
