//go:build linux

package pathsafe

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// OpenBeneath opens relPath -- a slash-separated path relative to baseDir --
// guaranteeing every path component (not just the final one) is resolved
// fresh, atomically, as part of a single syscall, and refusing the whole
// operation if any component is a symlink, a "magic link" (a /proc-style
// bind that resolves to something outside baseDir without itself being a
// classic symlink), or would resolve outside baseDir.
//
// A caller building an already-joined absolute path and opening it with a
// bare O_NOFOLLOW only ever guards the FINAL path component: an attacker who
// replaces a PARENT directory with a symlink between an earlier scan/
// validation step (which built that path string) and this open sails
// through undetected, because the kernel resolves every parent component
// using whatever the filesystem looks like at open time regardless of what
// O_NOFOLLOW says about the last one -- there is no way to protect a parent
// component after the fact with a flag on the final open() call.
//
// openat2's RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS makes
// the kernel itself walk and validate every component of relPath as part of
// the one openat2 syscall, refusing the instant any component doesn't
// qualify. There is no window between "figure out whether this path is
// safe" and "open it" for a parent-component swap to land in, because those
// are no longer two separate steps.
//
// Requires Linux 5.6+ (openat2). Fails closed rather than silently
// degrading to the weaker final-component-only check when openat2 itself is
// unavailable (ENOSYS).
//
// perm is passed through as the openat2 mode bits and matters only when
// flags includes os.O_CREATE (or O_TMPFILE): unlike legacy open()/openat(),
// which silently ignores a nonzero mode when O_CREAT isn't set, openat2
// validates this strictly and returns EINVAL for a nonzero perm without
// O_CREATE/O_TMPFILE in flags. Callers opening an existing file (no
// O_CREATE) must pass 0.
func OpenBeneath(baseDir, relPath string, flags int, perm os.FileMode) (*os.File, error) {
	baseFd, err := unix.Open(baseDir, unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open base directory %q: %w", baseDir, err)
	}
	defer unix.Close(baseFd)

	return openat2(baseFd, baseDir, relPath, flags, perm)
}

// OpenBeneathFd is OpenBeneath's held-descriptor variant: relPath is
// resolved beneath the already-open directory descriptor base, atomically,
// via a single openat2 syscall. A caller validating several paths beneath
// the same directory (for example, one write root per declared carve-out)
// should open that directory once and reuse the descriptor across every
// call instead of letting each call independently reopen the base
// directory by pathname -- reopening by pathname re-trusts whatever the
// filesystem looks like at that moment, which reintroduces exactly the kind
// of parent-component race this package exists to close, just moved up one
// level to the base directory argument itself. base must have been opened
// with O_DIRECTORY|O_NOFOLLOW (as resolveRealDir-style callers do); this
// function does not re-verify that.
func OpenBeneathFd(base *os.File, relPath string, flags int, perm os.FileMode) (*os.File, error) {
	return openat2(int(base.Fd()), base.Name(), relPath, flags, perm)
}

func openat2(baseFd int, baseDir, relPath string, flags int, perm os.FileMode) (*os.File, error) {
	how := unix.OpenHow{
		Flags:   uint64(flags) | unix.O_CLOEXEC,
		Mode:    uint64(perm),
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	}
	fd, err := unix.Openat2(baseFd, relPath, &how)
	if err != nil {
		if errors.Is(err, unix.ENOSYS) {
			return nil, fmt.Errorf("openat2 unavailable on this kernel; refusing %q beneath %q rather than falling back to a weaker parent-component check: %w", relPath, baseDir, err)
		}
		return nil, fmt.Errorf("openat2 %q beneath %q: %w", relPath, baseDir, err)
	}
	return os.NewFile(uintptr(fd), filepath.Join(baseDir, relPath)), nil
}

// RealPath returns the kernel-resolved absolute path an already-open file
// descriptor refers to, via /proc/self/fd. Unlike filepath.EvalSymlinks
// (which re-walks the path in userspace, one lstat/readlink at a time, and
// can itself race a concurrent rename), this reads the resolution the
// kernel already committed to when the descriptor was opened -- it can
// never observe a state other than "what f actually points at right now."
func RealPath(f *os.File) (string, error) {
	link := fmt.Sprintf("/proc/self/fd/%d", f.Fd())
	real, err := os.Readlink(link)
	if err != nil {
		return "", fmt.Errorf("resolve real path of fd %d: %w", f.Fd(), err)
	}
	return real, nil
}
