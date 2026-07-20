//go:build !linux

package pathsafe

import (
	"fmt"
	"os"
)

// OpenBeneath's real implementation (openbeneath.go) requires Linux 5.6+'s
// openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS), which
// doesn't exist on any other platform. This codebase's actual deployment
// target is Linux/WSL2 -- this stub exists only so the package
// cross-compiles for scripts/release.sh's non-Linux build targets, not to
// offer a working (and necessarily weaker, final-component-only) fallback on
// those platforms. Same "refuse, not degrade" posture openbeneath.go
// documents for openat2's own ENOSYS case.
func OpenBeneath(baseDir, relPath string, flags int, perm os.FileMode) (*os.File, error) {
	return nil, fmt.Errorf("OpenBeneath(%q, %q): openat2-based beneath-open is Linux-only; refusing rather than falling back to a weaker parent-component check on this platform", baseDir, relPath)
}

// OpenBeneathFd's real implementation (openbeneath.go) is Linux-only. See
// OpenBeneath's stub comment for why this package doesn't attempt a weaker
// cross-platform fallback.
func OpenBeneathFd(base *os.File, relPath string, flags int, perm os.FileMode) (*os.File, error) {
	return nil, fmt.Errorf("OpenBeneathFd(%q): openat2-based beneath-open is Linux-only; refusing rather than falling back to a weaker parent-component check on this platform", relPath)
}

// RealPath's real implementation (openbeneath.go) resolves via
// /proc/self/fd, which is Linux-only. See OpenBeneath's stub comment for
// why this package doesn't attempt a weaker cross-platform fallback.
func RealPath(f *os.File) (string, error) {
	return "", fmt.Errorf("RealPath: /proc/self/fd resolution is Linux-only")
}
