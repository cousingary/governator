//go:build !linux

package runtime

import (
	"fmt"
	"os"
)

// openBeneath's real implementation (openbeneath.go) requires Linux 5.6+'s
// openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS), which
// doesn't exist on any other platform. This codebase's actual deployment
// target is Linux/WSL2 (see internal/containment's cgroup v2 primitive,
// equally Linux-only) -- this stub exists only so the package cross-compiles
// for scripts/release.sh's non-Linux build targets, not to offer a working
// (and necessarily weaker, final-component-only) fallback on those
// platforms. Same "refuse, not degrade" posture openbeneath.go documents for
// openat2's own ENOSYS case.
func openBeneath(baseDir, relPath string, flags int, perm os.FileMode) (*os.File, error) {
	return nil, fmt.Errorf("openBeneath(%q, %q): openat2-based beneath-open is Linux-only; refusing rather than falling back to a weaker parent-component check on this platform", baseDir, relPath)
}
