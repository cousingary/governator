//go:build redteam

package redteam

import "testing"

// TestAttack22SymlinkParentReplacedBetweenScanAndOpen is report P1-7 /
// §9 attack 22: O_NOFOLLOW only protects the final path component; an
// attacker replaces a parent directory with a symlink between tree
// scanning, path resolution, and file opening (produced/consumed
// artifacts, schemas, validator outputs, snapshot files, release evidence,
// workspace-controlled config). Fixed by S7: pathsafe.OpenBeneath
// (internal/pathsafe/openbeneath.go -- extracted from internal/runtime's
// original package-private openBeneath by rc3 Session 7 so
// internal/enforce's Landlock write-carve-out resolution, Sol9 P1-3, could
// reuse the same primitive instead of reimplementing it) resolves every
// no-follow artifact read/write via openat2 with
// RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS, so the kernel
// validates every path component -- not just the final one -- as one
// atomic syscall; internal/runtime/artifacts.go's readRegularBeneath/
// writeNewBeneath/writeOverwriteBeneath (produced/consumed artifacts,
// schemas) route through it instead of the old absolute-path-plus-
// O_NOFOLLOW helpers.
//
// The real regression tests live in internal/runtime and internal/pathsafe
// (this package can't import another package's _test.go file, and this is
// a filesystem-kernel property, not something a governed-run black-box
// fixture is the natural home for -- same class of gap as attack 17/P1-3).
// This test only proves those fixtures still exist:
// internal/runtime/openbeneath_test.go::
// TestOpenBeneathRefusesParentComponentSymlink and
// TestOpenBeneathRefusesParentComponentSymlinkEvenAfterPriorSafeResolution.
func TestAttack22SymlinkParentReplacedBetweenScanAndOpen(t *testing.T) {
	assertRuntimeTestFileContains(t, "openbeneath_test.go",
		"func TestOpenBeneathRefusesParentComponentSymlink(",
		"func TestOpenBeneathRefusesParentComponentSymlinkEvenAfterPriorSafeResolution(",
	)
	assertPathsafeTestFileContains(t, "openbeneath.go",
		"RESOLVE_BENEATH",
		"RESOLVE_NO_SYMLINKS",
		"RESOLVE_NO_MAGICLINKS",
	)
}
