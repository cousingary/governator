//go:build !linux

package assay

import (
	"fmt"
	"os"
)

// sealPackageMemfd is unreachable off Linux: BuildSnapshot (snapshot.go)
// already refuses to build a snapshot at all on a non-Linux GOOS before
// calling this. This stub exists only so internal/assay still cross-compiles
// for scripts/release.sh's darwin/amd64 and darwin/arm64 targets -- see the
// linux-tagged sibling file (snapshot_linux.go) for the real implementation,
// and internal/enforce/consumed_other.go for the matching "refuse, not
// degrade" posture.
func sealPackageMemfd(zipBytes []byte) (*os.File, error) {
	return nil, fmt.Errorf("assay: sealed-memfd package execution is Linux-only")
}

// verifyPackageSeals is unreachable off Linux for the same reason
// sealPackageMemfd is -- see its stub comment.
func verifyPackageSeals(pkg *os.File) error {
	return fmt.Errorf("assay: sealed-memfd package execution is Linux-only")
}
