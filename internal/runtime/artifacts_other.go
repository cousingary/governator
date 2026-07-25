//go:build !linux

package runtime

import (
	"fmt"
	"os"
)

// sealOneConsumedArtifact's real implementation (artifacts_linux.go)
// requires memfd_create + F_ADD_SEALS, Linux-only syscalls. This stub
// exists only so internal/runtime still cross-compiles for
// scripts/release.sh's darwin/amd64 and darwin/arm64 targets -- fails
// closed (not a weaker fallback) matching
// internal/enforce/consumed_other.go's own posture; the platform-approval
// gate (internal/redteamgate) refuses production release on an
// unapproved GOOS before any run reaches this path.
func sealOneConsumedArtifact(name string, _ []byte) (*os.File, error) {
	return nil, fmt.Errorf("seal consumed-artifact memfd %q: sealed-memfd consumed artifacts are Linux-only", name)
}
