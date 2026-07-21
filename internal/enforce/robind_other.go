//go:build !linux

package enforce

import "fmt"

// bindMountReadOnly is unreachable off Linux: Plan.ROBinds is only ever
// populated by the local-runner enforcement path (Landlock + unshare are
// Linux-only), so RunSandboxExec's --ro-bind handling never runs elsewhere.
// This stub exists only so internal/enforce still cross-compiles for
// scripts/release.sh's non-Linux build targets, matching
// internal/containment/cgroupattr_other.go's own doc comment.
func bindMountReadOnly(src, dst string) error {
	return fmt.Errorf("read-only bind mounts are only supported on Linux (src=%q dst=%q)", src, dst)
}
