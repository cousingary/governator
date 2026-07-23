//go:build !linux

package enforce

import "fmt"

// mountConsumedArtifacts is unreachable off Linux: Plan.ConsumedArtifacts is
// only ever populated by the local-runner enforcement path (Landlock +
// unshare are Linux-only), so RunSandboxExec's --consumed-fd/--consumed-dst
// handling never runs elsewhere. This stub exists only so internal/enforce
// still cross-compiles for scripts/release.sh's non-Linux build targets,
// matching robind_other.go's own doc comment.
func mountConsumedArtifacts(dst string, specs []string) error {
	return fmt.Errorf("consumed-artifact tmpfs projection is only supported on Linux (dst=%q)", dst)
}
