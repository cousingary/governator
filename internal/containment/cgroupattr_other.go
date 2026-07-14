//go:build !linux

package containment

import "syscall"

// cgroupDirectSysProcAttr is unreachable on non-Linux: Scope selection
// never returns ScopeCgroupDirect off Linux (cgroup v2 doesn't exist
// there). This stub exists only so the package cross-compiles for
// scripts/release.sh's non-Linux build targets -- see the linux-tagged
// sibling file for the real implementation.
func cgroupDirectSysProcAttr(uintptr) *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true}
}
