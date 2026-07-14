//go:build linux

package containment

import "syscall"

// cgroupDirectSysProcAttr builds the SysProcAttr that atomically places a
// launched process into cgroupFD's cgroup at clone() time
// (CLONE_INTO_CGROUP). UseCgroupFD/CgroupFD are Linux-only
// syscall.SysProcAttr fields -- split into this file (and its !linux
// counterpart) so internal/containment still cross-compiles for
// scripts/release.sh's darwin/amd64 and darwin/arm64 targets, even though
// ScopeCgroupDirect (see descendants.go's Scope.Command) is only ever
// selected on Linux -- cgroup v2 doesn't exist anywhere else.
func cgroupDirectSysProcAttr(cgroupFD uintptr) *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Setpgid:     true,
		UseCgroupFD: true,
		CgroupFD:    int(cgroupFD),
	}
}
