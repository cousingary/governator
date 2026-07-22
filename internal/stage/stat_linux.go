package stage

import (
	"syscall"
	"time"
)

// statCtimeNS returns st.Ctim as nanoseconds since epoch. Linux's
// syscall.Stat_t names the field Ctim; darwin's names it Ctimespec
// (stat_darwin.go) -- same Timespec shape, different field name per GOOS,
// which is why this lives behind a build tag rather than inline in
// statWriteRootPath.
func statCtimeNS(st *syscall.Stat_t) int64 {
	return int64(st.Ctim.Sec)*int64(time.Second) + int64(st.Ctim.Nsec)
}
