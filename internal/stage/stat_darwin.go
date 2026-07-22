package stage

import (
	"syscall"
	"time"
)

// statCtimeNS returns st.Ctimespec as nanoseconds since epoch. See
// stat_linux.go's doc comment for why this is split per GOOS.
func statCtimeNS(st *syscall.Stat_t) int64 {
	return int64(st.Ctimespec.Sec)*int64(time.Second) + int64(st.Ctimespec.Nsec)
}
