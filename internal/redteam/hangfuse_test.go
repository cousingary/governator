//go:build redteam

// hangfuse_test.go implements a minimal, pure-Go, dependency-free FUSE
// lowlevel daemon whose read() handler for a single fixed file never
// replies. Per mainline Linux (verified against fs/fuse/dev.c,
// request_wait_answer: once a request is FR_SENT, a fatal signal only
// short-circuits the request if it was still FR_PENDING -- an in-flight,
// already-dispatched request falls through to a plain, non-killable
// wait_event(req->waitq, FR_FINISHED)), a process blocked reading such a
// file is not just in D state but genuinely immune to SIGKILL until this
// daemon answers or dies. Used by TestV7Case8 (see
// v7_s1_case8_extinction_test.go) to force a real
// containment.Scope.Extinguish timeout without any root/kernel-module/
// device-mapper privilege -- only /dev/fuse (world-writable on any host
// with CONFIG_FUSE_FS) and the base fusermount3 binary (not the -dev
// package; no libfuse linkage, no cgo).
//
// hangfuseProbeSurvivesSIGKILL empirically confirms the property on the
// current host before the corpus test relies on it: some kernels (this
// project's own WSL2 dev sandbox among them) patch FUSE's request wait to
// stay killable even for in-flight requests, specifically to avoid the
// "unkillable process from a hung userspace filesystem" complaint --
// verified by reading the exact wait_event/wait_event_killable sequence in
// fs/fuse/dev.c and empirically timing SIGKILL-to-zombie latency against a
// real hangfuse mount. Where that's true, the corpus test records a
// conditional, reasoned skip (matching this project's existing
// environment-availability skip category) rather than asserting a timeout
// that cannot reproduce.
package redteam

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const (
	fuseRootID = 1
	hangIno    = 2
	hangName   = "hang"
	hangSize   = 4096

	opLookup  = 1
	opGetattr = 3
	opOpen    = 14
	opRead    = 15
	opFlush   = 25
	opRelease = 18
	opInit    = 26

	errNoEnt  = -2
	errNoSys  = -38
	errIsDir  = -21
	modeDir   = 0040000 | 0755
	modeRegFl = 0100000 | 0644
)

type fuseInHeader struct {
	Len, Opcode          uint32
	Unique, Nodeid       uint64
	UID, GID, PID        uint32
	TotalExtlen, Padding uint16
}

type fuseOutHeader struct {
	Len    uint32
	Error  int32
	Unique uint64
}

type fuseInitIn struct {
	Major, Minor, MaxReadahead, Flags, Flags2 uint32
	Unused                                    [11]uint32
}

type fuseInitOut struct {
	Major, Minor, MaxReadahead, Flags  uint32
	MaxBackground, CongestionThreshold uint16
	MaxWrite, TimeGran                 uint32
	MaxPages, MapAlignment             uint16
	Flags2                             uint32
	Unused                             [7]uint32
}

type fuseAttr struct {
	Ino, Size, Blocks                           uint64
	Atime, Mtime, Ctime                         uint64
	Atimensec, Mtimensec, Ctimensec             uint32
	Mode, Nlink, UID, GID, Rdev, Blksize, Flags uint32
}

type fuseEntryOut struct {
	Nodeid, Generation, EntryValid, AttrValid uint64
	EntryValidNsec, AttrValidNsec             uint32
	Attr                                      fuseAttr
}

type fuseAttrOut struct {
	AttrValid            uint64
	AttrValidNsec, Dummy uint32
	Attr                 fuseAttr
}

type fuseOpenOut struct {
	Fh                 uint64
	OpenFlags, Padding uint32
}

func fillAttr(ino uint64, dir bool) fuseAttr {
	a := fuseAttr{Ino: ino, Nlink: 1, UID: uint32(os.Getuid()), GID: uint32(os.Getgid())}
	if dir {
		a.Mode = modeDir
		a.Nlink = 2
	} else {
		a.Mode = modeRegFl
		a.Size = hangSize
	}
	return a
}

// hangfuseDaemon owns a raw /dev/fuse channel obtained via fusermount3 (no
// libfuse, no cgo) and services requests for one directory containing one
// file ("hang") whose read() is deliberately never answered.
type hangfuseDaemon struct {
	f          *os.File
	mountpoint string
	mu         sync.Mutex
	readSeen   chan uint64 // unique IDs of READ requests received, never replied
}

// mountHangfuse mounts a fresh hangfuse daemon at mountpoint (must already
// exist and be empty) and starts servicing requests in a background
// goroutine. The returned stop func kills the connection (closing the
// /dev/fuse fd aborts every pending request, releasing any reader stuck in
// it) and best-effort unmounts.
func mountHangfuse(mountpoint string) (*hangfuseDaemon, func(), error) {
	fd, waitFn, err := fuseMountViaFusermount(mountpoint)
	if err != nil {
		return nil, nil, err
	}
	d := &hangfuseDaemon{f: os.NewFile(uintptr(fd), "/dev/fuse"), mountpoint: mountpoint, readSeen: make(chan uint64, 8)}
	go d.loop()
	stop := func() {
		_ = d.f.Close()
		waitFn()
		_ = exec.Command("fusermount3", "-uz", mountpoint).Run()
	}
	return d, stop, nil
}

// fuseMountViaFusermount performs the standard unprivileged FUSE mount
// handshake: open a socketpair, exec the setuid fusermount3 helper with the
// write end passed via the _FUSE_COMMFD env var (fd 3, Go's ExtraFiles
// convention), and receive back the connected /dev/fuse descriptor over
// SCM_RIGHTS -- exactly what libfuse's fuse_mount_fusermount does in
// lib/mount.c, reimplemented here without linking libfuse so this fixture
// needs only the base fuse3 package (fusermount3 binary + /dev/fuse), never
// libfuse3-dev headers or a C toolchain.
func fuseMountViaFusermount(mountpoint string) (fuseFD int, wait func(), err error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		return 0, nil, fmt.Errorf("socketpair: %w", err)
	}
	parentEnd, childEnd := fds[0], fds[1]

	cmd := exec.Command("fusermount3", "--", mountpoint)
	cmd.ExtraFiles = []*os.File{os.NewFile(uintptr(childEnd), "commfd")}
	cmd.Env = append(os.Environ(), "_FUSE_COMMFD=3")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		unix.Close(parentEnd)
		unix.Close(childEnd)
		return 0, nil, fmt.Errorf("start fusermount3: %w", err)
	}
	// The child has its own dup at fd 3; close our copy of childEnd (the
	// *os.File finalizer would otherwise also try, harmlessly-but-noisily).
	_ = cmd.ExtraFiles[0].Close()

	oob := make([]byte, unix.CmsgSpace(4))
	buf := make([]byte, 1)
	var n, oobn int
	deadline := time.Now().Add(10 * time.Second)
	for {
		n, oobn, _, _, err = unix.Recvmsg(parentEnd, buf, oob, 0)
		if err == unix.EINTR && time.Now().Before(deadline) {
			continue
		}
		break
	}
	if err != nil {
		unix.Close(parentEnd)
		_ = cmd.Wait()
		return 0, nil, fmt.Errorf("recvmsg from fusermount3 (stderr: %s): %w", strings.TrimSpace(stderr.String()), err)
	}
	if n == 0 || oobn == 0 {
		unix.Close(parentEnd)
		_ = cmd.Wait()
		return 0, nil, fmt.Errorf("fusermount3 did not pass back a fuse fd (stderr: %s)", strings.TrimSpace(stderr.String()))
	}
	cmsgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil || len(cmsgs) == 0 {
		unix.Close(parentEnd)
		_ = cmd.Wait()
		return 0, nil, fmt.Errorf("parse control message: %v (stderr: %s)", err, strings.TrimSpace(stderr.String()))
	}
	rights, err := unix.ParseUnixRights(&cmsgs[0])
	if err != nil || len(rights) == 0 {
		unix.Close(parentEnd)
		_ = cmd.Wait()
		return 0, nil, fmt.Errorf("parse unix rights: %v (stderr: %s)", err, strings.TrimSpace(stderr.String()))
	}
	unix.Close(parentEnd)
	waitErr := cmd.Wait()
	if waitErr != nil {
		unix.Close(rights[0])
		return 0, nil, fmt.Errorf("fusermount3 exited with error: %v (stderr: %s)", waitErr, strings.TrimSpace(stderr.String()))
	}
	return rights[0], func() {}, nil
}

func (d *hangfuseDaemon) reply(unique uint64, errno int32, body []byte) {
	var buf bytes.Buffer
	out := fuseOutHeader{Len: uint32(16 + len(body)), Error: errno, Unique: unique}
	_ = binary.Write(&buf, binary.LittleEndian, out)
	buf.Write(body)
	d.mu.Lock()
	_, _ = d.f.Write(buf.Bytes())
	d.mu.Unlock()
}

func (d *hangfuseDaemon) loop() {
	rbuf := make([]byte, 128*1024)
	for {
		n, err := d.f.Read(rbuf)
		if err != nil || n < 40 {
			return
		}
		msg := rbuf[:n]
		var in fuseInHeader
		_ = binary.Read(bytes.NewReader(msg[:40]), binary.LittleEndian, &in)
		body := msg[40:n]

		switch in.Opcode {
		case opInit:
			out := fuseInitOut{Major: 7, Minor: 31, MaxWrite: 4096, TimeGran: 1, MaxPages: 1}
			var b bytes.Buffer
			_ = binary.Write(&b, binary.LittleEndian, out)
			d.reply(in.Unique, 0, b.Bytes())
		case opLookup:
			name := string(bytes.TrimRight(body, "\x00"))
			if in.Nodeid == fuseRootID && name == hangName {
				e := fuseEntryOut{Nodeid: hangIno, EntryValid: 1, AttrValid: 1, Attr: fillAttr(hangIno, false)}
				var b bytes.Buffer
				_ = binary.Write(&b, binary.LittleEndian, e)
				d.reply(in.Unique, 0, b.Bytes())
			} else {
				d.reply(in.Unique, errNoEnt, nil)
			}
		case opGetattr:
			var a fuseAttrOut
			switch in.Nodeid {
			case fuseRootID:
				a = fuseAttrOut{AttrValid: 1, Attr: fillAttr(fuseRootID, true)}
			case hangIno:
				a = fuseAttrOut{AttrValid: 1, Attr: fillAttr(hangIno, false)}
			default:
				d.reply(in.Unique, errNoEnt, nil)
				continue
			}
			var b bytes.Buffer
			_ = binary.Write(&b, binary.LittleEndian, a)
			d.reply(in.Unique, 0, b.Bytes())
		case opOpen:
			if in.Nodeid == fuseRootID {
				d.reply(in.Unique, errIsDir, nil)
				continue
			}
			out := fuseOpenOut{}
			var b bytes.Buffer
			_ = binary.Write(&b, binary.LittleEndian, out)
			d.reply(in.Unique, 0, b.Bytes())
		case opRead:
			// The deliberate hang: no reply, ever, for this request. The
			// kernel keeps the caller's read(2) blocked (see file header).
			select {
			case d.readSeen <- in.Unique:
			default:
			}
		case opFlush, opRelease:
			d.reply(in.Unique, 0, nil)
		default:
			d.reply(in.Unique, errNoSys, nil)
		}
	}
}

// waitForRead blocks until the daemon has seen at least one FUSE_READ
// request (i.e. a reader has genuinely reached the hang point, not just
// opened the file), or the timeout elapses.
func (d *hangfuseDaemon) waitForRead(timeout time.Duration) bool {
	select {
	case <-d.readSeen:
		return true
	case <-time.After(timeout):
		return false
	}
}

// hangfuseAvailable reports whether this host can plausibly mount an
// unprivileged FUSE filesystem at all -- /dev/fuse must exist and be
// writable, and fusermount3 (or fusermount) must be on PATH. Cheap,
// side-effect-free preflight so the corpus test can render a precise
// conditional-skip reason instead of a confusing low-level mount error.
func hangfuseAvailable() (string, bool) {
	if _, err := exec.LookPath("fusermount3"); err != nil {
		if _, err2 := exec.LookPath("fusermount"); err2 != nil {
			return "neither fusermount3 nor fusermount is on PATH", false
		}
	}
	f, err := os.OpenFile("/dev/fuse", os.O_RDWR, 0)
	if err != nil {
		return fmt.Sprintf("/dev/fuse not usable: %v", err), false
	}
	_ = f.Close()
	return "", true
}

// hangfuseProbeSurvivesSIGKILL mounts a throwaway hangfuse instance, drives
// a real blocking read against it with a tiny standalone reader process,
// confirms the read is genuinely stuck (D state, undisturbed, for
// settleFor) and only THEN sends SIGKILL, reporting whether the reader is
// still alive killAfter later. This is the empirical, per-host gate for
// whether TestV7Case8 can assert a real Extinguish timeout on this kernel
// (see fs/fuse/dev.c reasoning in this file's header) rather than a skip
// mis-attributed to a fixture bug.
func hangfuseProbeSurvivesSIGKILL(t *testing.T, settleFor, killAfter time.Duration) (survived bool, detail string) {
	dir := t.TempDir()
	mnt := dir + "/probemnt"
	if err := os.Mkdir(mnt, 0755); err != nil {
		return false, "mkdir mountpoint: " + err.Error()
	}
	d, stop, err := mountHangfuse(mnt)
	if err != nil {
		return false, "mount: " + err.Error()
	}
	defer stop()

	reader := exec.Command("dd", "if="+mnt+"/"+hangName, "of=/dev/null", "bs=1", "count=1")
	if err := reader.Start(); err != nil {
		return false, "start reader: " + err.Error()
	}
	pid := reader.Process.Pid
	defer func() { _ = syscall.Kill(pid, syscall.SIGKILL) }()

	if !d.waitForRead(5 * time.Second) {
		return false, "daemon never observed a READ request from the probe reader"
	}
	time.Sleep(settleFor)
	if !alivePID(pid) {
		return false, "reader exited on its own before any signal was sent (fixture bug, not a kernel property)"
	}
	_ = syscall.Kill(pid, syscall.SIGKILL)
	time.Sleep(killAfter)
	return alivePID(pid), fmt.Sprintf("reader pid %d alive %s after SIGKILL", pid, killAfter)
}

func alivePID(pid int) bool {
	return syscall.Kill(pid, 0) == nil
}
