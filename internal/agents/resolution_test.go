package agents

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeExecutable writes a trivial shell script at path and marks it
// executable. body is appended after the shebang.
func writeExecutable(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0755); err != nil {
		t.Fatal(err)
	}
}

// TestSol3ResolvePathBareNameProducesRealHash is corpus #2's unit-level
// assertion: a bare configured name (backends.pi.bin: pi, the default —
// config.BackendBin("pi") returns the literal string "pi") must be resolved
// through PATH and hashed for real. Before the fix, computeExecutionIdentity
// hashed the bare string directly via os.ReadFile, which can never find a
// PATH-relative name from an arbitrary working directory and always produced
// the fixed "unreadable:pi" sentinel — never the executable's actual content
// hash — regardless of what "pi" resolved to or what its content was.
func TestSol3ResolvePathBareNameProducesRealHash(t *testing.T) {
	binDir := t.TempDir()
	binPath := filepath.Join(binDir, "pi")
	writeExecutable(t, binPath, "echo real-pi\n")
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	// No GOV_PI_BIN override: config.BackendBin("pi") must fall through to
	// the built-in bare name "pi", reproducing `backends: pi: bin: pi`.
	agent, err := New("pi")
	if err != nil {
		t.Fatal(err)
	}
	res, err := ResolvePath(agent)
	if err != nil {
		t.Fatalf("ResolvePath: %v", err)
	}
	if res.Requested != "pi" {
		t.Fatalf("Requested = %q, want bare name %q", res.Requested, "pi")
	}
	if strings.HasPrefix(res.SHA256, "unreadable") || res.SHA256 == "" {
		t.Fatalf("SHA256 = %q, want a real content hash, not a sentinel", res.SHA256)
	}
	data, err := os.ReadFile(binPath)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	want := hex.EncodeToString(sum[:])
	if res.SHA256 != want {
		t.Fatalf("SHA256 = %q, want %q (actual content hash of the PATH-resolved binary)", res.SHA256, want)
	}
	if !filepath.IsAbs(res.CanonicalPath) {
		t.Fatalf("CanonicalPath = %q, want an absolute path", res.CanonicalPath)
	}
	if resolvedData, err := os.ReadFile(res.CanonicalPath); err != nil || sha256.Sum256(resolvedData) != sha256.Sum256(data) {
		t.Fatalf("CanonicalPath %q does not point at the PATH-resolved binary", res.CanonicalPath)
	}
}

// TestSol3ResolvePathFailsClosedWhenUnresolvable proves a bare name that
// isn't on PATH at all is a hard error — never a sentinel value that lets the
// run proceed as if resolution had quietly succeeded.
func TestSol3ResolvePathFailsClosedWhenUnresolvable(t *testing.T) {
	t.Setenv("PATH", t.TempDir()) // empty: nothing named "pi" is findable
	agent, err := New("pi")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ResolvePath(agent); err == nil {
		t.Fatal("expected ResolvePath to fail closed for an unresolvable bare name, got nil error")
	}
}

// TestSol3RunCLIFailsClosedWhenResolvedBinDeletedBeforeLaunch is corpus #2's
// "deleted binary between resolution and launch fails closed" case, and also
// proves the required-behavior half of Finding 5 that isn't about replay:
// launch must use the already-resolved canonical path and never perform its
// own independent PATH lookup. binDirA is resolved first and listed first on
// PATH; binDirB also has a same-named "pi" executable further down PATH. If
// runCLI silently fell back to a fresh bare-name lookup after binDirA/pi is
// deleted, it would silently launch binDirB/pi instead — a different binary
// than the one resolution actually verified. The fix must fail closed
// instead.
func TestSol3RunCLIFailsClosedWhenResolvedBinDeletedBeforeLaunch(t *testing.T) {
	binDirA := t.TempDir()
	binDirB := t.TempDir()
	pathA := filepath.Join(binDirA, "pi")
	pathB := filepath.Join(binDirB, "pi")
	writeExecutable(t, pathA, "echo from-a\n")
	writeExecutable(t, pathB, "echo from-b\n")
	t.Setenv("PATH", binDirA+string(os.PathListSeparator)+binDirB+string(os.PathListSeparator)+os.Getenv("PATH"))

	agent, err := New("pi")
	if err != nil {
		t.Fatal(err)
	}
	res, err := ResolvePath(agent)
	if err != nil {
		t.Fatal(err)
	}
	if res.CanonicalPath != pathA {
		t.Fatalf("resolution picked %q, want the first-on-PATH %q", res.CanonicalPath, pathA)
	}

	// Delete the resolved binary. binDirB/pi (a different program) is still
	// reachable via a fresh bare-name PATH lookup — the fix must not fall
	// back to it.
	if err := os.Remove(pathA); err != nil {
		t.Fatal(err)
	}

	_, err = runCLI(context.Background(), runCLIRequest{
		bin: "pi", resolvedBin: res.CanonicalPath,
		workdir: t.TempDir(), transcript: filepath.Join(t.TempDir(), "t.jsonl"),
		timeout: 5 * time.Second, prompt: "do the thing",
	})
	if err == nil {
		t.Fatal("expected runCLI to fail closed when the resolved binary was deleted before launch, got nil error")
	}
}

// TestSol3RunCLIUsesResolvedPathNotFreshPATHLookup is
// TestSol3RunCLIFailsClosedWhenResolvedBinDeletedBeforeLaunch's positive
// counterpart: PATH order changes between resolution and launch (binDirB now
// comes first), but the host launch must still run the exact binary
// resolution picked, not whatever a fresh bare-name lookup would find now.
// No over-blocking: a valid resolution still launches successfully.
func TestSol3RunCLIUsesResolvedPathNotFreshPATHLookup(t *testing.T) {
	binDirA := t.TempDir()
	binDirB := t.TempDir()
	pathA := filepath.Join(binDirA, "pi")
	pathB := filepath.Join(binDirB, "pi")
	writeExecutable(t, pathA, "printf 'launched=A\\n'\nprintf '{\"type\":\"result\",\"total_cost_usd\":0.1}\\n'\n")
	writeExecutable(t, pathB, "printf 'launched=B\\n'\nprintf '{\"type\":\"result\",\"total_cost_usd\":0.1}\\n'\n")
	t.Setenv("PATH", binDirA+string(os.PathListSeparator)+binDirB+string(os.PathListSeparator)+os.Getenv("PATH"))

	agent, err := New("pi")
	if err != nil {
		t.Fatal(err)
	}
	res, err := ResolvePath(agent)
	if err != nil {
		t.Fatal(err)
	}
	if res.CanonicalPath != pathA {
		t.Fatalf("resolution picked %q, want the first-on-PATH %q", res.CanonicalPath, pathA)
	}

	// Reorder PATH so a fresh bare-name lookup of "pi" would now find B
	// first. The resolved record must still win.
	t.Setenv("PATH", binDirB+string(os.PathListSeparator)+binDirA+string(os.PathListSeparator)+os.Getenv("PATH"))

	transcript := filepath.Join(t.TempDir(), "t.jsonl")
	if _, err := runCLI(context.Background(), runCLIRequest{
		bin: "pi", resolvedBin: res.CanonicalPath,
		workdir: t.TempDir(), transcript: transcript,
		timeout: 5 * time.Second, prompt: "do the thing",
	}); err != nil {
		t.Fatalf("runCLI: %v", err)
	}
	out, err := os.ReadFile(transcript)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "launched=A") {
		t.Fatalf("expected the resolved binary (A) to launch, transcript: %s", out)
	}
	if strings.Contains(string(out), "launched=B") {
		t.Fatalf("launch re-resolved through PATH instead of using the already-resolved binary: %s", out)
	}
}
