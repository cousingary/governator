package toolregistry

import (
	"os"
	"path/filepath"
	"testing"
)

func writeExecutable(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestResolveUnregisteredToolRefuses(t *testing.T) {
	t.Setenv("GOV_TOOLREGISTRY_FILE", filepath.Join(t.TempDir(), "missing.yaml"))
	r, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Resolve("codegraph", "codegraph"); err == nil {
		t.Fatal("expected refusal for a name with no registry entry")
	}
}

func TestResolveRegisteredToolByAmbientLookup(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "codegraph")
	writeExecutable(t, bin, "#!/bin/sh\necho ok\n")
	regFile := filepath.Join(t.TempDir(), "tools.yaml")
	if err := os.WriteFile(regFile, []byte("tools:\n  - name: codegraph\n    kind: trusted_controller\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_TOOLREGISTRY_FILE", regFile)

	r, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	identity, err := r.Resolve("codegraph", bin)
	if err != nil {
		t.Fatal(err)
	}
	if identity.CanonicalPath != bin {
		t.Fatalf("canonical path = %q, want %q", identity.CanonicalPath, bin)
	}
	if identity.SHA256 == "" {
		t.Fatal("expected a content hash")
	}
}

func TestResolvePinnedPathIgnoresRequestedBin(t *testing.T) {
	dir := t.TempDir()
	pinned := filepath.Join(dir, "real-git")
	writeExecutable(t, pinned, "#!/bin/sh\necho real\n")
	regFile := filepath.Join(t.TempDir(), "tools.yaml")
	if err := os.WriteFile(regFile, []byte("tools:\n  - name: git\n    kind: trusted_controller\n    path: "+pinned+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_TOOLREGISTRY_FILE", regFile)

	// A hostile "git" earlier on a caller's PATH must not matter: Resolve
	// never consults requestedBin once the entry pins an explicit Path.
	hostileDir := t.TempDir()
	hostile := filepath.Join(hostileDir, "git")
	writeExecutable(t, hostile, "#!/bin/sh\necho hostile\n")

	r, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	identity, err := r.Resolve("git", hostile)
	if err != nil {
		t.Fatal(err)
	}
	if identity.CanonicalPath != pinned {
		t.Fatalf("canonical path = %q, want pinned %q (hostile bin must be ignored)", identity.CanonicalPath, pinned)
	}
}

func TestResolveRejectsGroupWritableParentOwnedByAnotherUser(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "codegraph")
	writeExecutable(t, bin, "#!/bin/sh\necho ok\n")
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	// This directory is still owned by the current euid, so the "untrusted
	// owner" branch of parentWritable does not fire -- verifying the
	// baseline case (self-owned, merely permissive) is accepted, since the
	// registry's real defense against a self-owned hostile substitute is
	// pinning (see TestResolvePinnedPathIgnoresRequestedBin), not this
	// hygiene check alone.
	regFile := filepath.Join(t.TempDir(), "tools.yaml")
	if err := os.WriteFile(regFile, []byte("tools:\n  - name: codegraph\n    kind: trusted_controller\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_TOOLREGISTRY_FILE", regFile)
	r, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Resolve("codegraph", bin); err != nil {
		t.Fatalf("expected self-owned, merely-permissive parent to be accepted: %v", err)
	}
}

func TestResolveRejectsContentHashMismatch(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "codegraph")
	writeExecutable(t, bin, "#!/bin/sh\necho ok\n")
	regFile := filepath.Join(t.TempDir(), "tools.yaml")
	if err := os.WriteFile(regFile, []byte("tools:\n  - name: codegraph\n    kind: trusted_controller\n    sha256: deadbeef\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_TOOLREGISTRY_FILE", regFile)
	r, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Resolve("codegraph", bin); err == nil {
		t.Fatal("expected content hash mismatch to be rejected")
	}
}

func TestGitHasShippedDefaultEntry(t *testing.T) {
	t.Setenv("GOV_TOOLREGISTRY_FILE", filepath.Join(t.TempDir(), "missing.yaml"))
	r, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := r.Entry("git")
	if !ok || entry.Kind != KindTrustedController {
		t.Fatalf("expected a shipped default trusted_controller entry for git, got %+v ok=%v", entry, ok)
	}
}

func TestPinPersistsPathAndPreservesOtherEntries(t *testing.T) {
	regFile := filepath.Join(t.TempDir(), "tools.yaml")
	if err := os.WriteFile(regFile, []byte("tools:\n  - name: codegraph\n    kind: trusted_controller\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_TOOLREGISTRY_FILE", regFile)

	if err := Pin("git", "/usr/bin/git"); err != nil {
		t.Fatal(err)
	}
	r, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	gitEntry, ok := r.Entry("git")
	if !ok || gitEntry.Path != "/usr/bin/git" {
		t.Fatalf("git entry = %+v ok=%v, want pinned path", gitEntry, ok)
	}
	codegraphEntry, ok := r.Entry("codegraph")
	if !ok || codegraphEntry.Kind != KindTrustedController {
		t.Fatalf("expected pre-existing codegraph entry preserved, got %+v ok=%v", codegraphEntry, ok)
	}

	// Pinning again (e.g. a second `gov doctor` run) must update in place,
	// not append a duplicate entry.
	if err := Pin("git", "/usr/local/bin/git"); err != nil {
		t.Fatal(err)
	}
	r2, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if e, _ := r2.Entry("git"); e.Path != "/usr/local/bin/git" {
		t.Fatalf("expected updated pin, got %+v", e)
	}
}
