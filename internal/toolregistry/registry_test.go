package toolregistry

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func secureTempDir(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(home, ".gov-toolregistry-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func writeExecutable(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestResolveUnregisteredToolRefuses(t *testing.T) {
	t.Setenv("GOV_TOOLREGISTRY_FILE", filepath.Join(secureTempDir(t), "missing.yaml"))
	r, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Resolve("codegraph", "codegraph"); err == nil {
		t.Fatal("expected refusal for a name with no registry entry")
	}
}

func TestResolveRegisteredToolWithoutEnrollmentRefusesAmbientLookup(t *testing.T) {
	dir := secureTempDir(t)
	bin := filepath.Join(dir, "codegraph")
	writeExecutable(t, bin, "#!/bin/sh\necho ok\n")
	regFile := filepath.Join(secureTempDir(t), "tools.yaml")
	if err := os.WriteFile(regFile, []byte("tools:\n  - name: codegraph\n    kind: trusted_controller\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_TOOLREGISTRY_FILE", regFile)

	r, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Resolve("codegraph", bin); err == nil {
		t.Fatal("expected registered-but-unenrolled tool to refuse ambient lookup")
	}
}

func TestEnrollPersistsFullIdentityAndResolveIgnoresRequestedBin(t *testing.T) {
	dir := secureTempDir(t)
	pinned := filepath.Join(dir, "real-git")
	writeExecutable(t, pinned, "#!/bin/sh\necho real\n")
	regFile := filepath.Join(secureTempDir(t), "tools.yaml")
	t.Setenv("GOV_TOOLREGISTRY_FILE", regFile)
	if _, err := Enroll("git", pinned); err != nil {
		t.Fatal(err)
	}

	hostileDir := secureTempDir(t)
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
		t.Fatalf("canonical path = %q, want enrolled %q", identity.CanonicalPath, pinned)
	}
	entry, ok := r.Entry("git")
	if !ok || entry.SHA256 == "" || entry.Mode == "" || entry.Inode == 0 {
		t.Fatalf("enrolled entry missing full identity: %+v ok=%v", entry, ok)
	}
}

func TestResolveRejectsPermissiveExecutableAncestor(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "codegraph")
	writeExecutable(t, bin, "#!/bin/sh\necho ok\n")
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	regFile := filepath.Join(secureTempDir(t), "tools.yaml")
	t.Setenv("GOV_TOOLREGISTRY_FILE", regFile)
	if _, err := Enroll("codegraph", bin); err == nil {
		t.Fatal("expected enrollment below group/world-writable ancestor to be rejected")
	}
}

func TestResolveRejectsContentHashMismatch(t *testing.T) {
	dir := secureTempDir(t)
	bin := filepath.Join(dir, "codegraph")
	writeExecutable(t, bin, "#!/bin/sh\necho ok\n")
	regFile := filepath.Join(secureTempDir(t), "tools.yaml")
	if err := os.WriteFile(regFile, []byte("tools:\n  - name: codegraph\n    kind: trusted_controller\n    path: "+bin+"\n    sha256: 0000000000000000000000000000000000000000000000000000000000000000\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_TOOLREGISTRY_FILE", regFile)
	r, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Resolve("codegraph", ""); err == nil {
		t.Fatal("expected content hash mismatch to be rejected")
	}
}

func TestGitHasShippedDefaultEntryButNoExecutableIdentity(t *testing.T) {
	t.Setenv("GOV_TOOLREGISTRY_FILE", filepath.Join(secureTempDir(t), "missing.yaml"))
	r, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := r.Entry("git")
	if !ok || entry.Kind != KindTrustedController {
		t.Fatalf("expected a shipped default trusted_controller entry for git, got %+v ok=%v", entry, ok)
	}
	if _, err := r.Resolve("git", "git"); err == nil {
		t.Fatal("fresh default git entry must not resolve without administrative enrollment")
	}
}

func TestPinPersistsIdentityAndPreservesOtherEntries(t *testing.T) {
	regFile := filepath.Join(secureTempDir(t), "tools.yaml")
	if err := os.WriteFile(regFile, []byte("tools:\n  - name: codegraph\n    kind: trusted_controller\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_TOOLREGISTRY_FILE", regFile)
	toolDir := secureTempDir(t)
	git1 := filepath.Join(toolDir, "git1")
	git2 := filepath.Join(toolDir, "git2")
	writeExecutable(t, git1, "#!/bin/sh\necho git1\n")
	writeExecutable(t, git2, "#!/bin/sh\necho git2\n")

	if err := Pin("git", git1); err != nil {
		t.Fatal(err)
	}
	r, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	gitEntry, ok := r.Entry("git")
	if !ok || gitEntry.Path != git1 || gitEntry.SHA256 == "" || gitEntry.Inode == 0 {
		t.Fatalf("git entry = %+v ok=%v, want full enrolled identity", gitEntry, ok)
	}
	codegraphEntry, ok := r.Entry("codegraph")
	if !ok || codegraphEntry.Kind != KindTrustedController {
		t.Fatalf("expected pre-existing codegraph entry preserved, got %+v ok=%v", codegraphEntry, ok)
	}

	if err := Pin("git", git2); err != nil {
		t.Fatal(err)
	}
	r2, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if e, _ := r2.Entry("git"); e.Path != git2 || e.SHA256 == gitEntry.SHA256 {
		t.Fatalf("expected rotated full identity, got %+v", e)
	}
}

func TestResolvePreservesEnrolledKind(t *testing.T) {
	dir := secureTempDir(t)
	bin := filepath.Join(dir, "helper")
	writeExecutable(t, bin, "#!/bin/sh\nexit 0\n")
	regFile := filepath.Join(secureTempDir(t), "tools.yaml")
	t.Setenv("GOV_TOOLREGISTRY_FILE", regFile)
	if err := os.WriteFile(regFile, []byte("tools:\n  - name: helper\n    kind: sandboxed_helper\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Enroll("helper", bin); err != nil {
		t.Fatal(err)
	}
	r, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	id, err := r.Resolve("helper", "")
	if err != nil {
		t.Fatal(err)
	}
	if id.Kind != KindSandboxedHelper {
		t.Fatalf("kind = %q, want %q", id.Kind, KindSandboxedHelper)
	}
}

func TestRotatePreservesAllowedEnv(t *testing.T) {
	dir := secureTempDir(t)
	first, second := filepath.Join(dir, "first"), filepath.Join(dir, "second")
	writeExecutable(t, first, "#!/bin/sh\nexit 0\n")
	writeExecutable(t, second, "#!/bin/sh\nexit 0\n")
	regFile := filepath.Join(secureTempDir(t), "tools.yaml")
	t.Setenv("GOV_TOOLREGISTRY_FILE", regFile)
	if err := os.WriteFile(regFile, []byte("tools:\n  - name: helper\n    kind: sandboxed_helper\n    allowed_env: [LANG, LC_ALL]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Enroll("helper", first); err != nil {
		t.Fatal(err)
	}
	if _, err := Rotate("helper", second); err != nil {
		t.Fatal(err)
	}
	r, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	e, _ := r.Entry("helper")
	if len(e.AllowedEnv) != 2 || e.AllowedEnv[0] != "LANG" || e.AllowedEnv[1] != "LC_ALL" {
		t.Fatalf("allowed_env lost on rotation: %#v", e.AllowedEnv)
	}
}

func TestLoadRejectsSymlinkRegistry(t *testing.T) {
	dir := secureTempDir(t)
	real := filepath.Join(dir, "real.yaml")
	link := filepath.Join(dir, "tools.yaml")
	if err := os.WriteFile(real, []byte("tools: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_TOOLREGISTRY_FILE", link)
	if _, err := Load(); err == nil {
		t.Fatal("expected symlink registry rejection")
	}
}

func copyExecutable(t *testing.T, src, dst string) {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, data, 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestResolvedHandleExecutesVerifiedObjectAfterPathReplacement(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires /proc/self/fd")
	}
	dir := secureTempDir(t)
	bin, replacement := filepath.Join(dir, "tool"), filepath.Join(dir, "replacement")
	copyExecutable(t, "/bin/echo", bin)
	copyExecutable(t, "/bin/false", replacement)
	regFile := filepath.Join(secureTempDir(t), "tools.yaml")
	t.Setenv("GOV_TOOLREGISTRY_FILE", regFile)
	if _, err := Enroll("git", bin); err != nil {
		t.Fatal(err)
	}
	r, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	h, err := r.ResolveHandle("git", "", KindTrustedController)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if err := os.Rename(replacement, bin); err != nil {
		t.Fatal(err)
	}
	cmd, err := h.Command(context.Background(), "verified")
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("sealed launch: %v", err)
	}
	if strings.TrimSpace(string(out)) != "verified" {
		t.Fatalf("executed replacement, output=%q", out)
	}
}

func TestResolveHandleEnforcesKindAtCallSite(t *testing.T) {
	dir := secureTempDir(t)
	bin := filepath.Join(dir, "helper")
	copyExecutable(t, "/bin/true", bin)
	regFile := filepath.Join(secureTempDir(t), "tools.yaml")
	t.Setenv("GOV_TOOLREGISTRY_FILE", regFile)
	if err := os.WriteFile(regFile, []byte("tools:\n  - name: helper\n    kind: sandboxed_helper\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Enroll("helper", bin); err != nil {
		t.Fatal(err)
	}
	r, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.ResolveHandle("helper", "", KindTrustedController); err == nil {
		t.Fatal("expected kind mismatch rejection")
	}
}
