//go:build redteam

package redteam

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cousingary/governator/internal/toolregistry"
)

func v7S4SecureDir(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(home, ".gov-v7-s4-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func v7S4Copy(t *testing.T, src, dst string) {
	t.Helper()
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, b, 0o755); err != nil {
		t.Fatal(err)
	}
}

func v7S4ToolSwap(t *testing.T, name string) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("conditional: sealed fd launch requires Linux")
	}
	dir := v7S4SecureDir(t)
	bin, hostile := filepath.Join(dir, name), filepath.Join(dir, "hostile")
	v7S4Copy(t, "/bin/echo", bin)
	v7S4Copy(t, "/bin/false", hostile)
	regDir := v7S4SecureDir(t)
	regFile := filepath.Join(regDir, "tools.yaml")
	t.Setenv("GOV_TOOLREGISTRY_FILE", regFile)
	if _, err := toolregistry.Enroll(name, bin); err != nil {
		t.Fatal(err)
	}
	reg, err := toolregistry.Load()
	if err != nil {
		t.Fatal(err)
	}
	h, err := reg.ResolveHandle(name, "", toolregistry.KindTrustedController)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if err := os.Rename(hostile, bin); err != nil {
		t.Fatal(err)
	}
	cmd, err := h.Command(context.Background(), "sealed-object")
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("replacement executable ran: %v", err)
	}
	if strings.TrimSpace(string(out)) != "sealed-object" {
		t.Fatalf("replacement altered executed bytes: %q", out)
	}
}

func TestV7Case13BashReplacementCannotChangeExecutedBytes(t *testing.T)   { v7S4ToolSwap(t, "bash") }
func TestV7Case14GitReplacementCannotChangeExecutedBytes(t *testing.T)    { v7S4ToolSwap(t, "git") }
func TestV7Case15PythonReplacementCannotChangeExecutedBytes(t *testing.T) { v7S4ToolSwap(t, "python3") }

func TestV7Case16GovernatorSelfIdentityUsesRunningObject(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	identity, err := os.ReadFile(filepath.Join(root, "internal", "runtime", "identity.go"))
	if err != nil {
		t.Fatal(err)
	}
	enforcement, err := os.ReadFile(filepath.Join(root, "internal", "enforce", "enforce.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(identity), `hashFileContent("/proc/self/exe")`) {
		t.Fatal("self identity reopens a mutable executable pathname")
	}
	if !strings.Contains(string(enforcement), `return "/proc/self/exe", nil`) {
		t.Fatal("sandbox-helper re-exec does not use the running executable object")
	}
}
