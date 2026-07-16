//go:build redteam

package redteam

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/cousingary/governator/internal/contracts"
	"github.com/cousingary/governator/internal/enforce"
	govruntime "github.com/cousingary/governator/internal/runtime"
)

func v7ForceUnsupported(t *testing.T) {
	t.Helper()
	enforce.ForceUnsupported = true
	t.Cleanup(func() { enforce.ForceUnsupported = false })
}

func runV7S2AllowError(t *testing.T, home, bin string, c contracts.Contract) (govruntime.RunRecord, error) {
	t.Helper()
	t.Setenv("GOV_HOME", home)
	t.Setenv("GOV_CLAUDE_BIN", bin)
	return govruntime.New().RunWithAutoRepair(context.Background(), c)
}

func TestV7Case1LowRiskEffectfulExternalWriteRejectedWithoutContainment(t *testing.T) {
	v7ForceUnsupported(t)
	root := fixtureRepo(t)
	hostEscape := filepath.Join(t.TempDir(), "outside-governator-case1.txt")
	bin := fakeBackend(t, "printf escaped > "+hostEscape+" 2>/dev/null || true\n"+standardBackendBody(""))
	c := baseContract(root)
	c.RiskClass = "low"
	c.Forbidden = contracts.Forbidden{Paths: []string{".git/**"}, Commands: []string{"rm -rf"}}
	rec, _ := runV7S2AllowError(t, t.TempDir(), bin, c)
	if _, err := os.Stat(hostEscape); err == nil {
		t.Fatalf("low-risk effectful backend launched and wrote outside workspace: %s", hostEscape)
	}
	if rec.Status == "APPROVED" {
		t.Fatal("low-risk effectful run approved without required host containment")
	}
}

func TestV7Case2LegacyEffectfulExternalWriteRejectedWithoutContainment(t *testing.T) {
	v7ForceUnsupported(t)
	root := fixtureRepo(t)
	hostEscape := filepath.Join(t.TempDir(), "outside-governator-case2.txt")
	bin := fakeBackend(t, "printf escaped > "+hostEscape+" 2>/dev/null || true\n"+standardBackendBody(""))
	c := baseContract(root)
	c.RiskClass = ""
	c.Forbidden = contracts.Forbidden{Paths: []string{".git/**"}, Commands: []string{"rm -rf"}}
	rec, _ := runV7S2AllowError(t, t.TempDir(), bin, c)
	if _, err := os.Stat(hostEscape); err == nil {
		t.Fatalf("legacy effectful backend launched and wrote outside workspace: %s", hostEscape)
	}
	if rec.Status == "APPROVED" {
		t.Fatal("legacy effectful run approved without required host containment")
	}
}

func TestV7Case3EmptyRiskNoNetworkRejectedWithoutContainment(t *testing.T) {
	v7ForceUnsupported(t)
	root := fixtureRepo(t)
	bin := fakeBackend(t, standardBackendBody(""))
	c := baseContract(root)
	c.RiskClass = ""
	rec, _ := runV7S2AllowError(t, t.TempDir(), bin, c)
	if rec.Status == "APPROVED" {
		t.Fatal("empty-risk explicit no-network run approved without external enforcement")
	}
}
