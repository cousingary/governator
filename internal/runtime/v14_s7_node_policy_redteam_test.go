//go:build redteam

package runtime

import (
	"strings"
	"testing"

	"github.com/cousingary/governator/internal/contracts"
)

func TestV14Case335LocalNodeBackendCannotObtainProductionApproval(t *testing.T) {
	if reason := nodeBackendApprovalViolation("closure-sha256", contracts.Contract{Runner: "local"}); reason == "" {
		t.Fatal("local Node backend was eligible for production approval")
	}
}

func TestV14Case336DigestPinnedContainerizedNodeBackendCanApprove(t *testing.T) {
	c := contracts.Contract{Runner: "docker", Docker: &contracts.DockerRunnerConfig{Image: "node@sha256:" + strings.Repeat("a", 64)}}
	if reason := nodeBackendApprovalViolation("closure-sha256", c); reason != "" {
		t.Fatalf("digest-pinned containerized Node backend was blocked by local-only policy: %s", reason)
	}
}
