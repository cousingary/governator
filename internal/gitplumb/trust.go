package gitplumb

import (
	"fmt"

	"github.com/cousingary/governator/internal/toolregistry"
)

// TrustedGitPath resolves and verifies git through the trusted-tool
// registry (Sol report attack 10: a hostile git prepended to PATH after
// Governator has already established trust in the real one must not be
// able to redirect a controller invocation). Resolved fresh on every call
// rather than cached process-wide: once an operator has pinned git's path
// (toolregistry.Pin, called by `gov doctor` on first successful
// resolution), every resolution reads that same pinned file regardless of
// the calling process's current PATH, so a fresh lookup each time costs a
// stat+hash, not a fresh trust decision. Before a pin exists, this is a
// plain ambient PATH lookup plus hygiene checks -- no different from
// today's behavior except that it is now verified, not merely resolved.
func TrustedGitPath() (string, error) {
	registry, err := toolregistry.Load()
	if err != nil {
		return "", fmt.Errorf("gitplumb: load trusted-tool registry: %w", err)
	}
	identity, err := registry.Resolve("git", "git")
	if err != nil {
		return "", fmt.Errorf("gitplumb: %w", err)
	}
	return identity.CanonicalPath, nil
}
