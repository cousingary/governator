package main

import "testing"

// Capability attestation is release tooling and must bypass the normal job
// config guard, while the pre-existing `gov attest <backend>` path retains it.
func TestCapabilityAttestDispatchesWithoutConfig(t *testing.T) {
	if got := run([]string{"attest", "capability"}); got != 2 {
		t.Fatalf("gov attest capability without required arguments returned %d, want usage exit 2; it may have been routed through the backend-attestation path", got)
	}
}
