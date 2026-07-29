//go:build integration

package contextgraph

import (
	"os"
	"testing"

	"github.com/cousingary/governator/internal/integrationharness"
)

// Sol14 P0-2 (rc7 Session 5): the integration-tier TestMain for the
// context-graph package. The three context-graph stage tests
// (TestInspectCodeGraphStatus, TestPrepareBuildsFingerprintAndQueries,
// TestPrepareAutoDegradesOnProviderFailure) skip in the unit tier via
// graph_test.go's requireExternalSandbox whenever enforce.SelfExeOverride
// is empty -- the same silent-skip defect the Assayer tier had. This
// TestMain wires up the real sandbox (integrationharness.Setup) so those
// tests RUN -- not skip -- in the integration tier, and fail-closes the
// package when enforcement cannot be established. The release integration
// gate's zero-skip rule then makes any residual skip release-blocking.
//
// This package records no Assayer identity (it exercises Governator's own
// context-graph path, not the Assayer bridge); assayerSource is "n/a
// (contextgraph)" so the evidence honestly states that rather than leaving
// the field ambiguous. S9 moves these three tests into their own exact-name
// integration manifest alongside the Assayer one.
func TestMain(m *testing.M) {
	os.Exit(integrationharness.Setup(m.Run, "contextgraph", "n/a (contextgraph)", ""))
}
