//go:build integration

package assay

import (
	"os"
	"testing"

	"github.com/cousingary/governator/internal/integrationharness"
)

// Sol14 P0-2 (rc7 Session 5): the integration-tier TestMain. The unit-tier
// TestMain (assay_unit_testmain_test.go) is constrained to //go:build
// !integration precisely so it cannot compile here and force enforcement
// unsupported. This TestMain instead WIRES UP REAL external enforcement via
// integrationharness.Setup: the exact rc-candidate `gov` binary is pointed
// at through enforce.SelfExeOverride, the containment primitives are
// enrolled, and the tier FAILS -- never skips -- when strong external
// enforcement cannot be established. See internal/integrationharness for
// the fail-closed policy and the evidence record both integration packages
// share.
//
// What this closes: the prior unconstrained TestMain compiled into the
// integration tier, set enforce.ForceUnsupported=true, and the sole
// integration-tagged test hit `if !enforce.Supported() { t.Skip(...) }` and
// always skipped -- hidden behind `ok ... 0.026s` because the release
// command used neither -v nor -json. Nothing ever exercised real external
// enforcement, Governator's sandbox helper, the Go->Python Assayer bridge,
// or real Assayer pass/fail behavior. Now it all runs, and the release
// gate (scripts/release.sh -> `gov integration-gate verify`) parses the
// -json stream to require every expected test ran with zero skips.
func TestMain(m *testing.M) {
	identity, err := integrationharness.ResolveAssayerIdentity(
		os.Getenv("ASSAYER_REPO"), os.Getenv("GOV_INTEGRATION_ASSAYER_COMMIT"),
	)
	os.Exit(integrationharness.Setup(m.Run, "assay", identity, err))
}
