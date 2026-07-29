//go:build !integration

package assay

import (
	"os"
	"testing"

	"github.com/cousingary/governator/internal/enforce"
)

// TestMain forces enforce.Supported() false for the UNIT test tier of this
// package only. This suite verifies Evaluate's wire protocol (JSON parsing,
// timeout, sha-mismatch, nonzero-exit handling) against ad hoc stub `cli.py`
// scripts in t.TempDir() -- it was never meant to exercise real Landlock
// containment, which needs a real `gov` binary wired up via
// enforce.SelfExeOverride the way internal/redteam's corpus does (that
// corpus, not this package, owns cases 11/12's actual containment
// assertions). Without this, a host that genuinely has Landlock/unshare
// (this sandbox does) makes Evaluate's now-real enforce.Plan active, which
// then requires `gov __sandbox_exec` -- unavailable from a plain `go test`
// binary -- and every stub-based test here fails for an environmental
// reason unrelated to what it actually checks.
//
// Sol14 P0-2 (rc7 Session 5): this file carries `//go:build !integration` so
// it CANNOT compile into the integration tier. The prior unconstrained
// TestMain compiled into `go test -tags integration` too, unconditionally
// forced enforcement unsupported, and made the sole integration-tagged test
// skip behind a package-level `ok` line -- a release-claim defect, not a
// code bug. The integration tier now gets its own TestMain in
// assay_integration_testmain_test.go that wires up a real sandbox and
// fail-closes (never skips) when enforcement cannot be established.
func TestMain(m *testing.M) {
	enforce.ForceUnsupported = true
	os.Exit(m.Run())
}
