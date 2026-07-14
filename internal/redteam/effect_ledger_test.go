//go:build redteam

package redteam

import (
	"testing"

	"github.com/cousingary/governator/internal/agents"
)

// TestAttack27BackendExecutableWithUntrustedWritableParentIsQuarantined is
// the post-v4 hardening plan's Session 3 (item D) redteam attack: the
// kernel-observed effect ledger (S9, internal/observability/effects.go)
// records an executable_launch row for every run -- the resolved backend
// handle's canonical path, hash, and identity -- but nothing ever compared
// it against anything until this session. agents.ResolveHandle has computed
// ParentWritable (Sol P0-6's "parent-directory trust state": is any
// directory in the executable's ancestry writable by a party other than its
// owner, where the owner is neither this process nor root) since before
// this session, but the value was dead: nothing read it. A backend binary
// reachable only because an untrusted party could rewrite something
// upstream of it in its own directory chain sailed through unexamined.
//
// effectLedgerViolations (internal/runtime/runtime.go) now gates on it: an
// executable_launch effect with ParentWritable=true quarantines the run.
//
// A real untrusted-writable ancestor directory needs a second real uid,
// which this unprivileged test process cannot construct (see
// agents.ForceParentWritable's doc comment) -- so this attack forces the
// exact condition parentTrustState would have detected on a genuinely
// hostile host, and drives a completely ordinary, otherwise-compliant
// governed run through the real end-to-end engine to prove the new gate
// actually reaches quarantine rather than just existing as dead code a
// second time.
func TestAttack27BackendExecutableWithUntrustedWritableParentIsQuarantined(t *testing.T) {
	agents.ForceParentWritable = true
	defer func() { agents.ForceParentWritable = false }()

	root := fixtureRepo(t)
	c := baseContract(root)
	bin := fakeBackend(t, standardBackendBody(""))

	rec := runGoverned(t, t.TempDir(), bin, c)
	if rec.Status != "QUARANTINED" {
		t.Fatalf("expected QUARANTINED (backend executable's directory ancestry reported untrusted-writable), got status=%s message=%s", rec.Status, rec.Message)
	}
}
