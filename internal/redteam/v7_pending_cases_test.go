//go:build redteam

package redteam

import "testing"

// Scaffolding reserved by Session 7 (agents/governator-sol-upgrade7-plan.md)
// for corpus cases owned by S1, S5, S6, and S8, none of which had landed a
// black-box test before S7 ran — see the S0/S1/S5/S6 findings entry in
// agents/governator-sol-upgrade7-findings.md for why this scaffold exists and
// who owns replacing each stub. Every name here is reserved in
// internal/redteam/manifest.yaml; the identity-based release gate keys off
// these exact strings, so replace a stub's *body* when you implement the
// case — never rename the function.
//
// Per the plan's Session 0 rule ("Every not-yet-fixed attack: t.Skip(...).
// The skip count is the burn-down."), these are placeholders, not fixes: no
// hostile fixture, no assertion, just a named, compiling test that reports
// itself as expected-fail until its owning session lands. A required corpus
// case skipping here still blocks the identity-based release gate — only
// case 28/36-style genuinely-conditional cases (recorded with a real
// allowed_skip predicate in manifest.yaml) do not.

// --- Session 1: StageExecutor, one launch path for every external stage ---

func TestV7Case5ValidatorExternalWriteBlockedOrContained(t *testing.T) {
	t.Skip("expected-fail until S1: validator external write must route through StageExecutor containment")
}

func TestV7Case6ValidatorNetworkExfiltrationBlockedOrContained(t *testing.T) {
	t.Skip("expected-fail until S1: validator network exfiltration must route through StageExecutor containment")
}

func TestV7Case7CleanupValidatorExternalWriteBlockedOrContained(t *testing.T) {
	t.Skip("expected-fail until S1: cleanup validator external write must route through StageExecutor containment")
}

func TestV7Case8CleanupValidatorDetachedDescendantExtinctionFailureBlocksApproval(t *testing.T) {
	t.Skip("expected-fail until S1: optional-cleanup descendant-extinction failure must block approval regardless of cleanup exit code")
}

func TestV7Case9GraphProviderExternalWriteBlockedOrContained(t *testing.T) {
	t.Skip("expected-fail until S1: graph provider external write must route through StageExecutor containment")
}

func TestV7Case10GraphProviderNetworkExfiltrationBlockedOrContained(t *testing.T) {
	t.Skip("expected-fail until S1: graph provider network exfiltration must route through StageExecutor containment")
}

func TestV7Case11AssayerExternalWriteBlockedOrContained(t *testing.T) {
	t.Skip("expected-fail until S1: Assayer external write must route through StageExecutor containment")
}

func TestV7Case12AssayerNetworkExfiltrationBlockedOrContained(t *testing.T) {
	t.Skip("expected-fail until S1: Assayer network exfiltration must route through StageExecutor containment")
}

// --- Session 5: narrow Landlock, exact read closure, fail-closed ABI ---

func TestV7Case4LowRiskHostSecretUnreadableUnderNarrowLandlock(t *testing.T) {
	t.Skip("expected-fail until S5: undeclared host secret must be unreadable under the exact-read-closure Landlock policy")
}

// --- Session 6: ExecutionIdentityV2 from one immutable transaction snapshot ---

func TestV7Case17ValidatorInterpreterChangeInvalidatesReplay(t *testing.T) {
	t.Skip("expected-fail until S6: resolved validator interpreter must be bound into strict replay identity")
}

func TestV7Case18ValidatorScriptBytesChangeInvalidatesReplay(t *testing.T) {
	t.Skip("expected-fail until S6: validator script bytes must be bound into strict replay identity")
}

func TestV7Case21RTKMinimalismAnnotationChangeInvalidatesReplay(t *testing.T) {
	t.Skip("expected-fail until S6: RTK/minimalism annotations are model-visible input and must invalidate replay on change")
}

func TestV7Case22GraphSnapshotChangeBetweenInspectionAndPrepInvalidatesReplay(t *testing.T) {
	t.Skip("expected-fail until S6: the graph inspected pre-replay and the graph prepared at execution must be the same frozen snapshot")
}

func TestV7Case23ConsumedArtifactChangeBetweenHashAndStagingInvalidatesReplay(t *testing.T) {
	t.Skip("expected-fail until S6: consumed artifacts must be opened/sealed at snapshot time, not reopened by path at staging")
}

func TestV7Case24ProtectedManifestChangeBetweenLoadAndHashInvalidatesReplay(t *testing.T) {
	t.Skip("expected-fail until S6: the protected manifest frozen for enforcement and the one hashed for identity must be the same read")
}

func TestV7Case25AssayerCommitChangeInvalidatesReplay(t *testing.T) {
	t.Skip("expected-fail until S6: the Assayer commit identity must be bound into strict replay identity")
}

func TestV7Case26AssayerProfileChangeInvalidatesReplay(t *testing.T) {
	t.Skip("expected-fail until S6: the Assayer profile bytes must be bound into strict replay identity")
}

func TestV7Case27GitIdentityChangeInvalidatesReplay(t *testing.T) {
	t.Skip("expected-fail until S6: the resolved Git executable identity must be bound into strict replay identity")
}

func TestV7Case28BashIdentityChangeInvalidatesReplay(t *testing.T) {
	t.Skip("expected-fail until S6: the resolved Bash executable identity must be bound into strict replay identity")
}

func TestV7Case29ModelVisibleCanaryChangeInvalidatesReplay(t *testing.T) {
	t.Skip("expected-fail until S6: every token shown to the model, including the per-run canary, must be represented in strict replay identity")
}

func TestV7Case30UnknownRequiredIdentityDisablesStrictReplay(t *testing.T) {
	t.Skip("expected-fail until S6: an \"unknown\" sentinel for a required identity must disable strict replay, never compare equal to another unknown")
}

// --- Session 8: Assayer fail-closed + close-out re-cut ---

func TestV7Case37AssayerVersionLacksTagBlocksRelease(t *testing.T) {
	t.Skip("expected-fail until S8: an Assayer version with no matching Git tag must block the release gate")
}

func TestV7Case38NoApplicableChecksBlocksApproval(t *testing.T) {
	t.Skip("expected-fail until S8: an empty applicable-check set must be ERROR/BLOCK for a blocking Assayer profile, never a silent PASS")
}
