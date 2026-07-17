//go:build redteam

package redteam

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
//
// Cases 5, 6, 7, 9, 10, 11, 12 landed as real fixtures in
// v7_s1_stage_containment_test.go (Task #3, S1/S4/S6 gap-closure session,
// 2026-07-16).
//
// Case 8 landed as a real fixture in v7_s1_case8_extinction_test.go (S8
// close-out session, 2026-07-17) -- a pure-Go raw FUSE daemon (see
// hangfuse_test.go) whose read() never replies, giving a black-box
// descendant genuine kernel-level immunity to SIGKILL past the extinction
// deadline. See that file's header comment for why the earlier declined
// attempt (a libfuse-linked C daemon) failed on this exact host while the
// raw, capability-minimal protocol implementation here succeeds.

// --- Session 5: narrow Landlock, exact read closure, fail-closed ABI ---
//
// Case 4 landed as a real fixture in v7_s5_narrow_landlock_test.go (Task
// #3, S1/S4/S6 gap-closure session, 2026-07-16).

// --- Session 6: ExecutionIdentityV2 from one immutable transaction snapshot ---
//
// Cases 17, 18, 21, 22, 23, 24 landed as real fixtures in
// v7_s6_strict_replay_test.go (S1/S4/S6 gap-closure session continuation,
// 2026-07-17).

// Cases 25, 26, 27, 28 landed as real fixtures in
// v7_s6_strict_replay_test.go (Task #3, S1/S4/S6 gap-closure session,
// 2026-07-16).

// Cases 29, 30 landed as real fixtures in v7_s6_strict_replay_test.go
// (S1/S4/S6 gap-closure session continuation, 2026-07-17).

// --- Session 8: Assayer fail-closed + close-out re-cut ---
//
// Cases 37, 38 landed as real fixtures in v7_s8_assayer_test.go (S8
// close-out session continuation, 2026-07-17).
