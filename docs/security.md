# Sol redteam findings register

This is the audit-closure artifact for the Sol redteam review (`agents/governator-sol-upgrade2.md`, 2026-07) and its repair program, executed as seven sessions (`Sol redteam repair S1`–`S7`) against Governator HEAD `ad897aa` plus one Assayer session, followed by a documentation pass (S8) and a follow-up session (commit `629cb62`) that closed the one gap S8 found: High 11's local-runner output capping, scoped into S3/S6 but never implemented. Every finding below reproduces against the pre-repair binary per Sol's audit; each row records the fix commit and the regression test(s) that prove the fail-closed outcome. See [docs/containment.md](containment.md) for the containment model these fixes establish and [docs/claims.md](claims.md) for how `docs/claims.yaml`'s `sol-s*` entries mechanically re-derive several of these from the repository.

Governator repo commits are on local `main` (no remote; never pushed per the repair plan's execution rules). Assayer repo commit is its own local `main`.

## Critical findings

| # | Finding | Fix commit | Regression test(s) |
|---|---|---|---|
| Critical 1 | Replay bypassed current policy, config, routing, and containment checks — keyed only on `contract_hash + approved_head + status=APPROVED`, evaluated before every other gate | `90f95b5` (S1) | `internal/runtime/identity_test.go`: `TestExecutionIdentityHashSensitiveToEveryField`, `TestReplayPositiveIdenticalEnvironmentReplays`, `TestReplayInvalidatedByBackendBinaryChange`, `TestReplayInvalidatedByPromptVersionChange`, `TestReplayInvalidatedByConfigChange`, `TestReplayInvalidatedByOrgPolicyDeny` |
| Critical 2 | Malformed configuration failed open — `config.Current()` swallowed load errors and silently returned built-in defaults | `90f95b5` (S1) | `internal/config/config_test.go`: `TestLoadStrictRejectsMalformedYAML`, `TestLoadStrictRejectsUnknownField`, `TestLoadStrictRejectsInvalidPolicyValue`; `cmd/gov/doctrine_test.go`: `TestGovValidateReportsMalformedConfigAsInvalid`, `TestGovValidateAcceptsMissingConfig` |
| Critical 3 | Local runner permitted host filesystem writes through a tracked symlink, with a clean fingerprint and `APPROVED` outcome | `9e5dc39` (S3) | `internal/runtime/runtime_test.go`: `TestRunRejectsTrackedSymlinkBeforeLaunch`, `TestRunRejectsSymlinkedWriteParentBeforeLaunch` |
| Critical 4 | Backend capabilities trusted by adapter name, not attested to the configured executable — any binary at `backends.codex.bin` inherited Codex's "native sandbox" | `9e5dc39` (S3) | `internal/runtime/runtime_test.go`: `TestRunRejectsHighRiskCodexWithoutCapabilityAttestation`, `TestEnforceContainmentHighRiskAcceptanceCriterion` |
| Critical 5 | Live-root Git merging was not atomic — squash-then-commit left agent output staged in the live repo when the live-root commit was rejected | `fc89606` (S2) | `internal/runtime/runtime_test.go`: `TestMergeCommitHookRejectionRollsBackLiveRoot` |
| Critical 6 | Declared JSON transcript formats accepted zero valid JSON events — an all-plaintext `pi-json` transcript produced zero violations and `APPROVED` | `9e5dc39` (S3) | `internal/runtime/transcript_test.go`: `TestAuditTranscriptRejectsAllPlaintextPiJSON`, `TestAuditTranscriptRejectsUnrecognizedStartupNoise` |
| Critical 7 | Workspaces leaked after early returns between `Prepare()` and the run's normal exit (e.g. a graph-provider failure) | `fc89606` (S2) | `internal/runtime/runtime_test.go`: `TestWorkspaceCleanupGuardRemovesGraphPrepareFailureResources` |
| Critical 8 | Workspace locking was path-string based; a symlinked alias to a locked repository got a separate lock, permitting two concurrent runs | `fc89606` (S2) | `internal/runtime/runtime_test.go`: `TestLockCanonicalizesSymlinkAlias` |

## High findings

| # | Finding | Fix commit | Regression test(s) |
|---|---|---|---|
| High 1 | `budget.max_minutes` was not a true total wall-clock budget across agent + validators + Assayer | `10a2b3e` (S5) | `internal/runtime/runtime_test.go`: `TestWallClockBudgetExhaustionQuarantinesSlowValidators`; `internal/runtime/usage_test.go`: `TestStageTimeoutFailsWhenRunBudgetExpired` |
| High 2 | Token/cost ceilings failed open when telemetry was unavailable | `10a2b3e` (S5) | `internal/runtime/usage_test.go`: `TestTelemetryModesHandleUnavailableUsage`; `internal/contracts/parser_test.go`: `TestAssayAdvisoryAndTelemetryEnforcementAccepted` |
| High 3 | Policy override identity was too broad (rule ID alone, not bound to the rule's actual definition) | `10a2b3e` (S5) | `internal/policy/conditions_test.go`: `TestEvaluateConditionRulesAttributesSourceAndRuleID`, `TestContractRulesConvertsAndValidates` |
| High 4 | ASK resolution (`gov ask approve/deny`) was not transactional | `10a2b3e` (S5) | `internal/observability/policy_checkpoints_test.go`: `TestPolicyCheckpointLifecycle`, `TestPolicyCheckpointByIDNotFound` |
| High 5 | One-shot override consumption had a race — two concurrent evaluations could both consume the same grant | `10a2b3e` (S5) | `internal/observability/policy_checkpoints_test.go`: `TestClaimActivePolicyOverridesConsumesOneShotExactlyOnce`, `TestActivePolicyOverridesExpiry` |
| High 6 | Policy hashes did not actually identify the policy (verdict+reasons only) | `10a2b3e` (S5) | `internal/policy/decision_test.go`: `TestGatePolicyHashStableAcrossPatternOrder`, `TestEvaluateLayersPolicyHashIncludesResolvedRuleIdentity` |
| High 7 | Malformed policy conditions (e.g. `op: gt, value: "ten"`) silently never fired instead of failing to load | `10a2b3e` (S5) | `internal/policy/conditions_test.go`: `TestConditionRuleValidateRejectsTypeMismatchedValues`, `TestValidateRejectsUnknownConditionField` |
| High 8 | Docker "hardened" status was too permissive (root user, mutable tags, weak digest validation) | `5653928` (S6) | `internal/contracts/schema_test.go`: `TestDockerHardenedRejectsRootUser`, `TestMutableTagException` |
| High 9 | Credential mounts accepted dangerous host resources (symlink escapes, control sockets, arbitrary directories) | `5653928` (S6) | `internal/runner/docker_test.go`: `TestCredentialMountNoRootsConfiguredRefuses`, `TestCredentialMountOutsideRootsRejected`, `TestCredentialMountSymlinkEscapeRejected`, `TestCredentialMountDirectoryRequiresAuthorization`, `TestCredentialMountSpecialFilesRejectedEvenIfDirAuthorized`, `TestCredentialMountDockerSocketRejected` |
| High 10 | Docker observation (`DockerRunner.Observe`) failed open — an inspect failure or mismatch degraded to a note rather than blocking | `5653928` (S6) | `internal/runner/docker_test.go`: `TestDockerObserveHardenedNoContainerFailsClosed`, `TestDockerObserveHardenedLiveMatchApproves`, `TestDockerObserveHardenedLiveMismatchBlocks` |
| High 11 | Nonblocking output truncation could hide later actions on a capped-but-continuing transcript | `629cb62` (S3/S6 follow-up) | Docker-side loud truncation (accept/discard accounting, `OUTPUT_TRUNCATED` stage, blocking under `require_complete_transcript`) predates this repair (`loud-output-truncation` claim, v1.4-session3) and stayed in place. **Now also fixed for local runs**, closing the gap S3/S6 left open: `internal/runner/runner.go`'s `LocalWorktreeRunner.executor` wraps the host subprocess's stdout/stderr in the same `cappedWriter` `DockerRunner.executor` uses, bounded by the new `local.output_cap_bytes` (default 20MiB, mirroring `docker.output_cap_bytes`) and gated by the new `local.require_complete_transcript`. `internal/runner/local_test.go`: `TestLocalWorktreeRunnerLaunchCapsOutput`, `TestLocalWorktreeRunnerObserveNoTruncationByDefault`, `TestNewThreadsLocalConfig`; `internal/contracts/schema_test.go`: `TestValidateRunnerLocalConfig`, `TestEffectiveOutputCapBytesLocal`; `internal/runtime/runtime_test.go`: `TestRequiresCompleteTranscript` (local cases); `internal/runtime/identity_test.go`: `TestRunnerConfigHashesLocalConfig` (the `local.*` config now also invalidates replay via `ExecutionIdentity.RunnerConfigHash`, closing a related gap found while wiring this up — `runnerConfig()` previously hashed only `Docker`). |
| High 12 | Temporal-policy rule coverage differed substantially by backend without surfacing which rules were actually unenforceable | `5653928` (S6) | `internal/policy/events_test.go`: `TestUnenforceableRulesCodexMissingReadWriteNetwork`, `TestUnenforceableRulesClaudeGLMFullCoverage`, `TestUnenforceableRulesOpenCodePiMissingToolOutputOnly`, `TestUnenforceableRulesUnknownFormatEverythingUnenforceable`; `internal/runtime/transcript_test.go`: `TestAuditTranscriptCodexUnenforceableRulesFlaggedByDefault`, `TestAuditTranscriptUnenforceableRulesBlockWhenConfigured`, `TestAuditTranscriptOpenCodeGenericToolClassificationEnablesRules`, `TestAuditTranscriptPiGenericToolClassificationEnablesRules` |

## §6 audit/recovery weaknesses

| # | Finding | Fix commit | Regression test(s) |
|---|---|---|---|
| 1 | Redaction failure ignored (`_ = redact(transcript)`) | `10a2b3e` (S5) | `internal/runtime/runtime_test.go`: `TestApprovedReplayRedactionAndRollback` |
| 2 | Canary chmod/remove errors ignored, and a canary could silently drop out of snapshots | `10a2b3e` (S5) | `internal/runtime/runtime_test.go`: `TestCanaryMutationIsQuarantined`, `TestCleanupCanarySucceedsAndClearsFile`, `TestCleanupCanaryFailurePermanentlyIsReported` |
| 3 | Validator ledger inserts ignored (`_, _ = db.Exec`) — an approved run could silently lose validator evidence | `10a2b3e` (S5) | `internal/runtime/runtime_test.go`: `TestValidatorEvidenceInsertFailureEntersOutbox` |
| 4 | Final `rn.Destroy(context.Background(), ...)` had no deadline | `10a2b3e` (S5) | `internal/runtime/reconcile_test.go`: `TestReconcileWorkspaceDestroyRemovesLeftoverWorktree` (bounded-context destroy plus outbox fallback) |
| 5 | `.git` was excluded from fingerprints entirely — a local backend could modify hooks/config undetected | `10a2b3e` (S5) | `internal/runtime/runtime_test.go`: `TestGitControlFingerprintDetectsHookMutationThroughWorktree` |

## §7 release identity / claims provenance

| # | Finding | Fix commit | Regression test(s) |
|---|---|---|---|
| Version inconsistency + claims overclaim | Source binary self-reported `1.0.0-rc1`, release archive said `0.0.0-SNAPSHOT-none`, repo claimed v1.4.1; `gov claims verify` proved symbol/key existence, never that tests ran or the artifact matched | `7f2a0c4` (S4) | `internal/claims/claims_test.go`: `TestVerifyReleaseArtifactChecksExactBinaryAndSelfReportedVersion` (the `rc1`-vs-`v1.4.1` mismatch case), `TestVerifyRealClaimsFileIsFullyConsistent`, `TestReportFlagsOverclaimAsFail` |

`scripts/release.sh` is the canonical one-artifact-per-commit builder; see [docs/claims.md](claims.md#release-artifact-provenance).

## §8 Assayer weaknesses

Assayer repo, commit `e7b50b8` ("Sol redteam repair S7: Assayer v2"); Governator bridge sync in commit `fca79ce`.

| # | Finding | Fix commit | Regression test(s) |
|---|---|---|---|
| 1 | `coding-output-v1` too weak — `{"content":"x"}` passed | `e7b50b8` | `tests/test_evaluate.py`: `test_v2_rejects_sol_weakness1_reproduction`, `test_v2_pass_verdict_with_language_and_matching_extension`, `test_v2_fails_on_file_path_language_mismatch`, `test_v2_fails_on_syntactically_invalid_python`, `test_v2_passes_unregistered_language_domain_validator`; `tests/test_profiles.py`: `test_v1_and_v2_both_registered`, `test_v1_and_v2_declare_distinct_semver` |
| 2 | Database schema's verdict `CHECK` didn't allow `advisory` | `e7b50b8` | `tests/test_schema_migrations.py` (baseline lacks `advisory`, migration 0002 adds it idempotently, `schema.sql` matches baseline ∪ migrations) |
| 3 | `checks_hash` was an outcome hash only — no way to tell *which* profile/validator code/config produced it | `e7b50b8` | `tests/test_profiles.py`: `test_version_participates_in_profile_definition_hash`; `tests/test_evaluate.py`: `test_pass_verdict` (asserts `checks_result_hash`/`validator_implementation_hash`/`validator_config_hash` all present), `test_verdict_determinism_same_input_same_checks_hash` |
| 4 | `trace_id` was not a real trace — no way to distinguish "traced" from "not traced" | `e7b50b8` | `tests/test_evaluate.py`: `test_pass_verdict` (asserts `evaluation_id` truthy, `trace_id` is `None`) |
| 5 | Persistence fallback on quarantine could disappear silently | `e7b50b8` | `tests/test_outbox.py`: `test_enqueue_persists_a_pending_entry`, `test_file_created_with_0600_perms`, `test_replay_moves_successful_entries_out_of_pending`, `test_replay_dispatches_traces_to_insert_trace`, `test_replay_requeues_failed_entries_with_incremented_attempts`, `test_replay_dead_letters_after_max_attempts` |
| 6 | No packaging / dependency reproducibility (`pyproject.toml`, lockfile, CI) | `e7b50b8` | Artifact-based, not test-based: `pyproject.toml` (pinned deps, package version `1.1.0`), `requirements-lock.txt` (fully resolved), `.github/workflows/ci.yml` (Python 3.10/3.11/3.12 matrix) |

The Governator↔Assayer bridge (`internal/assay/assay.go`, commit `fca79ce`) was resynced to the renamed/added hash fields (`ChecksResultHash`, `ProfileDefinitionHash`, `ValidatorImplementationHash`, `ValidatorConfigHash`, `EvaluationID`), verified against Assayer's actual current HEAD via `internal/assay/testdata/assayer_fixture/PINNED_COMMIT` (`e7b50b82d4d65b315780af6ca808db3944d5d68c`) — confirmed byte-identical to the live Assayer repo at documentation time, so the Go integration test suite (`assay_integration_test.go`, `//go:build integration`) exercises the real v2 wire protocol, not a stale fixture.

## Sol's non-goals — confirmed not violated

Per the audit's §11 non-goals, none of the fixes above: disabled replay entirely (`ExecutionIdentity` replaces the old key, it doesn't remove replay), relied on prompt instructions, trusted backend names (Critical 4/attestation fixes this directly), let local worktrees count as host containment (see [docs/containment.md](containment.md)), used an LLM judge for policy or merge state (all policy/merge decisions remain deterministic Go), silently ignored unavailable telemetry (High 2/`telemetry_mode`), marked mutable Docker tags as hardened (High 8 — `AllowMutableTag` is explicitly excluded from `IsHardened()`), or permitted cross-backend fallback after mutation (unchanged from pre-repair `fallbackEligible` behavior, `pre-mutation-only-fallback` claim).

## Known open items

- ~~**HMAC-only release signing.**~~ **Closed by Sol redteam v4 S8 (P0-7).** `scripts/release.sh`'s `manifest_hmac_sha256` (when `GOV_RELEASE_HMAC_KEY` is set) remains write-only provenance — `gov claims verify` does not verify it, and an HMAC key that signs can also forge. `scripts/release.sh` now additionally produces `checksums.txt.minisig` (Ed25519, via `minisign`) whenever `GOV_RELEASE_MINISIGN_KEY` (an unencrypted secret key path) is configured — a signature publicly verifiable from the corresponding public key alone, with no shared secret. This augments rather than replaces the HMAC signature; when minisign isn't configured, no `.minisig` file is fabricated. See [docs/claims.md](claims.md#release-artifact-provenance).
- **Sol §9 (P3 strategic enhancements)** — external backend adapter protocol, a capability-attestation registry beyond the current per-backend attestation, versioned harness profile registry, profile-plus-backend routing, panel independence across provider/account/model lineage/prompt/policy, an offline Governator Evolver Lab, and profile drift detection with champion/challenger promotion remain unbuilt roadmap items, not defects. See the README roadmap section.

---

# Sol redteam v4 findings register

This is the audit-closure artifact for Sol's third redteam pass (`agents/governator-sol-upgrade4.md`), which
reproduced a 25-item black-box attack corpus against the v1.0.0 binary the v3 repair round shipped —
git-tree sovereignty, descendant/process containment, executable identity, externally enforced (not
self-reported) capability attestation, and release/supply-chain integrity. Repair plan:
`agents/governator-sol-upgrade4-plan.md`, executed as ten sessions (S0–S9); full per-session narrative,
design decisions, and exact fix commits: `agents/governator-sol-upgrade4-findings.md` — this register is
the same audit-finding → session → corpus-item index format as the v2/v3 tables above, kept intentionally
short (pointing into the findings log for detail) rather than re-deriving a full per-finding table from a
program this session didn't execute start to finish.

Unlike v2/v3, this round's corpus lives in-repo as executable tests, not just a document: `internal/redteam/`
(build tag `redteam`), run via `scripts/redteam.sh`. The skip count it prints is the literal project
burn-down — S0 landed all 25 attacks with the not-yet-fixed ones `t.Skip`-marked with a session tag; each
session's fix removes its own skips. **Closed 2026-07-14: `scripts/redteam.sh` reports 25/25 attacks green,
zero skips, zero failures**, both plain and `-race`. The v1.0.0 tag points at `f0cba5c` (the S9 follow-ups
that fixed two darwin cross-compile breaks and a missing executable bit on `scripts/*.sh` in the git index,
landed after the `d289bf3` S0–S9 commit that the corpus first went green against).

## Session ↔ report-item map

| S | Theme | Report items closed | Corpus attacks |
|---|---|---|---|
| 0 | Attack harness + ground truth; P1-4 triage | — (P1-4: false positive, see below) | scaffolding for all 25 |
| 1 | Git tree sovereignty (`internal/gitplumb/`) | P0-1, P0-2, P1-6, P1-9 | 1, 2, 3, 4, 19 |
| 2 | Descendant containment (`internal/containment/descendants.go`) | P0-4 | 8 |
| 3 | Executable identity (`internal/agents/handle.go`) | P0-6, P1-1, P1-2 | 6, 7, 10, 11, 12 |
| 4 | Trusted tool registry (`internal/toolregistry/`) | P0-5, P1-14 | 9 |
| 5 | Externally enforced attestation (`internal/enforce/`, `internal/observability/enforcement.go`) | P0-3, P1-15, P1-17 | 5 |
| 6 | Assayer outbox/languages/evidence (companion repo) | P0-8, P1-12, P1-13 | 13, 14, 16 |
| 7 | Correctness/concurrency P1s | P1-3, P1-4, P1-5, P1-7, P1-8, P1-10, P1-11, P1-16 | 15, 17, 18, 20, 21, 22, 23 |
| 8 | Release/supply chain (`scripts/release_verify.sh`) | P0-7 | 24, 25 |
| 9 | Lifecycle state machine, effect ledger, chaos suite, close-out | — (formalization + property/chaos tests over prior sessions' fixes) | corpus stays 25/25; no new attacks added |

**P1-4 (duplicate org-policy evaluation) — verdict: false positive**, triaged in S0. Sol's finding described
two things that share a source *label* but are different rule sets evaluated on different code paths
(`internal/runtime/policy_gate.go`'s `evaluatePolicyGate` vs. `internal/policy/preflight.go`) — not the same
rule set evaluated twice. `internal/redteam/policy_race_test.go` asserts the exact count and source of
evaluated rules regardless of the verdict.

## S9 additions to the enforcement surface (this session)

Not report findings — S9 formalizes and property-tests the lifecycle the S0–S8 fixes above actually produce,
and closes two chaos-scenario gaps the plan named:

- `internal/lifecycle/` — the run state machine as an explicit `Stage` type with a validated transition
  graph, wired live into every `RecordStage` call site in `internal/runtime` (out-of-order stage writes are
  now rejected at record time). Three transition-graph bugs found and fixed by re-running the full suite and
  redteam corpus after wiring the validator in (see findings log for exact detail): `ASSAYING`'s conditional
  skip, `QUARANTINED`'s direct reachability from a mid-pipeline failure, `MERGED`'s reachability from a
  non-git root.
- `internal/observability/effects.go` — a kernel-observed effect ledger (`process_creation`, `network`,
  `executable_launch`) recorded independent of the transcript, alongside the pre-existing `files_touched`
  table (file writes) and `EnforcementRecord` (S5's per-run enforcement summary).
- New chaos tests: real concurrent-`*sql.DB` contention against one on-disk ledger, a hung validator killed
  at its context deadline, forward/backward system-clock jumps against the spend reservation ledger (no
  defect found — confirmed clock-jump-safe by construction). "Hook failures" and "disk full" have no test
  added — see the findings log for why (no scenario/seam exists to test against).

## Sol's v4 non-goals — confirmed not violated

Per the same non-goals discipline the v2/v3 registers above check: no fix in this round disabled tree
sovereignty for a documented convenience path, weakened descendant containment to a process-group-only
fallback for a "usually fine" case, let a probe's self-report stand in for external enforcement, or shipped
a release-identity check that trusted the requested version string over the actual artifact. The
containment/attestation posture established in v2/v3 (enforce by default, disclosed opt-outs only) is
unchanged; this round adds sovereignty over the *mechanism* (git plumbing, process trees, executable
identity) that posture depends on, it doesn't relax it.

---

# Sol redteam v3 findings register (2026-07-13)

This is the audit-closure artifact for Sol's second, deeper redteam pass (`agents/governator-sol-upgrade3.md`), which reproduced 20 new findings against the v1.0.0 binary the first repair round shipped — mostly transaction/concurrency, identity, and containment gaps the first pass's fixes didn't reach. Repair plan: `agents/governator-sol3-repair-plan.md`, executed as 15 sessions (S1–S15) plus one standalone flake fix; closure report: `agents/governator-sol3-repair-report.md`. Every finding below reproduces against the pre-fix code per the audit or the session's own report (most sessions verified failing-before/passing-after by temporarily reverting the fix file and re-running the regression test — see the closure report for exactly which). `docs/claims.yaml`'s `sol3-s*` entries mechanically re-derive most of these from the repository at `tested` maturity.

Governator repo commits are on local `main` (no remote). Assayer repo commit is its own local `main`. This register does not duplicate `agents/governator-sol3-repair-report.md`'s much longer per-session design-decision narrative — it's the same audit-finding → fix → test index format as the v2 tables above, for a future redteam to scan quickly.

## P0 — release-blocking findings

| # | Finding | Session | Fix commit | Regression test(s) |
|---|---|---|---|---|
| 1 | Capability attestation copied static adapter declarations into probe results — a fake executable printing `codex` in `--version` inherited real Codex capabilities without any actual sandbox/network/transcript probe | S4 | `27ae90f` | `internal/attest/sol3_attest_test.go`: `TestSol3FakeCodexVersionStringDoesNotAttestCapabilities`; `internal/runtime/sol3_attestation_test.go`: `TestSol3FakeCodexAttestationCannotAuthorizeHighRiskLocal` |
| 2 | Configuration was re-read from disk independently by multiple subsystems mid-run (`config.Current()`), so an edit to `config.yaml` while a run was in flight could change enforcement between the moment a rule was evaluated and the moment its effect was recorded | S3 | `25c7531` | `internal/runtime/config_mutation_test.go`: `TestSol3ConfigMutationDuringRunDoesNotAlterDoctrineEnforcement`; `internal/runtime/config_current_guard_test.go`: `TestSol3NoConfigCurrentInExecutionCriticalPackages` |
| 3 | No final re-measurement barrier before merge — a validator/formatter/Assayer stage that exited 0 but created an undeclared file, mutated a protected path, or deleted an in-scope file was never independently re-checked against the originally approved measurement | S5 | `495e0f2` | `internal/runtime/sol3_final_barrier_test.go`: `TestSol3FinalBarrierQuarantinesValidatorCreatedUndeclaredFile`, `TestSol3FinalBarrierQuarantinesValidatorProtectedPathMutation`, `TestSol3FinalBarrierQuarantinesValidatorDeletesInScopeFile`, `TestSol3FinalBarrierAllowsCleanupFormatterRewrite`, `TestSol3FinalBarrierQuarantinesValidatorLineBudgetOverflow` |
| 4 | A backend could create a runtime symlink to an external path and write through it undetected; artifact collection followed symlinks (`Stat`/`ReadFile`, not `Lstat`+no-follow), so a produced-artifact path pointing outside the workspace was copied into the artifact store | S6 | `495e0f2` | `internal/runtime/sol3_runtime_path_containment_test.go`: `TestSol3RuntimeCreatedSymlinkQuarantinesBeforeMerge`, `TestSol3RuntimeCreatedSpecialFileQuarantines`, `TestSol3ProducedArtifactSymlinkRefusedNoCopy` |
| 5 | Backend binary resolution hashed `config.BackendBin(...)` (a bare name like `"pi"`) directly via `os.ReadFile` instead of through `exec.LookPath` — always failed to a fixed `"unreadable:<name>"` sentinel, so replacing a PATH-resolved backend with a different program never invalidated replay | S2 | `e100f2a` | `internal/runtime/identity_test.go`: `TestSol3ReplayInvalidatedByBarePathBackendSwap`; `internal/agents/resolution_test.go`: `TestSol3ResolvePathBareNameProducesRealHash` |
| 6 | Assayer's quarantine outbox was a plain JSONL file with a read-modify-write replay path — an entry enqueued while a replay was in progress/blocked could be silently lost (overwritten by the replay's own rewrite of the file) | S7 | `a5f26f2` (Assayer) | `tests/test_outbox.py`: `test_sol3_enqueue_during_blocked_replay_is_not_lost`, `test_sol3_two_concurrent_replayers_never_double_process`, `test_sol3_kill_mid_replay_recovers_via_lease_expiry`, `test_sol3_legacy_jsonl_at_same_path_is_auto_migrated_on_open`, `test_sol3_double_migration_is_a_noop` |
| 7 | `gov hook pre-tool-use` returned exit 0 with no denial and no ledger record on malformed/truncated/oversized/wrong-version stdin — `printf '{broken' \| gov hook pre-tool-use` was silently allowed | S1 | `76bde79` | `cmd/gov/main_test.go`: `TestSol3HookProtocolMalformedInputDenies`, `TestSol3HookProtocolOversizedPayloadDenies`, `TestSol3HookProtocolValidPayloadsNotOverBlocked`, `TestSol3HookProtocolEmergencyJournal` |
| 14 | Produced-artifact collection followed symlinks — a produced artifact path that was itself a symlink to an external sensitive file was copied into the artifact store and could reach Assayer | S6 | `495e0f2` | `internal/runtime/sol3_runtime_path_containment_test.go`: `TestSol3ProducedArtifactSymlinkRefusedNoCopy` |

## P1 — other high-priority findings

| # | Finding | Session | Fix commit | Regression test(s) |
|---|---|---|---|---|
| 8 | One-shot ASK approvals were consumed the instant the policy gate resolved them, not at the actual execution boundary — if a second, independent rule still blocked the same run, the first rule's approval was burned for nothing | S8 | `a80df68` | `internal/runtime/sol3_ask_lifecycle_test.go`: `TestSol3OneShotApprovalSurvivesWhenAnotherRuleStillBlocks` |
| 9 | Config validation had several fail-open edge cases: a second YAML document was silently ignored; a negative `max_minutes`/`timeout_seconds`/token limit was silently replaced by the default instead of rejected (merge's `>0` gate hides the raw supplied value); `.nan`/`.inf` passed the `<0` numeric check | S8 | `a80df68` | `internal/config/sol3_config_validation_test.go`: `TestSol3LoadStrictRejectsMultipleYAMLDocuments`, `TestSol3LoadStrictRejectsNaNAndInfSpendCap`, `TestSol3LoadStrictRejectsNaNAndInfQuotaFields`, `TestSol3LoadStrictRejectsNegativeMaxMinutesInsteadOfDefaulting`, `TestSol3LoadStrictRejectsMalformedQuotaTimestamp`; `internal/policy/sol3_tofloat_test.go`: `TestSol3ToFloatRejectsNaNAndInf`, `TestSol3ConditionRuleValidateRejectsNaNLiteralForNumericOperator` |
| 10 | Quota headroom validation and reservation were two separate steps (read, then write) — concurrent reservations could jointly exceed headroom; `Settle`/`Release`/`ExpireStale` read `settled_at` outside any transaction, so two recovery workers could double-decrement the same reservation | S9 | `9421359` | `internal/quota/sol3_reserve_concurrency_test.go`: `TestSol3ConcurrentReservationsCannotExceedHeadroom` (12–14/20 succeeded pre-fix against a 10-slot headroom), `TestSol3SettleVersusExpireDoesNotDoubleDecrement`, `TestSol3SettleVersusReleaseDoesNotDoubleDecrement`, `TestSol3TwoRecoveryWorkersNeverDoubleApplyExpire` (reserved_usage=250 instead of 300 pre-fix) |
| 11 | Daily spend cap was checked via settled-spend-only `CheckBudget`, with no shared reservation state — two concurrent `gov run`/`gov batch` processes could each pass the check and jointly exceed the cap; an unknown-cost run counted as $0 against the cap instead of a conservative estimate | S9 | `9421359` | `internal/spend/sol3_reservation_test.go`: `TestSol3ReserveGlobalConcurrentAcrossTwoConnectionsNeverExceedsCap`, `TestSol3SettleGlobalUnknownCostFallsBackToEstimateNotZero`, `TestSol3SettleGlobalKnownCostUsesActualNotEstimate`, `TestSol3SettleVersusReleaseGlobalMutualExclusion`, `TestSol3ReleaseForRunOnlyTouchesThatRun` |
| 12 | Maintenance-outbox rows were read unclaimed (`PendingOutbox`) — two `gov reconcile` processes could both dispatch the same row; validator-evidence insertion and breaker-failure recording had no idempotency key | S10 | `fcbbc2a` | `internal/runtime/sol3_reconcile_leasing_test.go`: `TestSol3ConcurrentReconcilersNeverDoubleApplyBreakerFailure`, `TestSol3ClaimOutboxNeverDoubleClaimsAcrossTwoConnections` |
| 13 | Crash recovery's `WORKSPACE_READY` stage recorded an empty detail; recovery used an ad hoc `git worktree remove`/`os.RemoveAll` with every error swallowed instead of the real runner's `Destroy` path, so a Docker container from a killed run was never actually removed and the run was still marked recovered regardless | S10 | `fcbbc2a` | `internal/runtime/sol3_docker_crash_recovery_test.go`: `TestSol3RecoveryRemovesLeftoverDockerContainer` (container confirmed still present pre-fix), `TestSol3RecoveryLeavesRunRunningWhenContainerCleanupFails` |
| 15 | Transcript integrity was based entirely on self-report — a single benign recognizable event (any Codex `item.*`, or a Pi event naming a tool) satisfied `recognizedTranscriptEvent`'s bar regardless of what else the wrapper did outside the JSON stream | S12 | `cb57012` | `internal/runtime/sol3_transcript_conformance_test.go`: `TestSol3TranscriptConformanceCorpusSingleBenignEventBlocked`, `TestSol3TranscriptConformanceSessionIdentityMixedBlocks`, `TestSol3TranscriptConformanceUnpairedToolUseBlocks`, `TestSol3TranscriptConformanceTurnCountShortBlocks`, `TestSol3TranscriptConformanceConformingFixturesPass` (no-over-blocking), `TestSol3TranscriptConformanceCoexistsWithTemporalRuleDeny`. **Default posture is advisory (flag), not blocking** — see design decision in the closure report's S12 section; set `doctrine.transcript_conformance_action: block` to enforce. |
| 16 | Assay evaluated only the first produced artifact (`artifactRecords[0]`) — a contract producing several artifacts under a blocking assay passed as long as the alphabetically-first one did, regardless of later artifacts | S11 | `382e81f` | `internal/runtime/assay_test.go`: `TestSol3AssayEvaluatesEveryProducedArtifactThirdFailureBlocks` (wrongly `APPROVED` pre-fix, evaluating only "alpha"), `TestSol3UndeclaredProducedArtifactFailsClosed`, `TestSol3ArtifactAssayNoneExemptsWithoutOverBlocking` |
| 17 | Governator sent only the logical artifact name over the Assayer wire protocol, never its declared path/media type/language — a `.py` file named `code` never gave Assayer's file-aware checks the extension they needed | S11 | `382e81f` (Governator), `33bfde2` (Assayer) | `internal/assay/assay_test.go`: `TestSol3ArtifactDeclaredPathReachesRealAssayerFilePathCheck`; Assayer `tests/test_evaluate.py`: `test_v2_ignores_artifact_name_extension_mismatch`, `test_protocol_version_mismatch_fails_closed`, `test_protocol_version_missing_fails_closed` |

## P2 — lower-priority findings

| # | Finding | Session | Fix commit | Regression test(s) |
|---|---|---|---|---|
| 18 | `gov snap restore` had only one mode (overlay) — no way to remove post-snapshot additions on restore, even when an operator wanted an exact point-in-time restore | S13 | `8e36651` | `internal/snapshots/snapshots_test.go`: `TestRestoreExactRemovesAdditionsAndOverlayDoesNot`, `TestRestoreExactPreservesProtectedPaths`, `TestRestoreExactRequiresConfirmation` |
| 19 | Snapshot hardlink-dedup decision (`same()`) trusted size+mtime as proof of identity — a file whose content changed while both were preserved got hardlinked to stale content in the new snapshot | S13 | `8e36651` | `internal/snapshots/snapshots_test.go`: `TestSameDetectsContentChangeDespiteMatchingSizeAndMtime`, `TestSnapshotDoesNotHardlinkStaleContentWhenSizeAndMtimeMatch` (reproduced the exact corruption pre-fix: second snapshot captured stale content) |
| 20 | Release packaging was split across two incompatible generations (`scripts/release.sh` vs. `.goreleaser.yml`'s snapshot mode), producing archives with inconsistent version/commit identity, no checksums/SBOM/test-summary for the multi-platform build, and stale snapshot archives left in a reused output directory | S14 | `2d82ba2`, `3bd308a` | `internal/claims/claims_test.go`: `TestVerifyReleaseArtifactChecksExactBinaryAndSelfReportedVersion`; operationally: `scripts/release.sh`'s own acceptance smoke test (extract → executable bit → binary hash → `gov version --json` vs. manifest → `gov claims verify`), run for real each release |

## Corpus item ↔ session map

The audit's 15-item black-box reproduction corpus, closed end to end (see `agents/governator-sol3-repair-report.md`'s S15 section for the full run record):

| # | Corpus item | Session | Finding(s) |
|---|---|---|---|
| 1 | Fake Codex version-string attestation | S4 | #1 |
| 2 | PATH binary replacement invalidates replay | S2 | #5 |
| 3 | Config mutation during execution doesn't change enforcement | S3 | #2 |
| 4 | Validator-created forbidden file is quarantined | S5 | #3 |
| 5 | Runtime-created symlink host write is rejected | S6 | #4 |
| 6 | Malformed hook payload fails closed | S1 | #7 |
| 7 | Concurrent Assayer enqueue during replay isn't lost | S7 | #6 |
| 8 | Two simultaneous quota reservations can't exceed headroom | S9 | #10 |
| 9 | One-shot approval survives a second still-blocking rule | S8 | #8 |
| 10 | Docker process crash + stale recovery actually removes the container | S10 | #13 |
| 11 | Symlinked produced artifact is refused, not copied | S6 | #14 |
| 12 | Multiple produced artifacts under a blocking assay — any failing artifact blocks | S11 | #16 |
| 13 | Multiple YAML documents rejected, not silently ignored | S8 | #9 |
| 14 | NaN/Inf spend and quota limits rejected | S8 | #9 |
| 15 | Two concurrent reconcilers never double-apply a non-idempotent op | S10 | #12 |

## Test infrastructure fixed alongside the audit (not itself an audit finding)

`TestRunPanelQuorumProceedsWithoutStraggler` (`internal/runtime/panel_test.go`) is a real-wall-clock quorum test (1s hard timeout vs. a 2s slow-member sleep) that every S1–S14 session independently observed flaking under `-race`/system load and flagged in its report without touching (out of each session's own file scope). S14's own release-pipeline dry run caught it actually failing the unit tier of a real packaging attempt twice — elevating it from "annoying CI noise" to "can nondeterministically block a real release." Fixed as a standalone commit ahead of S15 (widened to a 5s hard timeout / 6s sleep, giving `m1`'s own setup overhead — worktree/git init, ledger writes, process spawn — a full order of magnitude of margin instead of racing it against a 1s ceiling): reproduced 2/6 fresh failures under `-race -count=1` before the fix, 12/12 clean after. Test-only change, no production code touched.

**CORRECTED (Sol v7 S9, 2026-07-17):** widening the timing margin above was treating a symptom, not the disease. Once real Landlock enforcement started actually applying to this test (rather than degrading to unconfined for unrelated reasons — see the v7 register below), the test failed **deterministically, 100% of the time, regardless of timing margin or host load**, with a real `mkdir: cannot create directory '.governator': Permission denied` from inside the confined subprocess. Root cause: `ModeArchitect`/`ModeVerifier`/`ModeScout` contracts map to a Landlock-`readOnly` sandbox that denies writes to the *entire* workspace with zero carve-out — including for `RESULT.json` (every contract's compiled prompt unconditionally instructs writing it, regardless of mode) and `.governator/artifacts/**` (needed by any `Produces`-declaring job, which is exactly the shape `internal/panel/panel.go`'s `readOnlyJob` builds in production). This was a real, previously-undiscovered production defect — any panel run was structurally unable to complete on a host with genuine Landlock+`unshare` support, not a flaky test. See the v7 register below for the fix.

## Sol v3's non-goals — confirmed not violated

Per the same non-goals discipline the v2 register above checks: none of the v3 fixes disabled replay, containment tiering, or the ASK lifecycle; none weakened a probe/schema/check to make a backend or fixture pass (S4's real attestation and S12's transcript conformance both explicitly leave real non-Claude/GLM backends with narrower, honestly-labeled — not fabricated — coverage where a real transcript sample wasn't available to verify against); the containment-tiering default (S6) and the transcript-conformance blocking default (S12) were both implemented enforcing-by-default with the non-default alternative behind an explicit, disclosed operator opt-out — never silently relaxed to make an existing workflow keep passing.


---

# Sol redteam v6 S9 Assayer lifecycle register (2026-07-15)

S9 closes the Assayer-owned lifecycle findings from `agents/governator-sol-upgrade6-plan.md` at the code/test level, but the release is not re-cut from this workspace until the whole v6 redteam corpus is green. Verification collected in this session:

- Assayer: `python3 -m pytest -q` -> `191 passed in 6.38s`.
- Governator S9 corpus pointer/process tests: `go test -tags redteam -run "V6Case3[123]" -count=1 ./internal/redteam` -> pass.
- Full `go build ./...` and `go vet ./...` passed.
- Full `go test -count=1 ./...` and `./scripts/redteam.sh` did not complete cleanly under the 120s harness; a bounded full-redteam attempt surfaced non-S9 failures in older corpus cases before timing out. No v6 S9 release install was performed.

| Finding | Fix state | Regression test(s) |
|---|---|---|
| P1-3: pytest could print a passing summary but hang under Python 3.13 due fork/thread crash-recovery tests | Crash-recovery multiprocessing now uses `multiprocessing.get_context("spawn")`; release evidence must still record process exit code. | Assayer `tests/test_outbox.py`: `Sol3OutboxCrashRecoveryTests.test_sol3_kill_mid_replay_recovers_via_lease_expiry`; Governator `internal/redteam/v6_s9_assayer_lifecycle_test.go`: `TestV6Case33AssayerPytestExitsCleanlyOnSupportedPythonVersions` |
| P1-4: outbox leases renewed once before slow target calls, allowing duplicate execution after lease expiry | `Outbox.replay` starts a per-entry heartbeat that renews the lease while the downstream call is in flight; completion still requires current lease ownership. | Assayer `tests/test_outbox.py`: `Sol6OutboxLeaseHeartbeatTests.test_attack31_lease_renewed_through_slow_downstream_call_prevents_duplicate_execution`; Governator: `TestV6Case31AssayerLeaseRenewedThroughSlowDownstreamCallPreventsDuplicate` |
| P1-5: unknown outbox table hints routed as traces | Strict allowlist (`assayer_quarantine`, `assayer_traces`); unknown hints become dead letters with `UNKNOWN_OUTBOX_OPERATION`. | Assayer `tests/test_outbox.py`: `Sol6OutboxUnknownOperationTests.test_attack32_unknown_table_hint_is_dead_lettered_not_reinterpreted_as_trace`; Governator: `TestV6Case32UnknownOutboxOperationIsDeadLettered` |
| P1-6: dedup store failures fail open | `checks.dedup(..., failure_policy=...)` supports `fail`, `advisory`, and `skip`; blocking profiles can fail closed. | Assayer `tests/test_checks.py`: `test_blocking_profile_can_fail_closed_when_store_raises`, `test_skip_policy_is_explicit` |
| P1-7: retention deletion selection/deletion race | `Store.delete_expired_quarantine(statuses, cutoff_iso)` constrains the delete by status and age; purge uses it when available and audits returned ids. | Assayer `tests/test_evidence.py`: purge tests with `FakeStore.delete_expired_quarantine` |
| P1-8: evidence encryption lacks key identity/rotation | Encrypted payloads now store `key_id`, `algorithm`, `format_version`, `nonce`, ciphertext, and auth metadata; decryption rejects unavailable key ids; classified/sensitive evidence requires encryption via `store_representation_for_classification`. | Assayer `tests/test_evidence.py`: `test_round_trips_with_key_id_and_previous_key_map`, `test_decrypt_rejects_unavailable_key_id`, `test_classified_evidence_requires_encryption` |

---

# Sol redteam v7 register (2026-07-17)

Sessions S1–S8 (`agents/governator-sol-upgrade7-plan.md`, findings in `agents/governator-sol-upgrade7-findings.md`) migrated every external process launch onto one common envelope (`internal/stage`), derived containment authority from actual effects rather than declared risk labels, sealed every controller/validator/graph-provider tool identity, narrowed Landlock to an exact per-executable read closure, and replaced the contract-hash release gate with a full identity-based one (`internal/redteamgate`). Full per-session detail (StageExecutor migration, sealed tool identities, `TestAttack8` setsid-daemon fuse extinction proof and the two containment bugs it found — `systemd-run --wait`+`--scope` conflict, missing `XDG_RUNTIME_DIR` in the frozen-environment allowlist — is in the findings log; this register only indexes what's new since v6.

**Sol v7's own manifest corpus (`internal/redteam/manifest.yaml`, 38 cases, build tag `redteam`): all `status: implemented`.**

This same session's `v1.0.2-rc1` release cut (below) is what first exercised the S1–S8 StageExecutor migration's real Landlock enforcement against the *entire* existing test suite, not just the redteam corpus — surfacing three real, previously-undiscovered defects that had nothing to do with the redteam corpus's own scope:

| Finding | Fix | Regression test(s) |
|---|---|---|
| Read-only-mode contracts (`ModeScout`/`ModeVerifier`/`ModeArchitect`) could never complete under genuinely active Landlock enforcement: the `readOnly` ruleset denies writes to the entire workspace with zero carve-out for `RESULT.json` (every contract's compiled prompt unconditionally instructs writing it) or `.governator/artifacts/**` (needed by any `Produces`-declaring job — the exact shape `internal/panel/panel.go`'s `readOnlyJob` builds in production). This was misdiagnosed at first as the panel-quorum test's long-running host-CPU-contention flakiness (see the corrected note above); it was actually 100% deterministic. | `internal/enforce`: `Plan` gained `WriteDirs`/`WriteFiles` + `WithWriteRoots(dirs, files)`; `Wrap()` emits `--write-dir`/`--write-file`; `applyLandlockRuleset`'s new `writeCarveOuts` grants `landlock.RWDirs`/`RWFiles` for them (fail-closed if a path escapes the workspace or doesn't already exist — Landlock binds a rule to an opened path). `internal/runtime/runtime.go`'s launch site pre-creates an empty `RESULT.json` (always, when the Plan is active and read-only) and `.governator/artifacts/` (when the contract declares `Produces`) on the host side, unconfined, before building the write-root list. | `internal/runtime/panel_test.go`: `TestRunPanelQuorumProceedsWithoutStraggler`, `TestRunPanelQuorumSkipsMemberOnceSatisfied` |
| `internal/stage/stage.go`'s `Executor.Run` pointed `cmd.Stdout` and `cmd.Stderr` at the same plain `bytes.Buffer`. `os/exec` copies a command's stdout and stderr from two independent goroutines, and `bytes.Buffer` is not safe for concurrent writes — a real data race on the shared launch path every governed run goes through, caught by `-race` only intermittently (consistent with a genuine race, not a deterministic bug). | Mutex-guarded `syncBuffer` wrapper used for both streams. | `internal/redteam/backend_identity_test.go`: `TestAttack5FakeBackendBehavesSafelyOnlyDuringAttestation` (5/5 under `-race -count=5` after the fix) |
| `internal/runtime/recovery.go`'s `destroyLeftoverWorkspace` built a bare `&runner.DockerRunner{}` for crash-recovery cleanup of a leftover Docker-runner workspace, with no `ControllerEnvironment` — every Docker-runner crash-recovery cleanup silently fell into `cleanup_pending`/retry-via-outbox, never `safe_resume`, regardless of whether the actual container removal would have succeeded. | `ControllerEnvironment: controllerenv.Freeze()`, matching the pattern `internal/runner/docker_test.go` already established for two other DockerRunner call sites. | `internal/runtime/sol3_docker_crash_recovery_test.go`: `TestSol3RecoveryRemovesLeftoverDockerContainer`, `TestSol3RecoveryLeavesRunRunningWhenContainerCleanupFails` (the latter's own `DOCKER_HOST`-based failure simulation also had to be replaced with a fake enrolled `docker` binary, since `controllerenv`'s allowlisted environment never passed `DOCKER_HOST` through to the child process either) |

**Closed 2026-07-21 (Sol10 P0-1, rc4 Session 1):** consumed-artifact staging previously sealed a consumed artifact at mode `0400` inside the writable worktree, intending it read-only to the consumer — defeated by `--map-root-user` (the confined process runs as root inside its own user namespace, needed elsewhere for mount operations, which grants it `CAP_DAC_OVERRIDE` over files it owns), and Landlock's write ruleset had no per-subpath write-*exclusion* mechanism to close the gap either. Fixed: consumed artifacts now stage into a private, controller-owned store outside the worktree (`internal/runtime/artifacts.go`'s `consumedArtifactStoreDir`), exposed to the backend and to any validator that reads it only through a genuinely separate mount — a read-only bind established inside a private mount namespace (local runner: `internal/enforce`'s `Plan.ROBinds`/`RunSandboxExec`'s `--ro-bind`) or a read-only docker volume (`internal/runner/docker.go`) — so the ancestor workspace's writable Landlock rule never reaches it (Landlock rules are additive within one ruleset; only a genuinely different mount object lets a narrower rule be authoritative). Validators, which launch through `internal/stage.Executor`'s own independently compiled plan rather than inheriting the backend's, get the same ro-bind explicitly (`stage.StageAuthority.ROBinds`). Every consumed artifact is additionally hash-reverified at four points (before backend launch, after backend extinction, before validation, after all validation); any mismatch quarantines with exactly `CONSUMED_ARTIFACT_MUTATED`, never silently re-copied. A host that cannot provide the boundary (Landlock ABI/unshare unavailable) fails the run closed rather than degrading silently, except under the operator's own pre-existing `enforce_local_effectful_tiering: off` opt-out, where staging honestly falls back to the mode-bits location and `ConsumedArtifactBoundary` records `mode-bits-degraded` rather than implying a boundary that isn't there. Proven end to end by `internal/redteam`'s `TestV10Case1BackendOverwriteOfConsumedArtifactRefused` through `TestV10Case8MutationDetectedAfterSuccessValidation` (manifest cases 102-109).

**Closed 2026-07-21 (Sol10 P0-2, rc4 Session 2):** `internal/containment/descendants.go`'s systemd-run/unshare descendant-containment primitives were resolved+verified through the trusted-tool registry, then launched by re-exec'ing their canonical pathname — a same-uid process could replace the file between verification and launch, and the replacement, not the verified binary, would become responsible for establishing containment (the file's own `known_gap_pending_hardening` marker). Separately, `NewScope` reloaded the global trusted-tool registry fresh on every call (once for the run-level Scope, again for every stage's own Scope), after the run's environment and replay identity were already frozen, so the primitive actually used could diverge from the one the transaction's identity described; the fd-open-per-attempt-and-never-close-on-early-return-paths shape of that reload also leaked one file descriptor per failed scope-selection attempt on a host without a usable systemd user manager. Fixed: `containment.ResolveEnvironment` resolves both primitives' handles exactly once, from the same frozen `toolregistry.Registry` `internal/runtime.RunEnvironment` already loads once per run; `NewScope` now takes that `ContainmentEnvironment` as an explicit parameter and never touches the registry itself. `Scope.Command` launches both primitives exclusively through the held handle's `/proc/self/fd/3` descriptor (never a pathname) — verified by grep: zero `primitivePath`-shaped strings remain in the package. The environment is threaded to every stage's own `NewScope` call via `containment.WithEnvironment`/`EnvironmentFromContext` (mirroring `enforce.WithPlan`), and its handles are borrowed, not owned, by each `Scope` — closed exactly once, by `runOnce`, after the whole run finishes, which also structurally closes the fd leak (no per-attempt open remains at all). `ExecutionIdentity` gained `ContainmentEnvironmentHash`, binding the exact resolved primitive identities (SHA-256/canonical path/device/inode) into the replay key. The `known_gap_pending_hardening` `govratchet` class was removed (`internal/govlint`) now that no site cites it. Proven end to end by `internal/containment`'s `TestV10Case9UnshareReplacedAfterFrozenEnvironmentConstructionHasNoEffect` through `TestV10Case14RealPIDNamespaceLaunchExecutesExactVerifiedTarget` (manifest cases 110-115; case 13/114 is host-gated on a live systemd `--user` bus via the manifest's `has_systemd_user` conditional).

**Pre-existing, out-of-scope defect (not fixed, unrelated to this session):** `TestV6Case23GraphDatabaseChangeBeforeReplayInvalidatesReplay` fails on an empty post-replay graph fingerprint (`runOnce` never calls `contextgraph.Prepare` on a non-replayed run in this exact ordering) — a v6-series case outside the v7 38-case manifest, repeatedly triaged and deferred across multiple sessions' own findings logs, not newly introduced or newly investigated here.

