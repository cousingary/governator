# Sol redteam findings register

This is the audit-closure artifact for the Sol redteam review (`agents/governator-sol-upgrade2.md`, 2026-07) and its repair program, executed as seven sessions (`Sol redteam repair S1`–`S7`) against Governator HEAD `ad897aa` plus one Assayer session. Every finding below reproduces against the pre-repair binary per Sol's audit; each row records the fix commit and the regression test(s) that prove the fail-closed outcome. See [docs/containment.md](containment.md) for the containment model these fixes establish and [docs/claims.md](claims.md) for how `docs/claims.yaml`'s `sol-s*` entries mechanically re-derive several of these from the repository.

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
| High 11 | Nonblocking output truncation could hide later actions on a capped-but-continuing transcript | **Partially fixed** — see below | Docker-side loud truncation (accept/discard accounting, `OUTPUT_TRUNCATED` stage, blocking under `require_complete_transcript`) predates this repair (`loud-output-truncation` claim, v1.4-session3) and stayed in place. **Not fixed:** local-runner output capping was never implemented — `LocalWorktreeRunner.Launch` has no capping writer, so a local run's transcript is not size-bounded the way a Docker run's is. No test exists because no cap exists. See [docs/containment.md](containment.md#known-gap) |
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

- **High 11 (local output capping)** is not fully closed — see the table above and [docs/containment.md](containment.md#known-gap).
- **HMAC-only release signing.** `scripts/release.sh`'s `manifest_hmac_sha256` (when `GOV_RELEASE_HMAC_KEY` is set) is write-only provenance today — `gov claims verify` does not yet verify it. No asymmetric signing (minisign/ed25519) exists for release manifests. Documented as the current trust root in [docs/claims.md](claims.md#release-artifact-provenance), not a defect, but not a strong signing guarantee either.
- **Sol §9 (P3 strategic enhancements)** — external backend adapter protocol, a capability-attestation registry beyond the current per-backend attestation, versioned harness profile registry, profile-plus-backend routing, panel independence across provider/account/model lineage/prompt/policy, an offline Governator Evolver Lab, and profile drift detection with champion/challenger promotion remain unbuilt roadmap items, not defects. See the README roadmap section.
