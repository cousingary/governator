# Governator

Governator is a contract-first runtime for replaceable coding-agent backends. The model proposes; deterministic validators and the merge gate decide; the SQLite ledger remembers.

## Implemented through Phase 2

Phase 1 provides the complete user-triggered `gov run` spine:

- strict sovereign job contracts and mode-aware prompt compilation;
- isolated Git worktrees, with copy-on-write non-Git workspaces;
- a generic agent ABI and headless Claude Code adapter;
- process-group timeouts and transcript capture with secret redaction;
- command-policy transcript auditing and out-of-process validators;
- pre/post fingerprints of the live root and protected-path manifest;
- diff scope, forbidden-path, deletion, and file-count merge gates;
- SQLite run, validator, and violation records;
- squash merge commits with `Gov-Run` trailers;
- quarantine inspection, idempotent approved replay, and Git/non-Git rollback.

Phase 2 hardens policy before and during execution:

- explicit intended-write declarations and preflight reports;
- LOW/MED/HIGH/BLOCKED blast-radius estimates, with scout or approval required for HIGH;
- the ported destructive-command classifier;
- file, changed-line, new-file, and zero-deletion budgets;
- controller canaries and scope-expansion transcript tripwires;
- quarantine without merge when any Phase 2 contract is violated.

The existing Python governed harness remains untouched and is still the control plane for Codex sessions. Governator does not replace it.

## Canonical commands

```bash
PATH=/home/lam/.local/go1.26.4/bin:$PATH
cd /mnt/e/downloads/governator
go test -v ./...
go build -trimpath -o /mnt/e/downloads/governator/bin/gov ./cmd/gov
/mnt/e/downloads/governator/bin/gov validate /mnt/e/downloads/governator/examples/jobs/clipart_regen.yaml
/mnt/e/downloads/governator/bin/gov preflight /mnt/e/downloads/governator/examples/jobs/code_surgical_fix.yaml
/mnt/e/downloads/governator/bin/gov doctor
/mnt/e/downloads/governator/bin/gov run /absolute/path/to/job.yaml
/mnt/e/downloads/governator/bin/gov diff last
/mnt/e/downloads/governator/bin/gov quarantine list
/mnt/e/downloads/governator/bin/gov rollback RUN_ID
```

The Claude adapter uses the installed subscription-authenticated `claude` CLI and never embeds an API key. `GOV_CLAUDE_BIN` exists for deterministic adapter tests. State defaults to `$HOME/.governator`; `GOV_HOME` may redirect it for tests.

Protected paths are read from `/home/lam/.governed-harness/state/protected_paths.txt`. Set `GOV_PROTECTED_PATHS` only for an alternate test manifest.

Running a real job can invoke a paid model and must be explicitly user-triggered. The test suite uses a fake Claude executable and performs no model calls.
