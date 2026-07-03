# Governator

Governator is a contract-first runtime for replaceable coding-agent backends. The model proposes; the governor disposes; deterministic validators decide; the ledger remembers.

## Current delivery

Phase 0 provides:

- strict `job.yaml` parsing with field-level validation;
- mode and worktree constraints;
- relative file-scope validation;
- literal-secret rejection;
- `gov validate`;
- `gov doctor`, including the shared Python-harness protected-path manifest;
- a statically linked Linux binary build.

The existing Python governed harness remains the live safety plane. Governator does not replace it.

## Canonical Phase 0 commands

```bash
PATH=/home/lam/.local/go1.26.4/bin:$PATH
go test -v /mnt/e/downloads/governator/...
go build -trimpath -o /mnt/e/downloads/governator/bin/gov /mnt/e/downloads/governator/cmd/gov
/mnt/e/downloads/governator/bin/gov validate /mnt/e/downloads/governator/examples/jobs/clipart_regen.yaml
/mnt/e/downloads/governator/bin/gov doctor
```

`gov doctor` reads `/home/lam/.governed-harness/state/protected_paths.txt` by default. Set `GOV_PROTECTED_PATHS` only when testing an alternate manifest.

## Next milestone

Phase 1 adds the end-to-end `gov run` spine: prompt compilation, isolated worktrees, the Claude adapter, process-group timeout control, live-workspace fingerprinting, out-of-process validators, SQLite ledger records, merge gating, quarantine, and rollback.
