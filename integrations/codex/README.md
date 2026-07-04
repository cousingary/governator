# Codex integration

Codex has no PreToolUse hook surface. Governator projects the contract to Codex's
native `--sandbox` and `--ask-for-approval` controls, runs in a disposable
worktree, and performs mandatory pre/post fingerprint scans. The fingerprint
floor detects worktree, live-root, and protected-path mutations even when a
backend transcript is incomplete.

Use `gov run <job.yaml> --agent codex`; do not add a shim that claims to veto
individual Codex tool calls.
