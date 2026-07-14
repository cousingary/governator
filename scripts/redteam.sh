#!/usr/bin/env bash
# Sol redteam v4 S0: runs the permanent black-box attack corpus
# (internal/redteam/, tag `redteam`) built from
# agents/governator-sol-upgrade4.md §9. The skip count printed at the end
# is the project burn-down (agents/governator-sol-upgrade4-plan.md) — as
# each session's fix lands, that session's t.Skip("expected-fail until
# S<n>") calls come off.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

go test -tags redteam -count=1 -v ./internal/redteam/...
