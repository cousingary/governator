"""Durable local outbox for blocking evidence that must never be silently
lost.

Sol audit Assayer weakness 5 ("persistence fallback can disappear
silently"): the old `Store.fallback()` wrote a best-effort JSONL line
inside a bare `except Exception: pass`, so a primary-insert failure
followed by a fallback-write failure (disk full, bad permissions, ...)
vanished without a trace. That is acceptable for optional telemetry
(trace()) but not for quarantine evidence, which is the one artifact that
lets a human recover a pipeline's rejected output later — losing it is
losing the item.

This module gives quarantine evidence its own durable path: file locking
(so concurrent writers don't interleave/corrupt lines), 0600 perms, fsync
before returning, size-based rotation, and a replay() that retries pending
entries against a live Store, moving anything that repeatedly fails to a
dead-letter file instead of retrying it forever.
"""

import fcntl
import json
import os
import time
import uuid

# TUNABLE
DEFAULT_OUTBOX_PATH = "/opt/assayer/quarantine_outbox.jsonl"
# TUNABLE: rotate the active outbox file once it exceeds this size.
DEFAULT_MAX_BYTES = 10 * 1024 * 1024
# TUNABLE: after this many failed replay attempts, an entry is dead-lettered
# instead of retried again.
DEFAULT_MAX_ATTEMPTS = 5


class OutboxError(Exception):
    """Raised when an entry cannot even be durably queued (e.g. disk full,
    permission denied). Deliberately loud: a caller catching this must treat
    it as evidence loss, never swallow it silently."""


class Outbox:
    def __init__(self, path=None, max_bytes=DEFAULT_MAX_BYTES, max_attempts=DEFAULT_MAX_ATTEMPTS):
        self.path = path or os.environ.get("ASSAYER_OUTBOX", DEFAULT_OUTBOX_PATH)
        self.dead_letter_path = self.path + ".deadletter"
        self.max_bytes = max_bytes
        self.max_attempts = max_attempts

    def enqueue(self, table_hint, row):
        """Durably append one entry and return its outbox id. Raises
        OutboxError if the entry cannot be written at all."""
        entry = {
            "id": str(uuid.uuid4()),
            "queued_at": time.time(),
            "table_hint": table_hint,
            "row": row,
            "attempts": 0,
            "status": "pending",
        }
        try:
            self._rotate_if_needed()
            self._append_locked(self.path, entry)
        except OSError as exc:
            raise OutboxError(f"failed to durably queue outbox entry: {exc}") from exc
        return entry["id"]

    def pending(self):
        return [e for e in self._read_all(self.path) if e.get("status") == "pending"]

    def dead_letters(self):
        return self._read_all(self.dead_letter_path)

    def replay(self, store):
        """Attempt to persist every pending entry to `store`. Entries that
        succeed are dropped from the outbox; entries that fail are
        re-queued with an incremented attempt count, or moved to the
        dead-letter file once max_attempts is exceeded.

        Returns (n_replayed, n_still_pending, n_dead_lettered)."""
        entries = self._read_all(self.path)
        remaining = []
        replayed = 0
        dead_lettered = 0

        for entry in entries:
            if entry.get("status") != "pending":
                remaining.append(entry)
                continue
            try:
                if entry.get("table_hint") == "assayer_quarantine":
                    store.insert_quarantine(entry["row"])
                else:
                    store.insert_trace(entry["row"])
                replayed += 1
            except Exception:
                entry["attempts"] = entry.get("attempts", 0) + 1
                if entry["attempts"] >= self.max_attempts:
                    entry["status"] = "dead_letter"
                    self._append_locked(self.dead_letter_path, entry)
                    dead_lettered += 1
                else:
                    remaining.append(entry)

        self._rewrite_locked(self.path, remaining)
        return replayed, len(remaining), dead_lettered

    def _rotate_if_needed(self):
        try:
            size = os.path.getsize(self.path)
        except OSError:
            return
        if size < self.max_bytes:
            return
        rotated = f"{self.path}.{int(time.time())}"
        os.replace(self.path, rotated)

    def _ensure_parent(self, path):
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)

    def _append_locked(self, path, entry):
        self._ensure_parent(path)
        fd = os.open(path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                os.write(fd, (json.dumps(entry, default=str) + "\n").encode("utf-8"))
                os.fsync(fd)
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def _read_all(self, path):
        if not os.path.exists(path):
            return []
        entries = []
        fd = os.open(path, os.O_RDONLY)
        try:
            fcntl.flock(fd, fcntl.LOCK_SH)
            try:
                with os.fdopen(fd, "r", closefd=False) as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entries.append(json.loads(line))
                        except Exception:
                            continue
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)
        return entries

    def _rewrite_locked(self, path, entries):
        self._ensure_parent(path)
        tmp_path = path + ".tmp"
        fd = os.open(tmp_path, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                for entry in entries:
                    os.write(fd, (json.dumps(entry, default=str) + "\n").encode("utf-8"))
                os.fsync(fd)
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)
        os.replace(tmp_path, path)
