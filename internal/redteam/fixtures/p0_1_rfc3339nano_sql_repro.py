#!/usr/bin/env python3
"""Reproduce Sol14 P0-1 against SQLite using rc6's exact predicates."""

from __future__ import annotations

import json
import sqlite3


WHOLE = "2026-07-28T00:00:00Z"
FRACTIONAL = "2026-07-28T00:00:00.5Z"


def main() -> int:
    db = sqlite3.connect(":memory:")
    db.executescript(
        """
        CREATE TABLE policy_overrides (
          id INTEGER PRIMARY KEY, scope_key TEXT, target TEXT, verdict TEXT,
          reason TEXT, created_by TEXT, created_at TEXT, expires_at TEXT,
          one_shot INTEGER, consumed_at TEXT DEFAULT '',
          reserved_at TEXT DEFAULT '', expired_at TEXT DEFAULT ''
        );
        CREATE TABLE maintenance_outbox (
          id INTEGER PRIMARY KEY, status TEXT, lease_until TEXT
        );
        CREATE TABLE spend_reservations (
          id INTEGER PRIMARY KEY, status TEXT, expires_at TEXT, settled_at TEXT
        );
        CREATE TABLE quota_reservations (
          id INTEGER PRIMARY KEY, settled_at TEXT, expires_at TEXT
        );
        CREATE TABLE quota_windows (
          backend TEXT, account TEXT, window_type TEXT, reset_at TEXT,
          window_started_at TEXT, measured_usage REAL, reserved_usage REAL,
          updated_at TEXT
        );
        """
    )

    db.executemany(
        """INSERT INTO policy_overrides
           (scope_key,target,verdict,reason,created_by,created_at,expires_at,one_shot)
           VALUES ('scope','rule',?,'fixture','operator',?,'',0)""",
        (("ALLOW", WHOLE), ("DENY", FRACTIONAL)),
    )
    ordered = [
        row[0]
        for row in db.execute(
            """SELECT verdict FROM policy_overrides
               WHERE scope_key=? AND (expires_at='' OR expires_at>?)
                 AND consumed_at='' AND expired_at='' AND reserved_at=''
               ORDER BY created_at DESC, id DESC""",
            ("scope", FRACTIONAL),
        )
    ]
    if ordered != ["ALLOW", "DENY"]:
        raise SystemExit(f"ordering defect did not reproduce: {ordered}")

    db.execute(
        """INSERT INTO policy_overrides
           (scope_key,target,verdict,reason,created_by,created_at,expires_at,one_shot)
           VALUES ('expiry','rule','ALLOW','fixture','operator',?,?,0)""",
        (WHOLE, WHOLE),
    )
    expired_still_active = db.execute(
        """SELECT verdict FROM policy_overrides
           WHERE scope_key=? AND (expires_at='' OR expires_at>?)
             AND consumed_at='' AND expired_at='' AND reserved_at=''
           ORDER BY created_at DESC, id DESC""",
        ("expiry", FRACTIONAL),
    ).fetchall()
    if expired_still_active != [("ALLOW",)]:
        raise SystemExit(f"expiry defect did not reproduce: {expired_still_active}")

    db.execute(
        """INSERT INTO policy_overrides
           (scope_key,target,verdict,reason,created_by,created_at,expires_at,
            one_shot,reserved_at)
           VALUES ('reservation','rule','ALLOW','fixture','operator',?,'',1,?)""",
        (WHOLE, WHOLE),
    )
    db.execute(
        """UPDATE policy_overrides SET expired_at=?
           WHERE one_shot=1 AND consumed_at='' AND expired_at=''
             AND reserved_at<>'' AND reserved_at<?""",
        (FRACTIONAL, FRACTIONAL),
    )
    reservation_expired_at = db.execute(
        "SELECT expired_at FROM policy_overrides WHERE scope_key='reservation'"
    ).fetchone()[0]
    if reservation_expired_at != "":
        raise SystemExit("stale one-shot reservation was unexpectedly reclaimed")

    db.execute(
        "INSERT INTO maintenance_outbox VALUES (1,'processing',?)", (FRACTIONAL,)
    )
    reclaimed_lease = db.execute(
        """SELECT id FROM maintenance_outbox
           WHERE status='pending'
              OR (status='processing' AND lease_until<>'' AND lease_until<?)""",
        (WHOLE,),
    ).fetchall()
    if reclaimed_lease != [(1,)]:
        raise SystemExit(f"outbox lease defect did not reproduce: {reclaimed_lease}")

    db.execute(
        "INSERT INTO spend_reservations VALUES (1,'pending',?,'')", (FRACTIONAL,)
    )
    db.execute(
        """UPDATE spend_reservations SET status='expired', settled_at=?
           WHERE status='pending' AND expires_at<>'' AND expires_at<?""",
        (WHOLE, WHOLE),
    )
    if db.execute("SELECT status FROM spend_reservations").fetchone()[0] != "expired":
        raise SystemExit("spend expiry defect did not reproduce")

    db.execute(
        "INSERT INTO quota_reservations VALUES (1,'',?)", (FRACTIONAL,)
    )
    stale_quota = db.execute(
        """SELECT id FROM quota_reservations
           WHERE settled_at='' AND expires_at<>'' AND expires_at<?""",
        (WHOLE,),
    ).fetchall()
    if stale_quota != [(1,)]:
        raise SystemExit(f"quota reservation defect did not reproduce: {stale_quota}")

    db.execute(
        """INSERT INTO quota_windows VALUES
           ('backend','account','minute',?,'start',7,3,'updated')""",
        (FRACTIONAL,),
    )
    rollover_keys = db.execute(
        """SELECT backend,account,window_type FROM quota_windows
           WHERE reset_at<>'' AND reset_at<=?""",
        (WHOLE,),
    ).fetchall()
    for backend, account, window_type in rollover_keys:
        db.execute(
            """UPDATE quota_windows
               SET window_started_at=?, reset_at=?,
                   measured_usage=0, reserved_usage=0, updated_at=?
               WHERE backend=? AND account=? AND window_type=?""",
            ("new-start", "new-reset", WHOLE, backend, account, window_type),
        )
    usage = db.execute(
        "SELECT measured_usage,reserved_usage FROM quota_windows"
    ).fetchone()
    if rollover_keys != [("backend", "account", "minute")] or usage != (0.0, 0.0):
        raise SystemExit(
            f"quota rollover defect did not reproduce: keys={rollover_keys} usage={usage}"
        )

    print(
        json.dumps(
            {
                "older_allow_returned_first": True,
                "expired_allow_returned_active": True,
                "stale_one_shot_not_reclaimed": True,
                "active_outbox_lease_reclaimed": True,
                "valid_spend_reservation_expired": True,
                "valid_quota_reservation_selected_stale": True,
                "future_quota_window_zeroed": True,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
