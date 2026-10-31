"""Trusted permission overrides for the AGENTGATE control plane.

The base policy profiles are code-owned. This store only ever *tightens*
them: revoking an agent operation, disabling a resource operation,
de-authorizing a recipient, or adding an approval requirement. Granting
anything new is not representable, so no untrusted writer - and no UI
toggle - can widen access beyond the profile.

Deleting an override restores the profile baseline. Overrides are applied
whenever a gateway is constructed, and every change is audited by the caller.
"""

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "agentgate.db"

AGENT_OPERATION = "agent_operation"      # key = agent id,   value = operation
RESOURCE_OPERATION = "resource_operation"  # key = resource, value = operation
RECIPIENT = "recipient"                  # key = recipient
APPROVAL_OPERATION = "approval_operation"  # key = operation

KINDS = (AGENT_OPERATION, RESOURCE_OPERATION, RECIPIENT, APPROVAL_OPERATION)

_VALUE_REQUIRED = (AGENT_OPERATION, RESOURCE_OPERATION)


class PermissionStore:
    def __init__(self, db_path=DB_PATH):
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

        with self._connect() as db:
            db.execute("""
                CREATE TABLE IF NOT EXISTS permission_overrides (
                    kind TEXT NOT NULL,
                    key TEXT NOT NULL,
                    value TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    PRIMARY KEY (kind, key, value)
                )
            """)

    def _connect(self):
        db = sqlite3.connect(self.db_path, timeout=10)
        db.row_factory = sqlite3.Row
        return db

    @staticmethod
    def _validate(kind, key, value):
        if kind not in KINDS:
            raise ValueError("Unknown permission override kind")

        if not isinstance(key, str) or not key.strip():
            raise ValueError("Permission override target is required")

        if not isinstance(value, str):
            raise ValueError("Permission override operation is required")

        if kind in _VALUE_REQUIRED and not value.strip():
            raise ValueError("Permission override operation is required")

        if kind not in _VALUE_REQUIRED and value.strip():
            raise ValueError("This override kind takes no operation")

        return key.strip(), value.strip()

    def add_override(self, kind, key, value, reviewer_id):
        """Record a tightening override. Only ever narrows the profile."""
        if not isinstance(reviewer_id, str) or not reviewer_id.strip():
            raise ValueError("A reviewer identity is required")

        key, value = self._validate(kind, key, value)

        with self._connect() as db:
            db.execute("""
                INSERT INTO permission_overrides
                    (kind, key, value, created_at, created_by)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(kind, key, value) DO UPDATE SET
                    created_at = excluded.created_at,
                    created_by = excluded.created_by
            """, (
                kind, key, value,
                datetime.now(timezone.utc).isoformat(), reviewer_id.strip(),
            ))

        return {"kind": kind, "key": key, "value": value}

    def remove_override(self, kind, key, value, reviewer_id):
        """Restore the profile baseline for one override."""
        if not isinstance(reviewer_id, str) or not reviewer_id.strip():
            raise ValueError("A reviewer identity is required")

        key, value = self._validate(kind, key, value)

        with self._connect() as db:
            deleted = db.execute(
                "DELETE FROM permission_overrides "
                "WHERE kind = ? AND key = ? AND value = ?",
                (kind, key, value),
            ).rowcount

        if deleted != 1:
            raise ValueError("No such permission override to remove")

        return {"kind": kind, "key": key, "value": value}

    def list_overrides(self):
        with self._connect() as db:
            rows = db.execute(
                "SELECT * FROM permission_overrides ORDER BY kind, key, value"
            ).fetchall()
        return [dict(row) for row in rows]


def apply_overrides(policy, overrides):
    """Return a policy narrowed by the stored tightening overrides."""
    for override in overrides:
        kind = override.get("kind")
        key = str(override.get("key") or "").strip()
        value = str(override.get("value") or "").strip()

        if kind == AGENT_OPERATION:
            operations = policy.agent_permissions.get(key)
            if operations is not None:
                operations.discard(value)
        elif kind == RESOURCE_OPERATION:
            operations = policy.resource_permissions.get(key)
            if operations is not None:
                operations.discard(value)
        elif kind == RECIPIENT:
            policy.authorized_recipients.discard(key)
            policy.recipient_clearance.pop(key, None)
        elif kind == APPROVAL_OPERATION:
            if value or not key:
                raise ValueError("Malformed approval override")
            policy.approval_required_operations.add(key)

    return policy
