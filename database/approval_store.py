import sqlite3
import uuid

from datetime import datetime, timedelta, timezone
from pathlib import Path


DB_PATH = Path(__file__).resolve().parent / "agentgate.db"


class ApprovalStore:
    """Persistent approval requests with expiry and one-time decisions."""

    def __init__(self, db_path=DB_PATH, expiry_minutes=15):
        self.db_path = str(db_path)
        self.expiry_minutes = expiry_minutes
        self._initialize()

    def _connect(self):
        db = sqlite3.connect(self.db_path, timeout=10)
        db.row_factory = sqlite3.Row
        return db

    def _initialize(self):
        with self._connect() as db:
            db.execute("""
                CREATE TABLE IF NOT EXISTS approval_requests (
                    id TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    resource TEXT NOT NULL,
                    recipient TEXT NOT NULL,
                    data_label TEXT NOT NULL,
                    status TEXT NOT NULL
                        CHECK(status IN (
                            'PENDING', 'APPROVED', 'REJECTED', 'EXPIRED'
                        )),
                    reviewed_by TEXT,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                )
            """)

    @staticmethod
    def _request_fields(request):
        from security.labels import SecurityLabel

        return (
            request.agent_id,
            request.operation,
            request.resource,
            request.recipient,
            SecurityLabel.parse(request.data_label).name,
        )

    def create(self, request):
        fields = self._request_fields(request)
        now = datetime.now(timezone.utc)
        expires = now + timedelta(minutes=self.expiry_minutes)
        approval_id = str(uuid.uuid4())

        with self._connect() as db:
            db.execute("""
                INSERT INTO approval_requests (
                    id, agent_id, operation, resource, recipient,
                    data_label, status, created_at, expires_at
                )
                VALUES (?, ?, ?, ?, ?, ?, 'PENDING', ?, ?)
            """, (
                approval_id, *fields, now.isoformat(), expires.isoformat()
            ))

        return self.get(approval_id)

    def get(self, approval_id):
        try:
            approval_id = str(uuid.UUID(str(approval_id)))
        except (ValueError, TypeError, AttributeError):
            raise ValueError("Invalid approval ID")

        with self._connect() as db:
            row = db.execute(
                "SELECT * FROM approval_requests WHERE id = ?",
                (approval_id,),
            ).fetchone()

        if row is None:
            raise ValueError("Approval request not found")

        return dict(row)

    def list_pending(self, limit=100):
        if not isinstance(limit, int) or isinstance(limit, bool):
            raise ValueError("Invalid limit")
        if not 1 <= limit <= 1000:
            raise ValueError("Limit must be between 1 and 1000")

        now = datetime.now(timezone.utc).isoformat()

        with self._connect() as db:
            db.execute("""
                UPDATE approval_requests
                SET status = 'EXPIRED'
                WHERE status = 'PENDING' AND expires_at <= ?
            """, (now,))

            rows = db.execute("""
                SELECT * FROM approval_requests
                WHERE status = 'PENDING'
                ORDER BY created_at DESC
                LIMIT ?
            """, (limit,)).fetchall()

        return [dict(row) for row in rows]

    def review(self, approval_id, decision, reviewer_id):
        try:
            approval_id = str(uuid.UUID(str(approval_id)))
            reviewer_id = str(uuid.UUID(str(reviewer_id)))
        except (ValueError, TypeError, AttributeError):
            raise ValueError("Approval ID and reviewer ID must be valid UUIDs")

        if decision not in ("APPROVED", "REJECTED"):
            raise ValueError("Decision must be APPROVED or REJECTED")

        now = datetime.now(timezone.utc).isoformat()

        with self._connect() as db:
            cursor = db.execute("""
                UPDATE approval_requests
                SET status = ?, reviewed_by = ?
                WHERE id = ?
                  AND status = 'PENDING'
                  AND expires_at > ?
            """, (decision, reviewer_id, approval_id, now))

            if cursor.rowcount != 1:
                raise ValueError(
                    "Approval is missing, expired, or already reviewed"
                )

        return self.get(approval_id)

    def consume_approved(self, approval_id, request):
        """Atomically consume an approved ticket once, bound to its exact action."""
        import uuid

        try:
            approval_id = str(uuid.UUID(str(approval_id)))
        except (ValueError, TypeError, AttributeError):
            raise ValueError("Invalid approval ID")

        expected_fields = self._request_fields(request)
        now = datetime.now(timezone.utc).isoformat()

        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")

            row = db.execute(
                "SELECT * FROM approval_requests WHERE id = ?",
                (approval_id,),
            ).fetchone()

            if row is None:
                raise ValueError("Approval not found or already consumed")

            actual_fields = (
                row["agent_id"],
                row["operation"],
                row["resource"],
                row["recipient"],
                row["data_label"],
            )

            if actual_fields != expected_fields:
                raise ValueError("Approval does not match this exact action")

            if row["status"] != "APPROVED":
                raise ValueError("Approval is not approved")

            if row["expires_at"] <= now:
                db.execute(
                    "UPDATE approval_requests SET status = 'EXPIRED' "
                    "WHERE id = ? AND status = 'APPROVED'",
                    (approval_id,),
                )
                raise ValueError("Approval has expired")

            deleted = db.execute(
                "DELETE FROM approval_requests "
                "WHERE id = ? AND status = 'APPROVED' AND expires_at > ?",
                (approval_id, now),
            ).rowcount

            if deleted != 1:
                raise ValueError("Approval could not be consumed")

            return dict(row)
