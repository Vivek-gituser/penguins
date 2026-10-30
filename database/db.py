import sqlite3
from pathlib import Path
from datetime import datetime, timezone

from database.models import AuditEvent

DB_PATH = Path(__file__).resolve().parent / "agentgate.db"


def connect():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    return db


def init_db():
    with connect() as db:
        db.execute("""
        CREATE TABLE IF NOT EXISTS audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            operation TEXT NOT NULL,
            resource TEXT NOT NULL,
            recipient TEXT,
            data_label TEXT NOT NULL,
            decision TEXT NOT NULL,
            reason TEXT NOT NULL,
            execution_status TEXT NOT NULL
        )
        """)


def write_audit_event(req, decision, reason, status):
    event = AuditEvent(
        timestamp=datetime.now(timezone.utc),
        agent_id=req.agent_id,
        operation=req.operation,
        resource=req.resource,
        recipient=req.recipient,
        data_label=str(req.data_label),
        decision=decision,
        reason=reason,
        execution_status=status,
    )

    with connect() as db:
        db.execute("""
        INSERT INTO audit_events (
            timestamp, agent_id, operation, resource,
            recipient, data_label, decision, reason, execution_status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event.timestamp.isoformat(),
            event.agent_id,
            event.operation,
            event.resource,
            event.recipient,
            event.data_label,
            event.decision,
            event.reason,
            event.execution_status,
        ))


def list_audit_events(limit=100):
    with connect() as db:
        rows = db.execute(
            "SELECT * FROM audit_events ORDER BY id DESC LIMIT ?",
            (limit,)
        ).fetchall()
        return [dict(row) for row in rows]
