
import sqlite3

from gateway import SecureGateway
from security.policy_engine import (
    ActionRequest,
    Decision,
    PolicyEngine,
    demo_policy,
)


def read_events(db_path):
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM audit_events ORDER BY id ASC"
        ).fetchall()

    return [dict(row) for row in rows]


def test_gateway_persists_pending_and_success_to_sqlite(tmp_path):
    from database.db import init_db

    db_path = tmp_path / "gateway_audit.db"

    # Redirect the audit database to an isolated test database.
    import database.db as db_module

    original_path = db_module.DB_PATH
    db_module.DB_PATH = db_path

    try:
        init_db()

        called = []
        gateway = SecureGateway(PolicyEngine(demo_policy()))
        gateway.register_tool(
            "read",
            "documents",
            lambda: called.append("executed"),
        )

        request = ActionRequest(
            "research-agent", "read", "documents"
        )

        result = gateway.execute(request)

        assert result.decision == Decision.ALLOW
        assert called == ["executed"]

        events = read_events(db_path)

        assert [event["execution_status"] for event in events] == [
            "PENDING", "SUCCESS"
        ]
        assert all(event["decision"] == "ALLOW" for event in events)
        assert events[0]["reason"] == "Authorized action; execution pending"
        assert events[1]["reason"] == "Tool execution completed"

    finally:
        db_module.DB_PATH = original_path


def test_gateway_persists_blocked_action_without_execution(tmp_path):
    from database.db import init_db
    import database.db as db_module

    db_path = tmp_path / "blocked_audit.db"

    original_path = db_module.DB_PATH
    db_module.DB_PATH = db_path

    try:
        init_db()

        called = []
        gateway = SecureGateway(PolicyEngine(demo_policy()))
        gateway.register_tool(
            "deliver",
            "inbox",
            lambda: called.append("executed"),
        )

        request = ActionRequest(
            "unknown-agent",
            "deliver",
            "inbox",
            "attacker@example.com",
            "PUBLIC",
        )

        result = gateway.execute(request)

        assert result.decision == Decision.BLOCK
        assert called == []

        events = read_events(db_path)

        assert len(events) == 1
        assert events[0]["decision"] == "BLOCK"
        assert events[0]["execution_status"] == "NOT_EXECUTED"
        assert events[0]["recipient"] == "attacker@example.com"
        assert events[0]["reason"] == "Agent operation not authorized"

    finally:
        db_module.DB_PATH = original_path
