from database.db import init_db, write_audit_event, list_audit_events
from security.policy_engine import ActionRequest

def test_audit_is_persisted():
    init_db()
    req = ActionRequest("test-agent", "read", "documents", data_label="INTERNAL")
    write_audit_event(req, "BLOCK", "test", "NOT_EXECUTED")
    assert list_audit_events(1)[0]["agent_id"] == "test-agent"
