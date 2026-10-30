from database.db import init_db, write_audit_event, list_audit_events
from security.policy_engine import ActionRequest

def test_audit_contains_reason_and_status():
    init_db()
    req = ActionRequest("audit-agent", "read", "documents")
    write_audit_event(req, "BLOCK", "unknown agent", "NOT_EXECUTED")
    event = list_audit_events(1)[0]
    assert event["decision"] == "BLOCK"
    assert event["reason"]
    assert event["execution_status"] == "NOT_EXECUTED"
