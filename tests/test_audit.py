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
from database.db import init_db, write_audit_event, list_audit_events
from security.policy_engine import ActionRequest


def test_audit_records_allow_and_block_decisions():
    init_db()

    allowed = ActionRequest(
        "research-agent", "read", "documents", data_label="INTERNAL"
    )
    blocked = ActionRequest(
        "unknown-agent", "deliver", "inbox",
        "attacker@example.com", "CONFIDENTIAL"
    )

    write_audit_event(allowed, "ALLOW", "Policy passed", "SUCCESS")
    write_audit_event(blocked, "BLOCK", "Unknown agent", "NOT_EXECUTED")

    events = list_audit_events(2)

    assert events[0]["decision"] == "BLOCK"
    assert events[0]["execution_status"] == "NOT_EXECUTED"
    assert events[0]["reason"] == "Unknown agent"

    assert events[1]["decision"] == "ALLOW"
    assert events[1]["execution_status"] == "SUCCESS"


def test_audit_records_recipient_and_sensitivity():
    init_db()

    request = ActionRequest(
        "research-agent", "deliver", "inbox",
        "public@example.com", "CONFIDENTIAL"
    )

    write_audit_event(
        request, "BLOCK", "Information-flow violation", "NOT_EXECUTED"
    )

    event = list_audit_events(1)[0]

    assert event["recipient"] == "public@example.com"
    assert event["data_label"] == "2"
    assert event["reason"] == "Information-flow violation"
