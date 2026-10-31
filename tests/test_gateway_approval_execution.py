import sqlite3
import uuid

import pytest

from database.approval_store import ApprovalStore
from gateway import SecureGateway
from security.labels import SecurityLabel
from security.policy_engine import (
    ActionRequest,
    Decision,
    PolicyEngine,
    demo_policy,
)


class MemoryAudit:
    def __init__(self):
        self.events = []

    def write_audit_event(self, request, decision, reason, status):
        self.events.append(
            {
                "request": request,
                "decision": decision,
                "reason": reason,
                "status": status,
            }
        )


class FailingAudit(MemoryAudit):
    def write_audit_event(self, request, decision, reason, status):
        raise RuntimeError("audit unavailable")


class FailingApprovalStore:
    def create(self, request):
        raise RuntimeError("approval storage unavailable")

    def consume_approved(self, approval_id, request):
        raise AssertionError("must never be reached")


def deliver_request(recipient="team@example.com", label="INTERNAL"):
    return ActionRequest(
        "research-agent", "deliver", "inbox", recipient, label
    )


def build(tmp_path, policy=None, tool_operation="deliver", audit=None):
    policy = policy or demo_policy()
    store = ApprovalStore(db_path=tmp_path / "approvals.db")
    audit = audit or MemoryAudit()
    gateway = SecureGateway(
        PolicyEngine(policy),
        audit_repository=audit,
        approval_store=store,
    )
    calls = []
    if tool_operation == "deliver":
        gateway.register_tool(
            "deliver",
            "inbox",
            lambda: calls.append("executed") or {"status": "delivered"},
        )
    return gateway, store, audit, calls, policy


def approve(store, approval_id):
    return store.review(approval_id, "APPROVED", str(uuid.uuid4()))


def test_policy_requires_approval_before_any_delivery(tmp_path):
    gateway, store, audit, calls, _ = build(tmp_path)

    outcome = gateway.execute(deliver_request())

    assert outcome.decision == Decision.REQUIRE_APPROVAL
    assert calls == []
    assert outcome.approval_id
    assert len(store.list_pending()) == 1
    assert audit.events[-1]["decision"] == "REQUIRE_APPROVAL"
    assert audit.events[-1]["status"] == "NOT_EXECUTED"
    assert outcome.approval_id in audit.events[-1]["reason"]


def test_pending_approval_is_never_executed_by_execute(tmp_path):
    gateway, _, _, calls, _ = build(tmp_path)

    gateway.execute(deliver_request())

    assert calls == []


def test_approved_action_rechecks_policy_and_executes_once(tmp_path):
    gateway, store, audit, calls, _ = build(tmp_path)

    pending = gateway.execute(deliver_request())
    approve(store, pending.approval_id)

    result = gateway.approve_and_execute(pending.approval_id, deliver_request())

    assert result.decision == Decision.ALLOW
    assert result.result == {"status": "delivered"}
    assert calls == ["executed"]
    assert audit.events[-1]["status"] == "SUCCESS"
    assert "reviewer" in audit.events[-2]["reason"]


def test_unreviewed_approval_never_executes(tmp_path):
    gateway, _, audit, calls, _ = build(tmp_path)

    pending = gateway.execute(deliver_request())
    result = gateway.approve_and_execute(pending.approval_id, deliver_request())

    assert result.decision == Decision.BLOCK
    assert calls == []
    assert audit.events[-1]["status"] == "NOT_EXECUTED"


def test_rejected_approval_never_executes(tmp_path):
    gateway, store, audit, calls, _ = build(tmp_path)

    pending = gateway.execute(deliver_request())
    reviewer = str(uuid.uuid4())

    rejected = gateway.reject_approval(pending.approval_id, reviewer)

    assert rejected.decision == Decision.BLOCK
    assert audit.events[-1]["status"] == "REJECTED"
    assert reviewer[:8] in audit.events[-1]["reason"]

    replay = gateway.approve_and_execute(pending.approval_id, deliver_request())

    assert replay.decision == Decision.BLOCK
    assert calls == []
    assert store.get(pending.approval_id)["status"] == "REJECTED"


def test_rejection_requires_a_reviewer_identity(tmp_path):
    gateway, store, _, _, _ = build(tmp_path)
    pending = gateway.execute(deliver_request())

    with pytest.raises(ValueError):
        gateway.reject_approval(pending.approval_id, "")

    assert store.get(pending.approval_id)["status"] == "PENDING"


def test_approved_ticket_cannot_be_replayed(tmp_path):
    gateway, store, _, calls, _ = build(tmp_path)

    pending = gateway.execute(deliver_request())
    approve(store, pending.approval_id)

    first = gateway.approve_and_execute(pending.approval_id, deliver_request())
    second = gateway.approve_and_execute(pending.approval_id, deliver_request())

    assert first.decision == Decision.ALLOW
    assert second.decision == Decision.BLOCK
    assert calls == ["executed"]


def test_expired_approval_cannot_execute(tmp_path):
    gateway, store, _, calls, _ = build(tmp_path)

    pending = gateway.execute(deliver_request())
    approve(store, pending.approval_id)

    with sqlite3.connect(str(store.db_path)) as db:
        db.execute(
            "UPDATE approval_requests SET expires_at = ? WHERE id = ?",
            ("2000-01-01T00:00:00+00:00", pending.approval_id),
        )

    result = gateway.approve_and_execute(pending.approval_id, deliver_request())

    assert result.decision == Decision.BLOCK
    assert calls == []


def test_approval_cannot_authorize_a_different_action(tmp_path):
    gateway, store, _, calls, _ = build(tmp_path)

    pending = gateway.execute(deliver_request(label="INTERNAL"))
    approve(store, pending.approval_id)

    result = gateway.approve_and_execute(
        pending.approval_id,
        deliver_request(recipient="team@example.com", label="PUBLIC"),
    )

    assert result.decision == Decision.BLOCK
    assert calls == []


def test_approval_cannot_authorize_a_different_resource(tmp_path):
    gateway, store, _, calls, _ = build(tmp_path)

    pending = gateway.execute(deliver_request())
    approve(store, pending.approval_id)

    other = ActionRequest(
        "research-agent", "save_report", "reports", "", "INTERNAL"
    )
    result = gateway.approve_and_execute(pending.approval_id, other)

    assert result.decision == Decision.BLOCK
    assert calls == []


def test_policy_denial_overrides_an_existing_approval(tmp_path):
    gateway, store, _, calls, policy = build(tmp_path)

    pending = gateway.execute(deliver_request())
    approve(store, pending.approval_id)

    policy.agent_permissions["research-agent"].clear()

    result = gateway.approve_and_execute(pending.approval_id, deliver_request())

    assert result.decision == Decision.BLOCK
    assert calls == []


def test_policy_denial_never_creates_an_approval_ticket(tmp_path):
    gateway, store, audit, calls, _ = build(tmp_path)

    result = gateway.execute(deliver_request("attacker@example.com"))

    assert result.decision == Decision.BLOCK
    assert result.approval_id is None
    assert store.list_pending() == []
    assert calls == []
    assert audit.events[-1]["status"] == "NOT_EXECUTED"


def test_information_flow_denial_outranks_approval(tmp_path):
    gateway, store, _, calls, _ = build(tmp_path)

    result = gateway.execute(deliver_request("public@example.com"))

    assert result.decision == Decision.BLOCK
    assert "Information-flow" in result.reason
    assert store.list_pending() == []
    assert calls == []


def test_missing_approval_authority_fails_closed(tmp_path):
    audit = MemoryAudit()
    gateway = SecureGateway(
        PolicyEngine(demo_policy()), audit_repository=audit
    )
    calls = []
    gateway.register_tool(
        "deliver", "inbox", lambda: calls.append("executed")
    )

    parked = gateway.execute(deliver_request())
    result = gateway.approve_and_execute("some-ticket", deliver_request())

    assert parked.decision == Decision.BLOCK
    assert result.decision == Decision.BLOCK
    assert calls == []


def test_approval_storage_failure_blocks(tmp_path):
    audit = MemoryAudit()
    gateway = SecureGateway(
        PolicyEngine(demo_policy()),
        audit_repository=audit,
        approval_store=FailingApprovalStore(),
    )
    calls = []
    gateway.register_tool(
        "deliver", "inbox", lambda: calls.append("executed")
    )

    result = gateway.execute(deliver_request())

    assert result.decision == Decision.BLOCK
    assert calls == []
    assert audit.events[-1]["status"] == "NOT_EXECUTED"


def test_unregistered_tool_cannot_be_executed_through_approval(tmp_path):
    gateway, store, _, _, _ = build(tmp_path, tool_operation=None)

    pending = gateway.execute(deliver_request())
    approve(store, pending.approval_id)

    result = gateway.approve_and_execute(pending.approval_id, deliver_request())

    assert result.decision == Decision.BLOCK
    assert "No trusted tool" in result.reason


def test_approved_execution_fails_closed_when_audit_is_unavailable(tmp_path):
    policy = demo_policy()
    store = ApprovalStore(db_path=tmp_path / "approvals.db")
    calls = []

    working = SecureGateway(
        PolicyEngine(policy),
        audit_repository=MemoryAudit(),
        approval_store=store,
    )
    working.register_tool(
        "deliver", "inbox", lambda: calls.append("executed")
    )
    pending = working.execute(deliver_request())
    approve(store, pending.approval_id)

    broken = SecureGateway(
        PolicyEngine(policy),
        audit_repository=FailingAudit(),
        approval_store=store,
    )
    broken.register_tool(
        "deliver", "inbox", lambda: calls.append("executed")
    )

    with pytest.raises(RuntimeError):
        broken.approve_and_execute(pending.approval_id, deliver_request())

    assert calls == []


def test_malformed_request_cannot_use_an_approved_ticket(tmp_path):
    gateway, store, _, calls, _ = build(tmp_path)

    pending = gateway.execute(deliver_request())
    approve(store, pending.approval_id)

    result = gateway.approve_and_execute(pending.approval_id, object())

    assert result.decision == Decision.BLOCK
    assert calls == []


def test_allowed_operations_still_execute_without_approval(tmp_path):
    policy = demo_policy()
    gateway, store, audit, _, _ = build(tmp_path, policy=policy)
    calls = []
    gateway.register_tool(
        "read", "documents", lambda: calls.append("read") or {"content": "x"}
    )

    result = gateway.execute(
        ActionRequest("research-agent", "read", "documents", "x@y.z",
                      SecurityLabel.INTERNAL)
    )

    assert result.decision == Decision.ALLOW
    assert store.list_pending() == []
    assert calls == ["read"]
