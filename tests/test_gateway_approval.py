import uuid
import pytest

from gateway import SecureGateway
from database.approval_store import ApprovalStore
from security.policy_engine import (
    ActionRequest,
    Decision,
    PolicyEngine,
    demo_policy,
)


@pytest.fixture
def setup_gateway(tmp_path):
    policy = demo_policy()
    store = ApprovalStore(db_path=tmp_path / "approvals.db")
    gateway = SecureGateway(
        PolicyEngine(policy),
        approval_store=store,
    )

    calls = []
    gateway.register_tool(
        "deliver",
        "inbox",
        lambda: calls.append("executed") or {"status": "delivered"},
    )

    request = ActionRequest(
        "research-agent",
        "deliver",
        "inbox",
        "team@example.com",
        "INTERNAL",
    )

    return gateway, store, request, calls, policy


def test_valid_approval_executes_tool_once(setup_gateway):
    gateway, store, request, calls, _ = setup_gateway

    pending = gateway.execute(request)
    assert pending.decision == Decision.REQUIRE_APPROVAL
    assert calls == []

    store.review(pending.approval_id, "APPROVED", str(uuid.uuid4()))

    result = gateway.approve_and_execute(pending.approval_id, request)

    assert result.decision == Decision.ALLOW
    assert result.result == {"status": "delivered"}
    assert calls == ["executed"]


def test_unapproved_ticket_never_executes(setup_gateway):
    gateway, _, request, calls, _ = setup_gateway

    pending = gateway.execute(request)
    result = gateway.approve_and_execute(pending.approval_id, request)

    assert result.decision == Decision.BLOCK
    assert calls == []


def test_replayed_approval_never_executes_twice(setup_gateway):
    gateway, store, request, calls, _ = setup_gateway

    pending = gateway.execute(request)
    store.review(pending.approval_id, "APPROVED", str(uuid.uuid4()))

    first = gateway.approve_and_execute(pending.approval_id, request)
    second = gateway.approve_and_execute(pending.approval_id, request)

    assert first.decision == Decision.ALLOW
    assert second.decision == Decision.BLOCK
    assert calls == ["executed"]


def test_policy_block_overrides_existing_approval(setup_gateway):
    gateway, store, request, calls, policy = setup_gateway

    pending = gateway.execute(request)
    store.review(pending.approval_id, "APPROVED", str(uuid.uuid4()))

    policy.agent_permissions["research-agent"].clear()

    result = gateway.approve_and_execute(pending.approval_id, request)

    assert result.decision == Decision.BLOCK
    assert calls == []
