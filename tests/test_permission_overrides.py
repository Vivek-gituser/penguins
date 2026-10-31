import uuid

import pytest

from database.approval_store import ApprovalStore
from database.permission_store import (
    AGENT_OPERATION,
    APPROVAL_OPERATION,
    RECIPIENT,
    RESOURCE_OPERATION,
    PermissionStore,
    apply_overrides,
)
from gateway import SecureGateway
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
        self.events.append((decision, status, reason))


def deliver_request(recipient="team@example.com", label="PUBLIC"):
    return ActionRequest(
        "research-agent", "deliver", "inbox", recipient, label
    )


def test_revoking_an_agent_operation_blocks_it():
    policy = demo_policy()
    apply_overrides(policy, [
        {"kind": AGENT_OPERATION, "key": "research-agent", "value": "deliver"}
    ])

    result = PolicyEngine(policy).evaluate(deliver_request())

    assert result.decision == Decision.BLOCK
    assert result.reason == "Agent operation not authorized"


def test_disabling_a_resource_operation_blocks_it():
    policy = demo_policy()
    apply_overrides(policy, [
        {"kind": RESOURCE_OPERATION, "key": "inbox", "value": "deliver"}
    ])

    assert PolicyEngine(policy).evaluate(
        deliver_request()
    ).decision == Decision.BLOCK


def test_deauthorizing_a_recipient_blocks_it():
    policy = demo_policy()
    apply_overrides(policy, [
        {"kind": RECIPIENT, "key": "team@example.com", "value": ""}
    ])

    result = PolicyEngine(policy).evaluate(deliver_request())

    assert result.decision == Decision.BLOCK
    assert result.reason == "Unauthorized recipient"
    assert "team@example.com" not in policy.recipient_clearance


def test_overrides_can_only_require_approval_never_grant():
    policy = demo_policy()
    apply_overrides(policy, [
        {"kind": APPROVAL_OPERATION, "key": "deliver", "value": ""}
    ])

    result = PolicyEngine(policy).evaluate(deliver_request())

    assert result.decision == Decision.REQUIRE_APPROVAL


def test_denied_action_still_outranks_an_approval_requirement():
    policy = demo_policy()
    apply_overrides(policy, [
        {"kind": APPROVAL_OPERATION, "key": "deliver", "value": ""}
    ])

    result = PolicyEngine(policy).evaluate(
        deliver_request("attacker@example.com")
    )

    assert result.decision == Decision.BLOCK


def test_information_flow_is_still_enforced_after_approval_override():
    policy = demo_policy()
    apply_overrides(policy, [
        {"kind": APPROVAL_OPERATION, "key": "deliver", "value": ""}
    ])

    result = PolicyEngine(policy).evaluate(
        ActionRequest(
            "research-agent", "deliver", "inbox",
            "public@example.com", "INTERNAL"
        )
    )

    assert result.decision == Decision.BLOCK
    assert result.reason == "Information-flow violation"


def test_malformed_approval_override_is_refused():
    policy = demo_policy()

    with pytest.raises(ValueError):
        apply_overrides(policy, [
            {"kind": APPROVAL_OPERATION, "key": "deliver", "value": "deliver"}
        ])


def test_override_store_roundtrip(tmp_path):
    store = PermissionStore(db_path=tmp_path / "perm.db")
    reviewer = str(uuid.uuid4())

    store.add_override(RECIPIENT, "team@example.com", "", reviewer)

    rows = store.list_overrides()

    assert len(rows) == 1
    assert rows[0]["created_by"] == reviewer

    store.remove_override(RECIPIENT, "team@example.com", "", reviewer)

    assert store.list_overrides() == []


def test_override_store_validates_input(tmp_path):
    store = PermissionStore(db_path=tmp_path / "perm.db")
    reviewer = str(uuid.uuid4())

    with pytest.raises(ValueError):
        store.add_override("make_public", "reports", "", reviewer)

    with pytest.raises(ValueError):
        store.add_override(AGENT_OPERATION, "research-agent", "", reviewer)

    with pytest.raises(ValueError):
        store.add_override(RECIPIENT, "team@example.com", "deliver", reviewer)

    with pytest.raises(ValueError):
        store.add_override(RECIPIENT, "team@example.com", "", "")

    with pytest.raises(ValueError):
        store.remove_override(RECIPIENT, "nobody@example.com", "", reviewer)


def test_persisted_override_narrows_a_real_gateway(tmp_path):
    """A stored restriction must change what the live gateway will run."""
    reviewer = str(uuid.uuid4())
    store = PermissionStore(db_path=tmp_path / "perm.db")
    approval_store = ApprovalStore(db_path=tmp_path / "approvals.db")

    def build_gateway():
        policy = demo_policy()
        apply_overrides(policy, store.list_overrides())
        gateway = SecureGateway(
            PolicyEngine(policy),
            audit_repository=MemoryAudit(),
            approval_store=approval_store,
        )
        gateway.register_tool(
            "save_report", "reports", lambda: {"status": "saved"}
        )
        return gateway

    report_request = ActionRequest(
        "research-agent", "save_report", "reports", "", "INTERNAL"
    )

    assert build_gateway().execute(
        report_request
    ).decision == Decision.ALLOW

    store.add_override(APPROVAL_OPERATION, "save_report", "", reviewer)

    parked = build_gateway().execute(report_request)

    assert parked.decision == Decision.REQUIRE_APPROVAL
    assert len(approval_store.list_pending()) == 1

    store.remove_override(APPROVAL_OPERATION, "save_report", "", reviewer)

    assert build_gateway().execute(
        report_request
    ).decision == Decision.ALLOW
