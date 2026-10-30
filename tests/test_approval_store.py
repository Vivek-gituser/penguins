import uuid

import pytest

from database.approval_store import ApprovalStore
from security.policy_engine import ActionRequest
from security.labels import SecurityLabel


@pytest.fixture
def store(tmp_path):
    return ApprovalStore(
        db_path=tmp_path / "approvals.db",
        expiry_minutes=15,
    )


@pytest.fixture
def action_request():
    return ActionRequest(
        agent_id="research-agent",
        operation="deliver",
        resource="inbox",
        recipient="team@example.com",
        data_label=SecurityLabel.CONFIDENTIAL,
    )


def test_create_pending_approval(store, action_request):
    item = store.create(action_request)
    assert item["status"] == "PENDING"
    assert item["agent_id"] == "research-agent"
    assert item["operation"] == "deliver"
    assert item["data_label"] == "CONFIDENTIAL"


def test_review_approval(store, action_request):
    item = store.create(action_request)
    reviewer = str(uuid.uuid4())
    reviewed = store.review(item["id"], "APPROVED", reviewer)
    assert reviewed["status"] == "APPROVED"
    assert reviewed["reviewed_by"] == reviewer


def test_reject_approval(store, action_request):
    item = store.create(action_request)
    reviewer = str(uuid.uuid4())
    reviewed = store.review(item["id"], "REJECTED", reviewer)
    assert reviewed["status"] == "REJECTED"


def test_cannot_review_twice(store, action_request):
    item = store.create(action_request)
    reviewer = str(uuid.uuid4())
    store.review(item["id"], "APPROVED", reviewer)

    with pytest.raises(ValueError):
        store.review(item["id"], "REJECTED", reviewer)


def test_invalid_reviewer_rejected(store, action_request):
    item = store.create(action_request)

    with pytest.raises(ValueError):
        store.review(item["id"], "APPROVED", "not-a-uuid")


def test_invalid_decision_rejected(store, action_request):
    item = store.create(action_request)

    with pytest.raises(ValueError):
        store.review(item["id"], "ALLOW", str(uuid.uuid4()))


def test_invalid_approval_id_rejected(store):
    with pytest.raises(ValueError):
        store.get("not-a-uuid")


def test_pending_list(store, action_request):
    store.create(action_request)
    pending = store.list_pending()
    assert len(pending) == 1
    assert pending[0]["status"] == "PENDING"

def _make_approved_ticket(tmp_path):
    import uuid
    from gateway import ActionRequest
    from database.approval_store import ApprovalStore

    store = ApprovalStore(db_path=tmp_path / "approval-test.db")
    request = ActionRequest(
        "research-agent",
        "deliver",
        "inbox",
        "team@example.com",
        "INTERNAL",
    )
    pending = store.create(request)
    store.review(
        pending["id"],
        "APPROVED",
        str(uuid.uuid4()),
    )
    return store, request, pending["id"]


def test_approved_action_can_be_consumed_once(tmp_path):
    store, request, approval_id = _make_approved_ticket(tmp_path)

    consumed = store.consume_approved(approval_id, request)

    assert consumed["id"] == approval_id
    with pytest.raises(ValueError, match="not found or already consumed"):
        store.consume_approved(approval_id, request)


def test_approval_rejects_different_action(tmp_path):
    from gateway import ActionRequest

    store, request, approval_id = _make_approved_ticket(tmp_path)

    modified_request = ActionRequest(
        request.agent_id,
        request.operation,
        request.resource,
        "public@example.com",
        request.data_label,
    )

    with pytest.raises(ValueError, match="does not match"):
        store.consume_approved(approval_id, modified_request)


def test_approval_cannot_be_replayed(tmp_path):
    store, request, approval_id = _make_approved_ticket(tmp_path)

    store.consume_approved(approval_id, request)

    with pytest.raises(ValueError):
        store.consume_approved(approval_id, request)


def test_expired_approval_cannot_be_consumed(tmp_path):
    from datetime import datetime, timedelta, timezone

    store, request, approval_id = _make_approved_ticket(tmp_path)

    expired_time = (
        datetime.now(timezone.utc) - timedelta(minutes=5)
    ).isoformat()

    with store._connect() as db:
        db.execute(
            "UPDATE approval_requests SET expires_at = ? WHERE id = ?",
            (expired_time, approval_id),
        )

    with pytest.raises(ValueError, match="expired"):
        store.consume_approved(approval_id, request)
