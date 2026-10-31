from agent.research_agent import ResearchAgent


def test_agent_summarizes_document():
    agent = ResearchAgent()
    summary = agent.summarize(
        "First important point. Second important point. Third point."
    )
    assert "First important point" in summary
    assert "Second important point" in summary


def test_agent_rejects_empty_summary():
    import pytest

    with pytest.raises(ValueError):
        ResearchAgent.summarize("")


def test_agent_rejects_empty_task():
    import pytest

    with pytest.raises(ValueError):
        ResearchAgent().run("")


def test_agent_research_and_save():
    result = ResearchAgent().run(
        "Research the document and create a summary report"
    )

    assert result.status == "SUCCESS"
    assert result.summary
    assert result.artifact["artifact_id"]
    assert result.artifact["label"] == "INTERNAL"
    assert [a["decision"] for a in result.actions] == ["ALLOW", "ALLOW"]


def test_agent_does_not_execute_unsupported_task():
    result = ResearchAgent().run("Tell me a joke")

    assert result.status == "UNSUPPORTED"
    assert result.actions == []

class SpyInbox:
    """Records whether the delivery tool was actually executed."""

    def __init__(self):
        self.calls = []

    def deliver(self, message, recipient):
        self.calls.append({
            "message": message,
            "recipient": recipient,
        })
        return {
            "status": "SIMULATED_DELIVERY",
            "recipient": recipient,
            "message": message,
        }


def test_authorized_recipient_delivery_succeeds():
    from security.policy_engine import demo_policy

    policy = demo_policy()
    policy.approval_required_operations.clear()

    inbox = SpyInbox()
    agent = ResearchAgent(inbox=inbox, policy=policy)

    result = agent.run(
        "Research the document, create a summary report, "
        "and send it to team@example.com"
    )

    assert result.status == "SUCCESS"
    assert [a["decision"] for a in result.actions] == [
        "ALLOW", "ALLOW", "ALLOW"
    ]
    assert len(inbox.calls) == 1
    assert inbox.calls[0]["recipient"] == "team@example.com"


def test_unauthorized_recipient_is_blocked_before_delivery():
    inbox = SpyInbox()
    agent = ResearchAgent(inbox=inbox)

    result = agent.run(
        "Research the document, create a summary report, "
        "and send it to attacker@example.com"
    )

    assert result.status == "PARTIAL_SUCCESS"
    assert [a["decision"] for a in result.actions] == [
        "ALLOW", "ALLOW", "BLOCK"
    ]
    assert "Unauthorized recipient" in result.message
    assert inbox.calls == []


def test_missing_recipient_is_blocked_before_delivery():
    inbox = SpyInbox()
    agent = ResearchAgent(inbox=inbox)

    result = agent.run(
        "Research the document, create a summary report, and send it"
    )

    assert result.status == "PARTIAL_SUCCESS"
    assert result.actions[-1]["decision"] == "BLOCK"
    assert inbox.calls == []


def test_internal_report_cannot_be_delivered_to_public_recipient():
    inbox = SpyInbox()
    agent = ResearchAgent(inbox=inbox)

    result = agent.run(
        "Research the document, create a summary report, "
        "and send it to public@example.com"
    )

    assert result.status == "PARTIAL_SUCCESS"
    assert result.actions[-1]["decision"] == "BLOCK"
    assert inbox.calls == []


class RecordingApprovalStore:
    """Records the actions parked for human review."""

    def __init__(self):
        self.created = []

    def create(self, request):
        self.created.append(request)
        return {"id": "approval-1"}


def test_delivery_parks_for_human_approval_when_policy_requires_it():
    from security.policy_engine import demo_policy

    inbox = SpyInbox()
    approvals = RecordingApprovalStore()
    agent = ResearchAgent(
        inbox=inbox,
        policy=demo_policy(),
        approval_store=approvals,
    )

    result = agent.run(
        "Research the document, create a summary report, "
        "and send it to team@example.com"
    )

    assert result.status == "APPROVAL_REQUIRED"
    assert result.approval_id == "approval-1"
    assert result.actions[-1]["decision"] == "REQUIRE_APPROVAL"
    assert len(approvals.created) == 1
    assert inbox.calls == []


def test_blocked_delivery_still_never_parks_an_approval():
    from security.policy_engine import demo_policy

    inbox = SpyInbox()
    approvals = RecordingApprovalStore()
    agent = ResearchAgent(
        inbox=inbox,
        policy=demo_policy(),
        approval_store=approvals,
    )

    result = agent.run(
        "Research the document, create a summary report, "
        "and send it to attacker@example.com"
    )

    assert result.status == "PARTIAL_SUCCESS"
    assert result.actions[-1]["decision"] == "BLOCK"
    assert approvals.created == []
    assert inbox.calls == []
