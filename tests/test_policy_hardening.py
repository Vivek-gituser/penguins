from security.policy_engine import (
    ActionRequest, Decision, PolicyEngine, demo_policy
)


def test_missing_agent_is_blocked():
    request = ActionRequest("", "read", "documents")
    result = PolicyEngine(demo_policy()).evaluate(request)
    assert result.decision == Decision.BLOCK


def test_missing_operation_is_blocked():
    request = ActionRequest("research-agent", "", "documents")
    result = PolicyEngine(demo_policy()).evaluate(request)
    assert result.decision == Decision.BLOCK


def test_missing_resource_is_blocked():
    request = ActionRequest("research-agent", "read", "")
    result = PolicyEngine(demo_policy()).evaluate(request)
    assert result.decision == Decision.BLOCK


def test_missing_delivery_recipient_is_blocked():
    request = ActionRequest(
        "research-agent", "deliver", "inbox", "", "PUBLIC"
    )
    result = PolicyEngine(demo_policy()).evaluate(request)
    assert result.decision == Decision.BLOCK


def test_invalid_recipient_clearance_is_blocked():
    policy = demo_policy()
    policy.recipient_clearance["team@example.com"] = "UNKNOWN"

    request = ActionRequest(
        "research-agent", "deliver", "inbox",
        "team@example.com", "PUBLIC"
    )
    result = PolicyEngine(policy).evaluate(request)

    assert result.decision == Decision.BLOCK
    assert result.reason == "Invalid recipient clearance"


def test_string_clearance_is_parsed_safely():
    policy = demo_policy()
    policy.approval_required_operations.clear()
    policy.recipient_clearance["team@example.com"] = "CONFIDENTIAL"

    request = ActionRequest(
        "research-agent", "deliver", "inbox",
        "team@example.com", "INTERNAL"
    )
    result = PolicyEngine(policy).evaluate(request)

    assert result.decision == Decision.ALLOW
