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


def test_malformed_approval_operations_are_blocked():
    policy = demo_policy()
    policy.approval_required_operations = None

    request = ActionRequest(
        "research-agent",
        "deliver",
        "inbox",
        "team@example.com",
        "INTERNAL",
    )

    result = PolicyEngine(policy).evaluate(request)

    assert result.decision == Decision.BLOCK
    assert result.reason == "Malformed trusted policy configuration"


def test_invalid_approval_operation_entry_is_blocked():
    policy = demo_policy()
    policy.approval_required_operations = {"deliver", 123}

    request = ActionRequest(
        "research-agent",
        "deliver",
        "inbox",
        "team@example.com",
        "INTERNAL",
    )

    result = PolicyEngine(policy).evaluate(request)

    assert result.decision == Decision.BLOCK

def automatic_policy():
    """Baseline policy with approval routing disabled.

    These cases isolate the information-flow checks; the trusted
    baseline itself is exercised by test_gateway_approval.py.
    """
    policy = demo_policy()
    policy.approval_required_operations.clear()
    return policy


def test_delivery_to_authorized_recipient_requires_human_approval():
    request = ActionRequest(
        "research-agent", "deliver", "inbox",
        "team@example.com", "CONFIDENTIAL"
    )
    result = PolicyEngine(demo_policy()).evaluate(request)
    assert result.decision == Decision.REQUIRE_APPROVAL


def test_internal_delivery_to_team_is_automatic():
    request = ActionRequest(
        "research-agent", "deliver", "inbox",
        "team@example.com", "INTERNAL"
    )
    result = PolicyEngine(automatic_policy()).evaluate(request)
    assert result.decision == Decision.ALLOW


def test_public_delivery_to_public_is_automatic():
    request = ActionRequest(
        "research-agent", "deliver", "inbox",
        "public@example.com", "PUBLIC"
    )
    result = PolicyEngine(automatic_policy()).evaluate(request)
    assert result.decision == Decision.ALLOW


def test_internal_delivery_to_public_is_blocked():
    request = ActionRequest(
        "research-agent", "deliver", "inbox",
        "public@example.com", "INTERNAL"
    )
    result = PolicyEngine(automatic_policy()).evaluate(request)
    assert result.decision == Decision.BLOCK


def test_confidential_delivery_to_team_is_automatic():
    request = ActionRequest(
        "research-agent", "deliver", "inbox",
        "team@example.com", "CONFIDENTIAL"
    )
    result = PolicyEngine(automatic_policy()).evaluate(request)
    assert result.decision == Decision.ALLOW


def test_unknown_recipient_is_blocked():
    request = ActionRequest(
        "research-agent", "deliver", "inbox",
        "unknown@example.com", "PUBLIC"
    )
    result = PolicyEngine(demo_policy()).evaluate(request)
    assert result.decision == Decision.BLOCK

