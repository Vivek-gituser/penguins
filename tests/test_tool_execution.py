from gateway import SecureGateway
from security.policy_engine import (
    ActionRequest, Decision, PolicyEngine, demo_policy
)


def test_blocked_action_never_executes():
    called = []
    gateway = SecureGateway(PolicyEngine(demo_policy()))
    gateway.register_tool("deliver", "inbox", lambda: called.append(True))

    request = ActionRequest(
        "unknown", "deliver", "inbox",
        "team@example.com", "PUBLIC"
    )

    result = gateway.execute(request)

    assert result.decision == Decision.BLOCK
    assert called == []


def test_allowed_action_uses_registered_tool():
    called = []
    gateway = SecureGateway(PolicyEngine(demo_policy()))
    gateway.register_tool("read", "documents", lambda: called.append("read"))

    request = ActionRequest("research-agent", "read", "documents")
    result = gateway.execute(request)

    assert result.decision == Decision.ALLOW
    assert called == ["read"]


def test_unregistered_tool_is_blocked():
    gateway = SecureGateway(PolicyEngine(demo_policy()))
    request = ActionRequest("research-agent", "read", "documents")

    result = gateway.execute(request)

    assert result.decision == Decision.BLOCK
    assert result.result is None
