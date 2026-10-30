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

def test_malformed_object_is_blocked_without_tool_execution(monkeypatch):
    import gateway as gateway_module

    audit_calls = []
    monkeypatch.setattr(
        gateway_module,
        "write_audit_event",
        lambda *args: audit_calls.append(args),
    )

    called = []
    gateway = SecureGateway(PolicyEngine(demo_policy()))
    gateway.register_tool("read", "documents", lambda: called.append(True))

    result = gateway.execute({"operation": "read"})

    assert result.decision == Decision.BLOCK
    assert called == []
    assert audit_calls
    assert audit_calls[0][3] == "NOT_EXECUTED"


def test_mutated_malformed_request_is_blocked(monkeypatch):
    import gateway as gateway_module

    monkeypatch.setattr(gateway_module, "write_audit_event", lambda *args: None)

    called = []
    gateway = SecureGateway(PolicyEngine(demo_policy()))
    gateway.register_tool("read", "documents", lambda: called.append(True))

    request = ActionRequest("research-agent", "read", "documents")
    request.operation = ""

    result = gateway.execute(request)

    assert result.decision == Decision.BLOCK
    assert called == []


def test_tool_failure_is_audited_and_reraised(monkeypatch):
    import gateway as gateway_module

    audit_calls = []
    monkeypatch.setattr(
        gateway_module,
        "write_audit_event",
        lambda *args: audit_calls.append(args),
    )

    def failing_tool():
        raise RuntimeError("simulated failure")

    gateway = SecureGateway(PolicyEngine(demo_policy()))
    gateway.register_tool("read", "documents", failing_tool)

    request = ActionRequest("research-agent", "read", "documents")

    import pytest
    with pytest.raises(RuntimeError):
        gateway.execute(request)

    assert audit_calls
    assert audit_calls[-1][3] == "ERROR"


def test_invalid_tool_registration_is_rejected():
    import pytest

    gateway = SecureGateway(PolicyEngine(demo_policy()))

    with pytest.raises(ValueError):
        gateway.register_tool("", "documents", lambda: None)

    with pytest.raises(TypeError):
        gateway.register_tool("read", "documents", "not-callable")


def test_audit_failure_prevents_tool_execution(monkeypatch):
    import pytest
    import gateway as gateway_module

    def failing_audit(*args):
        raise RuntimeError("simulated audit outage")

    monkeypatch.setattr(
        gateway_module,
        "write_audit_event",
        failing_audit,
    )

    called = []
    gateway = SecureGateway(PolicyEngine(demo_policy()))
    gateway.register_tool(
        "read", "documents",
        lambda: called.append("executed"),
    )

    request = ActionRequest("research-agent", "read", "documents")

    with pytest.raises(RuntimeError, match="tool was not executed"):
        gateway.execute(request)

    assert called == []


def test_supabase_audit_repository_is_injected():
    audit_statuses = []

    class FakeAuditRepository:
        def write_audit_event(self, request, decision, reason, status):
            audit_statuses.append(status)

    called = []
    gateway = SecureGateway(
        PolicyEngine(demo_policy()),
        audit_repository=FakeAuditRepository(),
    )
    gateway.register_tool(
        "read", "documents",
        lambda: called.append("executed"),
    )

    request = ActionRequest("research-agent", "read", "documents")
    result = gateway.execute(request)

    assert result.decision == Decision.ALLOW
    assert called == ["executed"]
    assert audit_statuses == ["PENDING", "SUCCESS"]
