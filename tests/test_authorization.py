from security.policy_engine import ActionRequest, Decision, PolicyEngine, demo_policy

def test_authorized_agent_can_read():
    result = PolicyEngine(demo_policy()).evaluate(
        ActionRequest("research-agent", "read", "documents")
    )
    assert result.decision == Decision.ALLOW

def test_unknown_agent_is_blocked():
    result = PolicyEngine(demo_policy()).evaluate(
        ActionRequest("unknown", "read", "documents")
    )
    assert result.decision == Decision.BLOCK
