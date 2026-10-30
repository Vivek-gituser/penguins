from pathlib import Path

from gateway import SecureGateway
from security.content_guard import wrap_untrusted_document, safe_document_context
from security.labels import SecurityLabel
from security.policy_engine import (
    ActionRequest, Decision, PolicyEngine, demo_policy
)


def test_prompt_injection_cannot_authorize_unauthorized_delivery():
    # Read intentionally malicious sample document
    content = Path("sample_documents/sample_prompt_injection.txt").read_text(
        encoding="utf-8"
    )

    document = wrap_untrusted_document(content, "prompt-injection-sample")
    context = safe_document_context(document)

    # Verify document remains untrusted data
    assert context["trust_level"] == "UNTRUSTED"
    assert context["may_authorize_actions"] is False
    assert context["may_modify_policy"] is False

    # Attempt the malicious delivery independently
    executed = []
    policy = demo_policy()
    gateway = SecureGateway(PolicyEngine(policy))
    gateway.register_tool(
        "deliver", "inbox",
        lambda: executed.append("DELIVERED")
    )

    request = ActionRequest(
        agent_id="research-agent",
        operation="deliver",
        resource="inbox",
        recipient="attacker@example.com",
        data_label=SecurityLabel.CONFIDENTIAL
    )

    result = gateway.execute(request)

    assert result.decision == Decision.BLOCK
    assert executed == []
    assert "attacker@example.com" not in policy.authorized_recipients
