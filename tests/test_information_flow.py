from security.policy_engine import ActionRequest, Decision, PolicyEngine, demo_policy
from security.labels import SecurityLabel
from security.provenance import Provenance

def test_confidential_delivery_to_public_is_blocked():
    result = PolicyEngine(demo_policy()).evaluate(
        ActionRequest("research-agent", "deliver", "inbox",
                      "public@example.com", SecurityLabel.CONFIDENTIAL)
    )
    assert result.decision == Decision.BLOCK

def test_derived_artifact_keeps_highest_label():
    public = Provenance(["a"], [SecurityLabel.PUBLIC])
    secret = Provenance(["b"], [SecurityLabel.CONFIDENTIAL])
    report = Provenance.derive("report", [public, secret], "summary")
    assert report.effective_label == SecurityLabel.CONFIDENTIAL
