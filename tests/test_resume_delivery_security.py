
from database.artifact_store import ArtifactStore
from gateway import SecureGateway
from security.labels import SecurityLabel
from security.policy_engine import (
    ActionRequest,
    Decision,
    PolicyEngine,
    demo_policy,
)


class SpyInbox:
    def __init__(self):
        self.calls = []

    def deliver(self, message, recipient):
        self.calls.append(recipient)
        return {"status": "SIMULATED_DELIVERY", "recipient": recipient}


def test_reloaded_internal_artifact_cannot_be_delivered_to_public_recipient(
    tmp_path,
):
    db_path = tmp_path / "resume_security.db"

    # Step 1: Save an INTERNAL artifact.
    store = ArtifactStore(db_path)

    saved = store.save(
        content="Confidential internal research report",
        source_ids=["sample_internal"],
        source_labels=["INTERNAL"],
        transformation="summarization",
    )

    artifact_id = saved["artifact_id"]

    # Step 2: Simulate application restart.
    restarted_store = ArtifactStore(db_path)
    loaded = restarted_store.load(artifact_id)

    assert loaded["label"] == "INTERNAL"
    assert loaded["source_labels"] == ["INTERNAL"]
    assert loaded["source_ids"] == ["sample_internal"]

    # Step 3: Attempt delivery using the reloaded classification.
    inbox = SpyInbox()

    gateway = SecureGateway(PolicyEngine(demo_policy()))

    gateway.register_tool(
        "deliver",
        "inbox",
        lambda: inbox.deliver(
            loaded["content"],
            "public@example.com",
        ),
    )

    request = ActionRequest(
        agent_id="research-agent",
        operation="deliver",
        resource="inbox",
        recipient="public@example.com",
        data_label=SecurityLabel.parse(loaded["label"]),
    )

    result = gateway.execute(request)

    # Step 4: Verify that information-flow enforcement survives restart.
    assert result.decision == Decision.BLOCK
    assert inbox.calls == []
    assert result.result is None
