"""AGENTGATE Research Agent.

The agent proposes actions. SecureGateway authorizes every tool execution.
"""

from dataclasses import dataclass, field

from database.artifact_store import ArtifactStore
from security.labels import SecurityLabel
from security.policy_engine import (
    ActionRequest,
    Decision,
    PolicyEngine,
    demo_policy,
)
from gateway import SecureGateway
from tools.document_reader import DocumentReader


@dataclass
class AgentResult:
    status: str
    task: str
    summary: str = ""
    artifact: dict = field(default_factory=dict)
    actions: list = field(default_factory=list)
    message: str = ""


class ResearchAgent:
    """A deterministic research agent protected by AGENTGATE."""

    def __init__(self, reader=None, artifact_store=None, audit_repository=None):
        self.reader = reader or DocumentReader()
        self.artifact_store = artifact_store or ArtifactStore()
        self.audit_repository = audit_repository

    @staticmethod
    def summarize(content, max_sentences=5):
        if not isinstance(content, str) or not content.strip():
            raise ValueError("Cannot summarize empty document content")

        sentences = [
            sentence.strip()
            for sentence in content.replace("\n", " ").split(".")
            if sentence.strip()
        ]
        return ". ".join(sentences[:max_sentences]) + (
            "." if sentences else ""
        )

    def run(self, task):
        if not isinstance(task, str) or not task.strip():
            raise ValueError("Please provide a valid research task")

        task = task.strip()

        if not any(
            word in task.lower()
            for word in ("research", "summary", "summarize", "report", "document")
        ):
            return AgentResult(
                status="UNSUPPORTED",
                task=task,
                message="Try asking me to research a document or create a summary report.",
            )

        gateway = SecureGateway(
            PolicyEngine(demo_policy()),
            audit_repository=self.audit_repository,
        )
        actions = []

        # Step 1: Read document only through the security gateway.
        gateway.register_tool(
            "read",
            "documents",
            self.reader.read_sample,
        )

        read_request = ActionRequest(
            agent_id="research-agent",
            operation="read",
            resource="documents",
            data_label=SecurityLabel.INTERNAL,
        )

        read_outcome = gateway.execute(read_request)
        actions.append({
            "operation": "read",
            "decision": read_outcome.decision.value,
            "reason": read_outcome.reason,
        })

        if read_outcome.decision != Decision.ALLOW:
            return AgentResult(
                status="BLOCKED",
                task=task,
                actions=actions,
                message="Gateway blocked document access.",
            )

        document = read_outcome.result
        if not isinstance(document, dict):
            raise ValueError("Document reader returned invalid data")

        content = document.get("content")
        if not isinstance(content, str) or not content.strip():
            raise ValueError("Document has no readable content")

        # Step 2: Treat document contents as data, never as instructions.
        summary = self.summarize(content)

        # Step 3: Save artifact through the gateway.
        # Trusted source ID and sensitivity come from application setup,
        # not from document text or AI-generated instructions.
        saved_artifact = {}

        def save_report():
            nonlocal saved_artifact
            save_method = getattr(self.artifact_store, "save_artifact", None)
            if callable(save_method):
                saved_artifact = save_method(
                    content=summary,
                    source_ids=["sample_internal"],
                    source_labels=[SecurityLabel.INTERNAL],
                    transformation="extractive_summary",
                )
            else:
                saved_artifact = self.artifact_store.save(
                    content=summary,
                    source_ids=["sample_internal"],
                    source_labels=[SecurityLabel.INTERNAL],
                    transformation="extractive_summary",
                )
            return saved_artifact

        gateway.register_tool(
            "save_report",
            "reports",
            save_report,
        )

        save_request = ActionRequest(
            agent_id="research-agent",
            operation="save_report",
            resource="reports",
            data_label=SecurityLabel.INTERNAL,
        )

        save_outcome = gateway.execute(save_request)
        actions.append({
            "operation": "save_report",
            "decision": save_outcome.decision.value,
            "reason": save_outcome.reason,
        })

        if save_outcome.decision != Decision.ALLOW:
            return AgentResult(
                status="BLOCKED",
                task=task,
                summary=summary,
                actions=actions,
                message="Gateway blocked report saving.",
            )

        return AgentResult(
            status="SUCCESS",
            task=task,
            summary=summary,
            artifact=saved_artifact,
            actions=actions,
            message="Research completed and report securely saved.",
        )
