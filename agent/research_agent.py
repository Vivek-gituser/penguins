import re
from dataclasses import dataclass, field

from database.artifact_store import ArtifactStore
from gateway import SecureGateway
from security.labels import SecurityLabel
from security.policy_engine import (
    ActionRequest,
    Decision,
    PolicyEngine,
    demo_policy,
)
from tools.document_reader import DocumentReader
from tools.mock_inbox import MockInbox


@dataclass
class AgentResult:
    status: str
    task: str
    summary: str = ""
    artifact: dict = field(default_factory=dict)
    actions: list = field(default_factory=list)
    message: str = ""
    approval_id: str = None


class ResearchAgent:
    """Deterministic research agent with gateway-enforced tool execution."""

    AGENT_ID = "research-agent"
    SOURCE_ID = "sample_internal"

    def __init__(
        self,
        reader=None,
        artifact_store=None,
        audit_repository=None,
        inbox=None,
        policy=None,
        approval_store=None,
    ):
        self.reader = reader or DocumentReader()
        self.artifact_store = artifact_store or ArtifactStore()
        self.audit_repository = audit_repository
        self.inbox = inbox or MockInbox()
        self.policy = policy or demo_policy()
        self.approval_store = approval_store

    @staticmethod
    def summarize(content, max_sentences=5):
        if not isinstance(content, str) or not content.strip():
            raise ValueError("Content cannot be empty")

        if not isinstance(max_sentences, int) or max_sentences < 1:
            raise ValueError("max_sentences must be a positive integer")

        normalized = content.replace("\r\n", "\n").replace("\r", "\n")
        sentences = re.split(r"(?<=[.!?])\s+|\n+", normalized.strip())
        sentences = [sentence.strip() for sentence in sentences if sentence.strip()]

        return " ".join(sentences[:max_sentences])

    @staticmethod
    def _is_supported_task(task):
        keywords = (
            "research",
            "summary",
            "summarize",
            "summarise",
            "report",
            "document",
        )
        lowered = task.lower()
        return any(keyword in lowered for keyword in keywords)

    @staticmethod
    def _requests_delivery(task):
        lowered = task.lower()

        return bool(
            re.search(r"\b(send|deliver)\b", lowered)
            or re.search(r"\bemail\b.*\bto\b", lowered)
        )

    @staticmethod
    def _extract_recipient(task):
        match = re.search(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
            task,
        )
        return match.group(0) if match else ""

    @staticmethod
    def _action_record(operation, outcome):
        return {
            "operation": operation,
            "decision": outcome.decision.value,
            "reason": outcome.reason,
            "approval_id": outcome.approval_id or "",
        }

    def _new_gateway(self):
        return SecureGateway(
            PolicyEngine(self.policy),
            audit_repository=self.audit_repository,
            approval_store=self.approval_store,
        )

    def run(self, task):
        if not isinstance(task, str) or not task.strip():
            raise ValueError("Task cannot be empty")

        task = task.strip()

        if not self._is_supported_task(task):
            return AgentResult(
                status="UNSUPPORTED",
                task=task,
                message=(
                    "Unsupported task. Try asking me to research a document "
                    "or create a summary report."
                ),
            )

        gateway = self._new_gateway()
        actions = []

        # STEP 1: Read the source document through the secure gateway.
        gateway.register_tool("read", "documents", self.reader.read_sample)

        read_outcome = gateway.execute(
            ActionRequest(
                agent_id=self.AGENT_ID,
                operation="read",
                resource="documents",
                data_label=SecurityLabel.INTERNAL,
            )
        )
        actions.append(self._action_record("read", read_outcome))

        if read_outcome.decision.value != "ALLOW":
            return AgentResult(
                status="BLOCKED",
                task=task,
                actions=actions,
                message=f"Gateway refused document access: {read_outcome.reason}",
            )

        document = read_outcome.result

        if not isinstance(document, dict):
            return AgentResult(
                status="ERROR",
                task=task,
                actions=actions,
                message="Document reader returned an invalid result.",
            )

        content = document.get("content")

        if not isinstance(content, str) or not content.strip():
            return AgentResult(
                status="ERROR",
                task=task,
                actions=actions,
                message="The source document was empty or invalid.",
            )

        # STEP 2: Summarize the retrieved content.
        # Document instructions are treated as content, not agent commands.
        try:
            summary = self.summarize(content)
        except ValueError as exc:
            return AgentResult(
                status="ERROR",
                task=task,
                actions=actions,
                message=str(exc),
            )

        # STEP 3: Save the report through the secure gateway.
        saved_artifact = {}

        def save_report():
            artifact = self.artifact_store.save(
                content=summary,
                source_ids=[self.SOURCE_ID],
                source_labels=[SecurityLabel.INTERNAL],
                transformation="extractive_summary",
            )
            saved_artifact.update(artifact)
            return artifact

        gateway.register_tool("save_report", "reports", save_report)

        save_outcome = gateway.execute(
            ActionRequest(
                agent_id=self.AGENT_ID,
                operation="save_report",
                resource="reports",
                data_label=SecurityLabel.INTERNAL,
            )
        )
        actions.append(self._action_record("save_report", save_outcome))

        if save_outcome.decision.value != "ALLOW":
            return AgentResult(
                status="BLOCKED",
                task=task,
                summary=summary,
                actions=actions,
                message=(
                    "Report was prepared, but the gateway refused saving: "
                    f"{save_outcome.reason}"
                ),
            )

        artifact = (
            save_outcome.result
            if isinstance(save_outcome.result, dict)
            else saved_artifact
        )

        if not artifact:
            artifact = saved_artifact

        # STEP 4: Optional simulated delivery.
        # No delivery is attempted unless the task explicitly requests it.
        if self._requests_delivery(task):
            recipient = self._extract_recipient(task)

            def deliver_report():
                return self.inbox.deliver(
                    message=summary,
                    recipient=recipient,
                )

            gateway.register_tool("deliver", "inbox", deliver_report)

            # Use the saved artifact's verified sensitivity label.
            artifact_label = SecurityLabel.parse(
                artifact.get("label", SecurityLabel.INTERNAL)
            )

            delivery_outcome = gateway.execute(
                ActionRequest(
                    agent_id=self.AGENT_ID,
                    operation="deliver",
                    resource="inbox",
                    recipient=recipient,
                    data_label=artifact_label,
                )
            )
            actions.append(
                self._action_record("deliver", delivery_outcome)
            )

            if delivery_outcome.decision == Decision.REQUIRE_APPROVAL:
                return AgentResult(
                    status="APPROVAL_REQUIRED",
                    task=task,
                    summary=summary,
                    artifact=artifact,
                    actions=actions,
                    approval_id=delivery_outcome.approval_id,
                    message=(
                        "Report saved. Simulated delivery is parked until a "
                        f"reviewer approves request {delivery_outcome.approval_id}."
                    ),
                )

            if delivery_outcome.decision.value != "ALLOW":
                return AgentResult(
                    status="PARTIAL_SUCCESS",
                    task=task,
                    summary=summary,
                    artifact=artifact,
                    actions=actions,
                    message=(
                        "Report was saved, but the gateway blocked "
                        "simulated delivery: "
                        f"{delivery_outcome.reason}"
                    ),
                )

            return AgentResult(
                status="SUCCESS",
                task=task,
                summary=summary,
                artifact=artifact,
                actions=actions,
                message="Research completed, report saved, and delivery simulated.",
            )

        return AgentResult(
            status="SUCCESS",
            task=task,
            summary=summary,
            artifact=artifact,
            actions=actions,
            message="Research completed and report securely saved.",
        )