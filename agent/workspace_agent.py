"""AI workspace: interpret a request, then let the gateway decide.

Nothing in this module authorizes anything. It turns a user prompt into
candidate actions, binds each one to the sensitivity the trusted source
registry actually holds, and hands it to SecureGateway.
"""

import re

from ai import composer as ai_composer
from ai import interpreter as ai_interpreter
from agent.research_agent import ResearchAgent
from security.labels import SecurityLabel
from security.policy_engine import ActionRequest, Decision
from tools.pdf_generator import build_pdf, safe_filename
from tools.pptx_generator import build_pptx

EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")


class WorkspaceAgent:
    def __init__(
        self,
        gateway,
        reader,
        artifact_store,
        inbox,
        policy,
        agent_id="research-agent",
        workspace=None,
    ):
        self.gateway = gateway
        self.reader = reader
        self.artifact_store = artifact_store
        self.inbox = inbox
        self.policy = policy
        self.agent_id = agent_id
        self.workspace = workspace
        self.summary = ""
        self.artifact = {}
        self.document = {}
        self.delivered = []
        self.generated = []
        self.file_ref = ""
        self.prompt = ""

    # ---------- trusted label handling ----------
    def _source_for(self, proposal):
        """A proposal may name a source; otherwise use the last authorized read."""
        return (
            (proposal.get("source_id") or "").strip()
            or (self.document.get("source_id") or "")
        )

    def _trusted_labels(self, source_id):
        if not source_id:
            return []

        try:
            return [self.artifact_store.get_trusted_source_label(source_id)]
        except Exception:
            return []

    def _effective_label(self, proposal):
        labels = self._trusted_labels(self._source_for(proposal))

        if not labels and self.artifact:
            labels = [SecurityLabel.parse(self.artifact.get("label"))]

        if not labels:
            labels = [SecurityLabel.INTERNAL]

        return SecurityLabel.parse(
            ai_interpreter.resolve_data_label(
                proposal.get("data_label"), labels
            )
        )

    # ---------- document access ----------
    def _read_document(self, source_id):
        # Only reached from inside a gateway-authorized tool call.
        for uploaded_id, content in self.uploaded:
            if uploaded_id == source_id and content.strip():
                return {
                    "document_id": source_id,
                    "content": content,
                    "label": self._effective_label({"source_id": source_id}).name,
                }

        return self.reader.read_sample()

    # ---------- workspace files ----------
    def _read_workspace_file(self, file_ref):
        # Only reached from inside a gateway-authorized tool call.
        if self.workspace is None:
            raise ValueError("No file workspace is configured")

        record, text = self.workspace.read_text(file_ref)
        return {
            "document_id": record["source_id"],
            "content": text,
            "label": record["label"],
            "file_name": record["display_name"],
            "file_id": record["file_id"],
        }

    def _export(self, operation, proposal):
        """Build a real PDF or PowerPoint file from authorized content."""
        if self.workspace is None:
            raise ValueError("No file workspace is configured")

        source_id = self._source_for(proposal)
        content = self.document.get("content") or ""
        label = self._effective_label(proposal)

        spec, meta = ai_composer.draft_document(
            "presentation" if operation == "generate_pptx" else "report",
            self.prompt,
            [(source_id or "workspace", content)] if content else [],
            label.name,
            source_ids=[source_id] if source_id else [],
            title_hint=(proposal.get("title") or "").strip(),
        )

        if operation == "generate_pptx":
            data = build_pptx(spec)
            display_name = safe_filename(spec.title, ".pptx", "presentation")
        else:
            data = build_pdf(spec)
            display_name = safe_filename(spec.title, ".pdf", "report")

        # Classification is inherited from the source material; a generated
        # file can never be presented as less sensitive than its inputs.
        record = self.workspace.store_generated(
            display_name,
            data,
            source_ids=[source_id] if source_id else [],
            claimed_label=spec.label,
            transformation=f"{operation}_export",
        )
        record["generator"] = meta["generator"]
        record["degraded"] = meta["degraded"]
        record["slides"] = spec.slide_count
        self.generated.append(record)
        return record

    # ---------- protected tools ----------
    def _tool_for(self, operation, proposal):
        source_id = self._source_for(proposal)

        if operation == "read":
            return lambda: self._read_document(source_id)

        if operation == "read_file":
            return lambda: self._read_workspace_file(
                source_id or self.file_ref
            )

        if operation == "generate_pdf":
            return lambda: self._export(operation, proposal)

        if operation == "generate_pptx":
            return lambda: self._export(operation, proposal)

        if operation == "save_report":
            def save_report():
                content = self.summary or "No report content was produced."
                labels = self._trusted_labels(source_id)

                if not labels:
                    raise ValueError("The report has no trusted source label")

                self.artifact = self.artifact_store.save(
                    content=content,
                    source_ids=[source_id],
                    source_labels=labels,
                    transformation="workspace_summary",
                )
                return self.artifact

            return save_report

        if operation == "deliver":
            recipient = (proposal.get("recipient") or "").strip()

            def deliver():
                message = (
                    self.artifact.get("content")
                    or self.summary
                    or "AGENTGATE workspace report"
                )
                result = self.inbox.deliver(message=message, recipient=recipient)
                self.delivered.append(recipient)
                return result

            return deliver

        return None

    # ---------- recipient integrity ----------
    def _pin_recipient(self, proposal, prompt):
        """The recipient a human asked for cannot be replaced by a model."""
        named = EMAIL_PATTERN.findall(prompt or "")
        recipient = (proposal.get("recipient") or "").strip()

        if len(named) == 1 and recipient and recipient != named[0]:
            proposal["recipient"] = named[0]
            proposal["rationale"] = (
                f"Interpreter proposed {recipient}; pinned to the recipient "
                f"named in the user request ({named[0]})."
            )

        return proposal

    def _pin_source_target(self, proposal):
        """A source the human picked in the interface outranks the wording.

        "Read the document" is ambiguous. When the workspace page has been
        pointed at one of the user's own files, a generic read is retargeted
        to that file instead of the bundled sample document. The gateway
        still decides whether the retargeted action is allowed.
        """
        if not self.file_ref or proposal.get("operation") != "read":
            return proposal

        if any(source_id == self.file_ref for source_id, _ in self.uploaded):
            return proposal

        resource = policy_vocabulary(self.policy)["operation_resource"].get(
            "read_file"
        )

        if not resource:
            return proposal

        proposal["operation"] = "read_file"
        proposal["resource"] = resource
        proposal["source_id"] = self.file_ref
        proposal["rationale"] = (
            "Retargeted to the workspace file selected in the interface."
        )
        return proposal

    def _skipped(self, proposal, reason):
        return {
            "operation": proposal.get("operation", ""),
            "resource": proposal.get("resource", ""),
            "recipient": "",
            "source_id": proposal.get("source_id", ""),
            "rationale": proposal.get("rationale", ""),
            "decision": "SKIPPED",
            "reason": reason,
            "approval_id": "",
            "data_label": "",
        }

    # ---------- main flow ----------
    def run(self, prompt, documents=(), file_ref=""):
        # One user action gets one model-time budget. An overloaded API can
        # cost the first steps their bounded share, but it cannot stall the
        # rest of the turn: later calls fall back immediately and the gateway
        # decisions are made the same way either way.
        with ai_interpreter.gemini_budget():
            return self._run(prompt, documents=documents, file_ref=file_ref)

    def _run(self, prompt, documents=(), file_ref=""):
        prompt = (prompt or "").strip()

        if not prompt:
            raise ValueError("Enter a request for the workspace.")

        self.prompt = prompt
        self.file_ref = (str(file_ref) if file_ref else "").strip()
        self.delivered = []
        self.generated = []
        self.document = {}
        self.uploaded = [
            (str(source_id), str(content))
            for source_id, content in documents
            if isinstance(content, str)
        ]

        interpretation = ai_interpreter.interpret(
            prompt,
            self.uploaded,
            vocabulary=policy_vocabulary(self.policy),
        )

        actions = []
        seen = set()

        for proposal in interpretation["proposals"]:
            proposal = self._pin_recipient(dict(proposal), prompt)
            proposal = self._pin_source_target(proposal)
            operation = proposal["operation"]

            identity = (
                operation,
                proposal.get("resource", ""),
                proposal.get("source_id", "") or self.file_ref,
                proposal.get("recipient", ""),
            )

            if identity in seen:
                actions.append(self._skipped(
                    proposal,
                    "The same action was already proposed in this request, "
                    "so it was not repeated.",
                ))
                continue

            seen.add(identity)

            if operation == "save_report" and not self.summary:
                # Report text may only come from content that an earlier
                # gateway-authorized read actually released.
                content = self.document.get("content") or ""

                if content.strip():
                    self.summary = summarize_text(content)
                else:
                    actions.append(self._skipped(
                        proposal,
                        "No gateway-authorized document content is "
                        "available yet, so nothing was saved.",
                    ))
                    continue

            if operation in ("generate_pdf", "generate_pptx"):
                content = self.document.get("content") or ""

                if not content.strip():
                    actions.append(self._skipped(
                        proposal,
                        "Nothing has been read through the gateway yet, so "
                        "there is no authorized source to export.",
                    ))
                    continue

            if operation == "read_file" and not (
                self._source_for(proposal) or self.file_ref
            ):
                actions.append(self._skipped(
                    proposal,
                    "No workspace file was named for this request.",
                ))
                continue

            tool = self._tool_for(operation, proposal)
            if tool is not None:
                try:
                    self.gateway.register_tool(
                        operation, proposal["resource"], tool
                    )
                except ValueError:
                    pass

            actions.append(
                self._execute(operation, proposal)
            )

        blocked = [a for a in actions if a["decision"] == "BLOCK"]
        pending = [a for a in actions if a["decision"] == "REQUIRE_APPROVAL"]

        if not actions:
            status = "NO_ACTIONS"
        elif blocked:
            status = "BLOCKED"
        elif pending:
            status = "APPROVAL_REQUIRED"
        else:
            status = "SUCCESS"

        return {
            "status": status,
            "prompt": prompt,
            "interpretation": interpretation,
            "actions": actions,
            "summary": self.summary,
            "artifact": self.artifact,
            "delivered": self.delivered,
            "generated": self.generated,
        }

    def _execute(self, operation, proposal):
        record = {
            "operation": operation,
            "resource": proposal.get("resource", ""),
            "recipient": proposal.get("recipient", ""),
            "source_id": proposal.get("source_id", ""),
            "rationale": proposal.get("rationale", ""),
            "decision": "SKIPPED",
            "reason": "",
            "approval_id": "",
            "data_label": "",
        }

        if operation == "summarize":
            content = self.document.get("content") or ""

            if not content.strip():
                record.update(
                    decision="SKIPPED",
                    reason=(
                        "Nothing has been read through the gateway yet, "
                        "so there is no content to summarize."
                    ),
                )
                return record

            self.summary = summarize_text(content)
            record.update(
                decision="ALLOWED_LOCALLY",
                reason=(
                    "Summarization is not a protected tool action; "
                    "the source was already gateway-authorized."
                ),
                data_label=self._effective_label(proposal).name,
            )
            return record

        if self._tool_for(operation, proposal) is None:
            record.update(
                decision="BLOCK",
                reason="No trusted tool implements this operation",
            )
            return record

        data_label = self._effective_label(proposal)
        request = ActionRequest(
            agent_id=self.agent_id,
            operation=operation,
            resource=proposal["resource"],
            recipient=proposal.get("recipient", ""),
            data_label=data_label,
        )
        record["data_label"] = data_label.name

        outcome = self.gateway.execute(request)

        record["decision"] = outcome.decision.value
        record["reason"] = outcome.reason
        record["approval_id"] = outcome.approval_id or ""

        if operation in ("read", "read_file") and (
            outcome.decision == Decision.ALLOW
        ):
            result = outcome.result or {}
            content = result.get("content") if isinstance(result, dict) else None
            if isinstance(content, str) and content.strip():
                self.document = {
                    "source_id": (
                        result.get("document_id")
                        or proposal.get("source_id", "")
                    ),
                    "content": content,
                }
                if operation == "read_file":
                    record["file_name"] = result.get("file_name", "")

        if operation in ("generate_pdf", "generate_pptx") and (
            outcome.decision == Decision.ALLOW
        ):
            record["file"] = outcome.result or {}

        return record


def summarize_text(content):
    try:
        return ResearchAgent.summarize(content)
    except ValueError:
        return ""


def policy_vocabulary(policy):
    """The operations the system knows at all.

    This comes from the trusted tool surface, not from one agent's grants:
    dropping a proposal here would hide an action the gateway should openly
    block and audit.
    """
    return {
        "operations": {
            operation
            for operations in policy.resource_permissions.values()
            for operation in operations
        },
        "operation_resource": {
            operation: resource
            for resource, operations in policy.resource_permissions.items()
            for operation in operations
        },
    }
