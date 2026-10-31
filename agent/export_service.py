"""One gateway-decided path from workspace content to a real downloadable file.

Reading a protected file, building the document and storing the export are
each separate ActionRequests. Nothing in this module decides whether an
export may happen; it only describes the request and runs the tool the
gateway authorises.
"""

from ai import composer as ai_composer
from security.labels import SecurityLabel
from security.policy_engine import ActionRequest, Decision
from tools.pdf_generator import build_pdf, safe_filename
from tools.pptx_generator import build_pptx

EXPORT_OPERATIONS = {"pdf": "generate_pdf", "pptx": "generate_pptx"}

EXPORT_BUILDERS = {
    "pdf": build_pdf,
    "pptx": build_pptx,
}

EXPORT_KIND = {"pdf": "report", "pptx": "presentation"}


class ExportService:
    def __init__(self, gateway, workspace, agent_id="research-agent"):
        self.gateway = gateway
        self.workspace = workspace
        self.agent_id = agent_id

    # ---------- authorized reads ----------
    def read_file(self, file_ref, binary=False):
        """Release one workspace file's content, only through the gateway.

        The classification asked for is the one the trusted index already
        holds for that file, so the audit record states the real sensitivity
        instead of a guess.
        """
        record = self.workspace.get(file_ref)
        request = ActionRequest(
            agent_id=self.agent_id,
            operation="read_file",
            resource="files",
            recipient="",
            data_label=SecurityLabel.parse(record["label"]),
        )

        def tool():
            if binary:
                stored, payload = self.workspace.read_bytes(file_ref)
            else:
                stored, payload = self.workspace.read_text(file_ref)
            return {
                "record": stored,
                "content": payload,
                "label": stored["label"],
                "source_id": stored["source_id"],
                "file_name": stored["display_name"],
            }

        self._register("read_file", "files", tool)
        outcome = self.gateway.execute(request)

        if outcome.decision != Decision.ALLOW:
            return {
                "decision": outcome.decision.value,
                "reason": outcome.reason,
                "approval_id": outcome.approval_id or "",
                "record": None,
                "content": "",
            }

        result = outcome.result or {}
        payload = result.get("content", "")

        return {
            "decision": outcome.decision.value,
            "reason": outcome.reason,
            "approval_id": "",
            "record": result.get("record"),
            "content": "" if binary else payload,
            "data": payload if binary else b"",
            "label": result.get("label"),
            "source_id": result.get("source_id"),
            "file_name": result.get("file_name"),
        }

    # ---------- exports ----------
    def export_file(self, kind, file_ref, title="", prompt=""):
        """Export a workspace file, inheriting its registered label."""
        read = self.read_file(file_ref)

        if read["decision"] != Decision.ALLOW:
            return {
                "status": read["decision"],
                "reason": read["reason"],
                "approval_id": read["approval_id"],
                "file": None,
            }

        return self.export(
            kind,
            content=read["content"],
            label=read["label"],
            source_ids=[read["source_id"]] if read["source_id"] else [],
            title=title,
            prompt=prompt or f"Export {read['record']['display_name']}",
        )

    def export(self, kind, content, label, source_ids=(), title="",
               prompt=""):
        if kind not in EXPORT_OPERATIONS:
            raise ValueError(f"Unsupported export kind: {kind}")

        operation = EXPORT_OPERATIONS[kind]
        trusted_label = SecurityLabel.parse(label).name

        spec, meta = ai_composer.draft_document(
            EXPORT_KIND[kind],
            prompt or title or "AGENTGATE workspace export",
            [("workspace", content)] if content else [],
            trusted_label,
            source_ids=list(source_ids),
            title_hint=(title or "").strip(),
        )

        def build_and_store():
            data = EXPORT_BUILDERS[kind](spec)
            display_name = safe_filename(
                spec.title,
                ".pptx" if kind == "pptx" else ".pdf",
                fallback="presentation" if kind == "pptx" else "report",
            )
            record = self.workspace.store_generated(
                display_name,
                data,
                source_ids=list(source_ids),
                claimed_label=spec.label,
                transformation=f"{operation}_export",
            )
            record["generator"] = meta["generator"]
            record["degraded"] = meta["degraded"]
            record["slides"] = spec.slide_count
            record["sections"] = [
                {"heading": s.heading, "bullets": list(s.bullets)}
                for s in spec.sections
            ]
            # Kept in memory for this session only, so the download button
            # serves the exact bytes the authorised tool produced.
            record["payload"] = data
            return record

        request = ActionRequest(
            agent_id=self.agent_id,
            operation=operation,
            resource="reports",
            recipient="",
            data_label=spec.label,
        )
        self._register(operation, "reports", build_and_store)
        outcome = self.gateway.execute(request)

        if outcome.decision != Decision.ALLOW:
            return {
                "status": outcome.decision.value,
                "reason": outcome.reason,
                "approval_id": outcome.approval_id or "",
                "file": None,
                "data_label": spec.label,
            }

        return {
            "status": Decision.ALLOW.value,
            "reason": outcome.reason,
            "approval_id": "",
            "file": outcome.result,
            "data_label": spec.label,
        }

    def _register(self, operation, resource, tool):
        try:
            self.gateway.register_tool(operation, resource, tool)
        except ValueError:
            # Already registered on this gateway instance for this session.
            pass
