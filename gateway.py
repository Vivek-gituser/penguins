from dataclasses import dataclass
from typing import Any, Callable

from security.policy_engine import ActionRequest, Decision
from security.labels import SecurityLabel
from database.db import write_audit_event


@dataclass
class GatewayOutcome:
    decision: Decision
    reason: str
    result: Any = None
    approval_id: str = None


class SecureGateway:
    """Central enforcement point for all agent-to-tool actions."""

    def __init__(self, policy_engine, audit_repository=None, approval_store=None):
        self.policy_engine = policy_engine
        self.audit_repository = audit_repository
        self.approval_store = approval_store
        self._tools: dict[tuple[str, str], Callable] = {}

    def _write_audit(self, request, decision, reason, status):
        writer = (
            self.audit_repository.write_audit_event
            if self.audit_repository is not None
            else write_audit_event
        )
        writer(request, decision, reason, status)

    def register_tool(self, operation, resource, function):
        if (
            not isinstance(operation, str) or not operation.strip()
            or not isinstance(resource, str) or not resource.strip()
        ):
            raise ValueError("Tool operation and resource must be valid strings")
        if not callable(function):
            raise TypeError("Registered tool must be callable")

        key = (operation.strip(), resource.strip())
        if key in self._tools:
            raise ValueError(f"Tool already registered: {key}")
        self._tools[key] = function

    @staticmethod
    def _valid_request(request):
        if not isinstance(request, ActionRequest):
            return False
        if not all(
            isinstance(value, str) and value.strip()
            for value in (
                request.agent_id, request.operation, request.resource
            )
        ):
            return False
        if not isinstance(request.recipient, str):
            return False
        try:
            SecurityLabel.parse(request.data_label)
        except (ValueError, TypeError, KeyError):
            return False
        return True

    @staticmethod
    def _audit_safe_request(request):
        if SecureGateway._valid_request(request):
            return request
        return ActionRequest(
            agent_id="malformed-request",
            operation="invalid",
            resource="invalid",
            recipient="",
            data_label=SecurityLabel.CONFIDENTIAL,
        )

    def _block(self, request, reason):
        safe_request = self._audit_safe_request(request)
        self._write_audit(
            safe_request, Decision.BLOCK.value, reason, "NOT_EXECUTED"
        )
        return GatewayOutcome(Decision.BLOCK, reason)

    def execute(self, request):
        if not self._valid_request(request):
            return self._block(request, "Malformed action request")

        try:
            policy = self.policy_engine.evaluate(request)
        except Exception as exc:
            return self._block(
                request, f"Policy evaluation failed: {type(exc).__name__}"
            )

        decision = policy.decision
        reason = policy.reason

        if decision == Decision.REQUIRE_APPROVAL:
            return self._request_approval(request, reason)

        if decision != Decision.ALLOW:
            return self._block(request, reason)

        key = (request.operation, request.resource)
        tool = self._tools.get(key)
        if tool is None:
            return self._block(
                request,
                "No trusted tool is registered for this operation and resource",
            )

        return self._run_tool(request, tool, reason)

    def _request_approval(self, request, reason):
        """Park the action in the approval store; never execute it here."""
        if self.approval_store is None:
            return self._block(
                request,
                "Approval required but no approval authority is configured; "
                "fail-closed block.",
            )

        try:
            ticket = self.approval_store.create(request)
        except Exception as exc:
            return self._block(
                request,
                f"Approval request could not be persisted: "
                f"{type(exc).__name__}",
            )

        approval_id = self._approval_id(ticket)
        if approval_id is None:
            return self._block(
                request,
                "Approval store returned an invalid request; fail-closed block.",
            )

        self._write_audit(
            request,
            Decision.REQUIRE_APPROVAL.value,
            f"{reason}; approval request {approval_id} is pending",
            "NOT_EXECUTED",
        )
        return GatewayOutcome(
            decision=Decision.REQUIRE_APPROVAL,
            reason=reason,
            approval_id=approval_id,
        )

    @staticmethod
    def _approval_id(ticket):
        if not isinstance(ticket, dict):
            return None
        approval_id = ticket.get("id") or ticket.get("approval_id")
        if not isinstance(approval_id, str) or not approval_id.strip():
            return None
        return approval_id.strip()

    @staticmethod
    def _ticket_request(ticket):
        """Rebuild the action exactly as recorded in the approval ticket."""
        return ActionRequest(
            agent_id=ticket["agent_id"],
            operation=ticket["operation"],
            resource=ticket["resource"],
            recipient=ticket.get("recipient") or "",
            data_label=ticket.get("data_label") or SecurityLabel.CONFIDENTIAL,
        )

    def _run_tool(self, request, tool, reason, audit_detail=None):
        pending_reason = (
            f"Authorized action; execution pending; {audit_detail}"
            if audit_detail
            else "Authorized action; execution pending"
        )
        success_reason = (
            f"Tool execution completed; {audit_detail}"
            if audit_detail
            else "Tool execution completed"
        )

        # The pre-execution audit must succeed before a tool can run.
        try:
            self._write_audit(
                request,
                Decision.ALLOW.value,
                pending_reason,
                "PENDING",
            )
        except Exception as exc:
            raise RuntimeError(
                "Audit persistence failed; protected tool was not executed"
            ) from exc

        try:
            result = tool()
        except Exception as tool_error:
            failure_reason = f"Tool execution failed: {type(tool_error).__name__}"
            try:
                self._write_audit(
                    request, Decision.ALLOW.value, failure_reason, "ERROR"
                )
            except Exception as audit_error:
                raise RuntimeError(
                    "Tool execution failed and outcome audit could not be persisted"
                ) from audit_error
            raise

        try:
            self._write_audit(
                request,
                Decision.ALLOW.value,
                success_reason,
                "SUCCESS",
            )
        except Exception as exc:
            raise RuntimeError(
                "Tool executed successfully, but outcome audit persistence failed"
            ) from exc

        return GatewayOutcome(
            decision=Decision.ALLOW,
            reason=reason,
            result=result,
        )

    def approve_and_execute(self, approval_id, request, reviewer_id=None):
        """Execute a previously parked action after a human approved it.

        The approval is bound to the exact action, consumed once, and the
        trusted policy is rechecked immediately before the tool runs.
        """
        if self.approval_store is None:
            return self._block(
                request,
                "No approval authority is configured; approval execution is denied.",
            )

        if not self._valid_request(request):
            return self._block(request, "Malformed action request")

        # A policy denial can never be overridden by a human approval.
        try:
            policy = self.policy_engine.evaluate(request)
        except Exception as exc:
            return self._block(
                request,
                f"Policy evaluation failed: {type(exc).__name__}",
            )

        if policy.decision == Decision.BLOCK:
            return self._block(
                request,
                f"Trusted policy denies this action; approval cannot override "
                f"it: {policy.reason}",
            )

        key = (request.operation, request.resource)
        tool = self._tools.get(key)
        if tool is None:
            return self._block(
                request,
                "No trusted tool is registered for this operation and resource",
            )

        try:
            ticket = self.approval_store.consume_approved(approval_id, request)
        except Exception as exc:
            return self._block(
                request,
                f"Approval was not valid for this exact action: {exc}",
            )

        reviewer = "unknown"
        if isinstance(ticket, dict) and ticket.get("reviewed_by"):
            reviewer = str(ticket["reviewed_by"])[:8]

        consumed_id = self._approval_id(ticket) if isinstance(
            ticket, dict
        ) else approval_id
        audit_detail = (
            f"one-time approval {str(consumed_id)[:8]} consumed; "
            f"reviewer {reviewer}"
        )

        # Recheck immediately before execution. The consumed one-time
        # ticket is what satisfies a REQUIRE_APPROVAL decision; a policy
        # denial at this point still stops the action.
        try:
            fresh = self.policy_engine.evaluate(request)
        except Exception as exc:
            return self._block(
                request,
                f"Policy recheck failed after approval: {type(exc).__name__}",
            )

        if fresh.decision == Decision.BLOCK:
            return self._block(
                request,
                "Policy recheck before execution denied the approved action: "
                f"{fresh.reason}",
            )

        reason = f"Approved action authorized by policy; reviewer {reviewer}"

        outcome = self._run_tool(request, tool, reason, audit_detail)
        outcome.approval_id = consumed_id
        return outcome

    def reject_approval(self, approval_id, reviewer_id):
        """Record a human rejection and audit it without executing anything."""
        if self.approval_store is None:
            raise ValueError("No approval authority is configured")
        if not isinstance(reviewer_id, str) or not reviewer_id.strip():
            raise ValueError("A reviewer identity is required to reject")

        request = None
        try:
            request = self._ticket_request(self.approval_store.get(approval_id))
        except Exception:
            request = None

        reviewed = self.approval_store.review(
            approval_id, "REJECTED", reviewer_id
        )

        if request is None:
            request = self._ticket_request(reviewed)

        safe_request = self._audit_safe_request(request)
        self._write_audit(
            safe_request,
            Decision.BLOCK.value,
            "Rejected by reviewer "
            f"{str(reviewer_id)[:8]}; protected tool was not executed",
            "REJECTED",
        )
        return GatewayOutcome(
            decision=Decision.BLOCK,
            reason="Rejected by reviewer; the action was not executed.",
            approval_id=approval_id,
        )
