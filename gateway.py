from dataclasses import dataclass
from typing import Any, Callable

from security.policy_engine import (
    ActionRequest,
    Decision,
    PolicyEngine,
)
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
        """Persist an audit event through the configured trusted backend."""
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
                request.agent_id,
                request.operation,
                request.resource,
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
        """Return a valid audit identity even for malformed input."""
        if SecureGateway._valid_request(request):
            return request

        return ActionRequest(
            agent_id="malformed-request",
            operation="invalid",
            resource="invalid",
            recipient="",
            data_label=SecurityLabel.CONFIDENTIAL,
        )

    def execute(self, request):
        if not self._valid_request(request):
            decision = Decision.BLOCK
            reason = "Malformed action request"

            self._write_audit(
                self._audit_safe_request(request),
                decision.value,
                reason,
                "NOT_EXECUTED",
            )
            return GatewayOutcome(decision, reason)

        try:
            policy = self.policy_engine.evaluate(request)
        except Exception as exc:
            decision = Decision.BLOCK
            reason = f"Policy evaluation failed: {type(exc).__name__}"

            self._write_audit(
                request, decision.value, reason, "NOT_EXECUTED"
            )
            return GatewayOutcome(decision, reason)

        decision = policy.decision
        reason = policy.reason

        # Tool lookup happens only after validation and policy evaluation.
        key = (request.operation, request.resource)
        tool = self._tools.get(key)

        if decision == Decision.ALLOW and tool is None:
            decision = Decision.BLOCK
            reason = (
                "No trusted tool is registered for this operation "
                "and resource"
            )

        # Approval-required actions are persisted but never executed.
        if decision == Decision.REQUIRE_APPROVAL:
            if self.approval_store is None:
                reason = "Approval required, but no approval store is configured"
                self._write_audit(
                    request, Decision.BLOCK.value, reason, "NOT_EXECUTED"
                )
                return GatewayOutcome(Decision.BLOCK, reason)

            try:
                pending = self.approval_store.create(request)
                self._write_audit(
                    request,
                    decision.value,
                    "Approval request created; tool execution withheld",
                    "NOT_EXECUTED",
                )
                return GatewayOutcome(
                    decision,
                    reason,
                    approval_id=pending["id"],
                )
            except Exception as exc:
                raise RuntimeError(
                    "Approval persistence failed; protected tool was not executed"
                ) from exc

        # Blocked actions are never executed.
        if decision != Decision.ALLOW:
            self._write_audit(
                request, decision.value, reason, "NOT_EXECUTED"
            )
            return GatewayOutcome(decision, reason)

        # Persist intent before executing any protected tool.
        try:
            self._write_audit(
                request,
                decision.value,
                "Authorized action; execution pending",
                "PENDING",
            )
        except Exception as exc:
            raise RuntimeError(
                "Audit persistence failed; protected tool was not executed"
            ) from exc

        # Execute only after the pre-execution audit succeeds.
        try:
            result = tool()
        except Exception as tool_error:
            reason = f"Tool execution failed: {type(tool_error).__name__}"

            try:
                self._write_audit(
                    request, decision.value, reason, "ERROR"
                )
            except Exception as audit_error:
                raise RuntimeError(
                    "Tool execution failed and its outcome audit "
                    "could not be persisted"
                ) from audit_error

            raise

        # Record the completed action. A failure here cannot undo the tool.
        try:
            self._write_audit(
                request,
                decision.value,
                "Tool execution completed",
                "SUCCESS",
            )
        except Exception as exc:
            raise RuntimeError(
                "Tool executed successfully, but outcome audit "
                "persistence failed"
            ) from exc

        return GatewayOutcome(
            decision=decision,
            reason=reason,
            result=result,
        )

    def approve_and_execute(self, approval_id, request):
        """Consume an exact approved action and execute it once."""
        if not self._valid_request(request):
            reason = "Malformed action request"
            self._write_audit(
                self._audit_safe_request(request),
                Decision.BLOCK.value,
                reason,
                "NOT_EXECUTED",
            )
            return GatewayOutcome(Decision.BLOCK, reason)

        if self.approval_store is None:
            reason = "No approval store configured"
            self._write_audit(
                request, Decision.BLOCK.value, reason, "NOT_EXECUTED"
            )
            return GatewayOutcome(Decision.BLOCK, reason)

        # Re-evaluate current policy. An old approval cannot override
        # a policy that now blocks the action or no longer requires approval.
        try:
            policy = self.policy_engine.evaluate(request)
        except Exception as exc:
            reason = f"Policy evaluation failed: {type(exc).__name__}"
            self._write_audit(
                request, Decision.BLOCK.value, reason, "NOT_EXECUTED"
            )
            return GatewayOutcome(Decision.BLOCK, reason)

        if policy.decision != Decision.REQUIRE_APPROVAL:
            reason = "Current policy does not permit approval-based execution"
            self._write_audit(
                request, Decision.BLOCK.value, reason, "NOT_EXECUTED"
            )
            return GatewayOutcome(Decision.BLOCK, reason)

        key = (request.operation, request.resource)
        tool = self._tools.get(key)

        if tool is None:
            reason = "No trusted tool is registered for this action"
            self._write_audit(
                request, Decision.BLOCK.value, reason, "NOT_EXECUTED"
            )
            return GatewayOutcome(Decision.BLOCK, reason)

        # Atomically consume the ticket bound to this exact request.
        try:
            self.approval_store.consume_approved(approval_id, request)
        except Exception as exc:
            reason = f"Approval rejected: {type(exc).__name__}"
            self._write_audit(
                request, Decision.BLOCK.value, reason, "NOT_EXECUTED"
            )
            return GatewayOutcome(Decision.BLOCK, reason)

        # Approval is now consumed. Audit must succeed before execution.
        try:
            self._write_audit(
                request,
                Decision.ALLOW.value,
                "Approved action; execution pending",
                "PENDING",
            )
        except Exception as exc:
            raise RuntimeError(
                "Pre-execution audit failed; approved tool was not executed"
            ) from exc

        try:
            result = tool()
        except Exception as tool_error:
            reason = f"Tool execution failed: {type(tool_error).__name__}"
            try:
                self._write_audit(
                    request, Decision.ALLOW.value, reason, "ERROR"
                )
            except Exception as audit_error:
                raise RuntimeError(
                    "Tool failed and outcome audit could not be persisted"
                ) from audit_error
            raise

        try:
            self._write_audit(
                request,
                Decision.ALLOW.value,
                "Approved tool execution completed",
                "SUCCESS",
            )
        except Exception as exc:
            raise RuntimeError(
                "Tool executed, but outcome audit persistence failed"
            ) from exc

        return GatewayOutcome(
            decision=Decision.ALLOW,
            reason="Approved action executed successfully",
            result=result,
        )
