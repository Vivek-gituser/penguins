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


class SecureGateway:
    """Central enforcement point for all agent-to-tool actions."""

    def __init__(self, policy_engine):
        self.policy_engine = policy_engine
        self._tools: dict[tuple[str, str], Callable] = {}

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
        """Return a valid audit record identity even for malformed input."""
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
            write_audit_event(
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
            write_audit_event(
                request, decision.value, reason, "NOT_EXECUTED"
            )
            return GatewayOutcome(decision, reason)

        decision = policy.decision
        reason = policy.reason
        result = None
        status = "NOT_EXECUTED"

        # Only look up tools after request validation and policy evaluation.
        key = (request.operation, request.resource)
        tool = self._tools.get(key)

        if decision == Decision.ALLOW and tool is None:
            decision = Decision.BLOCK
            reason = "No trusted tool is registered for this operation and resource"

        if decision == Decision.ALLOW:
            try:
                result = tool()
                status = "SUCCESS"
            except Exception as exc:
                status = "ERROR"
                reason = f"Tool execution failed: {type(exc).__name__}"
                write_audit_event(
                    request, decision.value, reason, status
                )
                raise

        write_audit_event(request, decision.value, reason, status)

        return GatewayOutcome(
            decision=decision,
            reason=reason,
            result=result,
        )
