from dataclasses import dataclass
from typing import Any, Callable

from security.policy_engine import Decision
from database.db import write_audit_event


@dataclass
class GatewayOutcome:
    decision: Decision
    reason: str
    result: Any = None


class SecureGateway:
    """
    Central enforcement point.
    Only trusted startup code can register tools.
    Agent requests cannot supply executable functions.
    """

    def __init__(self, policy_engine):
        self.policy_engine = policy_engine
        self._tools: dict[tuple[str, str], Callable] = {}

    def register_tool(self, operation, resource, function):
        key = (operation, resource)

        if key in self._tools:
            raise ValueError(f"Tool already registered: {key}")

        if not callable(function):
            raise TypeError("Registered tool must be callable")

        self._tools[key] = function

    def execute(self, request):
        policy = self.policy_engine.evaluate(request)
        result = None
        status = "NOT_EXECUTED"
        decision = policy.decision
        reason = policy.reason

        tool = self._tools.get((request.operation, request.resource))

        if decision == Decision.ALLOW and tool is None:
            decision = Decision.BLOCK
            reason = "No trusted tool is registered for this operation and resource"

        if decision == Decision.ALLOW:
            try:
                result = tool()
                status = "SUCCESS"
            except Exception as exc:
                status = "ERROR"
                write_audit_event(
                    request, decision.value,
                    f"Tool execution failed: {type(exc).__name__}",
                    status
                )
                raise

        write_audit_event(request, decision.value, reason, status)

        return GatewayOutcome(
            decision=decision,
            reason=reason,
            result=result
        )
