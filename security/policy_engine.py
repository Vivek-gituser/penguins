from dataclasses import dataclass, field
from enum import Enum

from security.labels import SecurityLabel


class Decision(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


@dataclass
class ActionRequest:
    agent_id: str
    operation: str
    resource: str
    recipient: str = ""
    data_label: SecurityLabel = SecurityLabel.CONFIDENTIAL

    def __post_init__(self):
        self.data_label = SecurityLabel.parse(self.data_label)


@dataclass
class PolicyResult:
    decision: Decision
    reason: str


@dataclass
class SecurityPolicy:
    agent_permissions: dict = field(default_factory=dict)
    resource_permissions: dict = field(default_factory=dict)
    authorized_recipients: set = field(default_factory=set)
    recipient_clearance: dict = field(default_factory=dict)
    approval_required_operations: set = field(default_factory=set)


class PolicyEngine:
    def __init__(self, policy):
        self.policy = policy

    def evaluate(self, req):
        # Fail closed for malformed requests.
        if not isinstance(req, ActionRequest):
            return PolicyResult(Decision.BLOCK, "Malformed action request")

        if not all(
            isinstance(value, str) and value.strip()
            for value in (req.agent_id, req.operation, req.resource)
        ):
            return PolicyResult(Decision.BLOCK, "Missing or malformed request identity")

        if not isinstance(req.recipient, str):
            return PolicyResult(Decision.BLOCK, "Malformed recipient")

        try:
            data_label = SecurityLabel.parse(req.data_label)
        except (ValueError, TypeError, KeyError):
            return PolicyResult(Decision.BLOCK, "Unknown data sensitivity label")

        try:
            agent_operations = self.policy.agent_permissions.get(req.agent_id)
            if not agent_operations or req.operation not in agent_operations:
                return PolicyResult(Decision.BLOCK, "Agent operation not authorized")

            resource_operations = self.policy.resource_permissions.get(req.resource)
            if not resource_operations:
                return PolicyResult(Decision.BLOCK, "Unknown resource")

            if req.operation not in resource_operations:
                return PolicyResult(Decision.BLOCK, "Operation not permitted on resource")

            if req.operation == "deliver":
                if not req.recipient.strip():
                    return PolicyResult(Decision.BLOCK, "Missing recipient")

                if req.recipient not in self.policy.authorized_recipients:
                    return PolicyResult(Decision.BLOCK, "Unauthorized recipient")

                raw_clearance = self.policy.recipient_clearance.get(req.recipient)
                if raw_clearance is None:
                    return PolicyResult(Decision.BLOCK, "Unknown recipient clearance")

                try:
                    clearance = SecurityLabel.parse(raw_clearance)
                except (ValueError, TypeError, KeyError):
                    return PolicyResult(Decision.BLOCK, "Invalid recipient clearance")

                if data_label > clearance:
                    return PolicyResult(Decision.BLOCK, "Information-flow violation")

        except (AttributeError, TypeError):
            return PolicyResult(Decision.BLOCK, "Malformed trusted policy configuration")

        if req.operation in self.policy.approval_required_operations:
            return PolicyResult(
                Decision.REQUIRE_APPROVAL,
                "This operation requires human approval",
            )

        return PolicyResult(Decision.ALLOW, "All policy checks passed")


def demo_policy():
    return SecurityPolicy(
        agent_permissions={
            "research-agent": {"read", "save_report", "deliver"}
        },
        resource_permissions={
            "documents": {"read"},
            "reports": {"save_report"},
            "inbox": {"deliver"}
        },
        authorized_recipients={
            "team@example.com", "public@example.com"
        },
        approval_required_operations={"deliver"},
        recipient_clearance={
            "team@example.com": SecurityLabel.CONFIDENTIAL,
            "public@example.com": SecurityLabel.PUBLIC
        }
    )
