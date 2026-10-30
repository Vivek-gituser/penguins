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

class PolicyEngine:
    def __init__(self, policy):
        self.policy = policy

    def evaluate(self, req):
        if not req.agent_id or req.agent_id not in self.policy.agent_permissions:
            return PolicyResult(Decision.BLOCK, "Unknown agent")

        if req.operation not in self.policy.agent_permissions[req.agent_id]:
            return PolicyResult(Decision.BLOCK, "Agent operation not authorized")

        if req.resource not in self.policy.resource_permissions:
            return PolicyResult(Decision.BLOCK, "Unknown resource")

        if req.operation not in self.policy.resource_permissions[req.resource]:
            return PolicyResult(Decision.BLOCK, "Operation not permitted on resource")

        if req.operation == "deliver":
            if req.recipient not in self.policy.authorized_recipients:
                return PolicyResult(Decision.BLOCK, "Unauthorized recipient")

            clearance = self.policy.recipient_clearance.get(req.recipient)
            if clearance is None:
                return PolicyResult(Decision.BLOCK, "Unknown recipient clearance")

            if req.data_label > clearance:
                return PolicyResult(Decision.BLOCK, "Information-flow violation")

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
        recipient_clearance={
            "team@example.com": SecurityLabel.CONFIDENTIAL,
            "public@example.com": SecurityLabel.PUBLIC
        }
    )
