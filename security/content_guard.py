from dataclasses import dataclass
from typing import Any

@dataclass(frozen=True)
class UntrustedDocument:
    content: str
    source_id: str
    trust_level: str = "UNTRUSTED"

def wrap_untrusted_document(content: str, source_id: str) -> UntrustedDocument:
    if not isinstance(content, str) or not source_id:
        raise ValueError("Invalid document content or source ID")
    return UntrustedDocument(content=content, source_id=source_id)

def safe_document_context(document: UntrustedDocument) -> dict[str, Any]:
    """Content is data only. It must never become policy or authorization."""
    return {
        "trust_level": document.trust_level,
        "source_id": document.source_id,
        "content": document.content,
        "may_authorize_actions": False,
        "may_modify_policy": False,
    }

INJECTION_SIGNALS = (
    "ignore all previous instructions",
    "ignore previous instructions",
    "disregard the above",
    "system override",
    "urgent system",
    "new instructions",
    "reveal all private",
    "exfiltrate",
    "modify the security policy",
    "authorize this action",
    "you must send",
)

EMAIL_PATTERN = __import__("re").compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)


def detect_injection_signals(content):
    """Advisory only: flags instruction-shaped text so it can be shown to a
    human. A signal never authorizes or blocks an action - the policy engine
    remains the only decision maker."""
    if not isinstance(content, str) or not content.strip():
        return []

    lowered = content.lower()
    found = [signal for signal in INJECTION_SIGNALS if signal in lowered]

    if "send" in lowered and EMAIL_PATTERN.search(content):
        found.append("delivery instruction addressed to an email recipient")

    return found
