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
