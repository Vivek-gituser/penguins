"""Shared context object handed from app.py to the page modules."""

from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass
class WorkspaceContext:
    """Everything a page needs, passed explicitly instead of imported."""

    get_policy: Callable[[], Any]
    make_gateway: Callable[..., Any]
    get_artifact_store: Callable[[], Any]
    get_approval_store: Callable[[], Any]
    get_events: Callable[[], list]
    reviewer_gate: Callable[[], Any]
    audit_permission_change: Callable[..., None]
    is_reviewer_authorized: Callable[[str], bool]
    workspace: Any
    inbox: Any
    reader: Any
    labels: tuple = ()
    upload_suffixes: tuple = ()
    extra: dict = field(default_factory=dict)
