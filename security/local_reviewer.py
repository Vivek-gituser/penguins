"""Reviewer gate for the local SQLite approval store.

The cloud backend authenticates reviewers through Supabase and checks the
allowlisted `reviewers` table. The local demo database has no identity
provider, so reviewing is unlocked with a single operator credential read
from AGENTGATE_REVIEWER_PASSWORD. If that variable is not configured, local
approvals cannot be granted at all - the gateway stays fail-closed.

Verified reviewer identity is held in memory only (Streamlit session state)
and is never written to the audit trail, logs, or disk.
"""

import hashlib
import hmac
import os
import threading
import uuid
from time import monotonic

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 60

_local_reviewer_id = uuid.uuid5(
    uuid.NAMESPACE_DNS, "agentgate.local.reviewer.invalid"
)

_failures = 0
_locked_until = 0.0
_lock = threading.Lock()


def local_reviewer_id():
    """Stable pseudonymous id recorded on locally reviewed tickets."""
    return str(_local_reviewer_id)


def is_local_reviewer_configured():
    return bool(os.getenv("AGENTGATE_REVIEWER_PASSWORD", "").strip())


def reset_local_reviewer_state():
    global _failures, _locked_until
    with _lock:
        _failures = 0
        _locked_until = 0.0


def unlock_local_reviewer(password):
    """Return a reviewer id when the operator credential is correct."""
    global _failures, _locked_until

    configured = os.getenv("AGENTGATE_REVIEWER_PASSWORD", "").strip()
    if not configured:
        raise RuntimeError(
            "Local reviewing is not configured. Set "
            "AGENTGATE_REVIEWER_PASSWORD to enable approval review."
        )

    if not isinstance(password, str) or not password:
        raise ValueError("Enter the reviewer credential.")

    with _lock:
        if monotonic() < _locked_until:
            remaining = int(_locked_until - monotonic()) + 1
            raise RuntimeError(
                f"Too many failed attempts. Wait {remaining}s."
            )

    # Hash both sides so length is not leaked by the comparison.
    candidate = hashlib.sha256(password.encode("utf-8")).digest()
    expected = hashlib.sha256(configured.encode("utf-8")).digest()

    if not hmac.compare_digest(candidate, expected):
        with _lock:
            _failures += 1
            if _failures >= MAX_FAILED_ATTEMPTS:
                _locked_until = monotonic() + LOCKOUT_SECONDS
                _failures = 0
        raise PermissionError("Reviewer credential rejected.")

    with _lock:
        _failures = 0

    return local_reviewer_id()
