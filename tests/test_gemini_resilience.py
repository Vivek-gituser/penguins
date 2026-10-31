"""Model calls are bounded, and losing them must never stall or weaken a turn.

The gateway is the authority; Gemini is an optional convenience. These tests
pin the timing bounds and prove a failing model still produces a complete,
gateway-decided workflow instead of a hang.
"""

import time

import pytest
import requests

from agent.workspace_agent import WorkspaceAgent
from ai import interpreter as ai
from database.approval_store import ApprovalStore
from database.artifact_store import ArtifactStore
from gateway import SecureGateway
from security.policy_engine import Decision, PolicyEngine, demo_policy
from tools.file_workspace import SecureFileWorkspace


class FakeReader:
    def read_sample(self):
        return {
            "document_id": "sample_internal",
            "content": "First finding. Second finding. Third finding.",
            "label": "INTERNAL",
        }


class SpyInbox:
    def __init__(self):
        self.calls = []

    def deliver(self, message, recipient):
        self.calls.append({"message": message, "recipient": recipient})
        return {"status": "SIMULATED_DELIVERY", "recipient": recipient}


class MemoryAudit:
    def __init__(self):
        self.events = []

    def write_audit_event(self, request, decision, reason, status):
        value = getattr(decision, "value", decision)
        self.events.append((request.operation, str(value), status))


# ---------- time bounds ----------
def test_single_call_has_a_hard_upper_bound():
    assert ai.CONNECT_TIMEOUT_SECONDS == 5
    assert ai.READ_TIMEOUT_SECONDS == 20
    assert ai.REQUEST_TIMEOUT == ai.CONNECT_TIMEOUT_SECONDS + ai.READ_TIMEOUT_SECONDS
    assert ai.REQUEST_TIMEOUT <= 30
    assert ai.TURN_GEMINI_BUDGET_SECONDS <= 60


def test_request_is_given_separate_connect_and_read_limits(monkeypatch):
    seen = {}

    class Response:
        status_code = 200

        def json(self):
            return {
                "candidates": [
                    {"content": {"parts": [{"text": '{"commentary":"x","proposals":[]}'}]}}
                ]
            }

    def fake_post(url, headers=None, json=None, timeout=None):
        seen["timeout"] = timeout
        return Response()

    monkeypatch.setattr(ai.requests, "post", fake_post)
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    ai.reset_gemini_state()

    ai.call_gemini("system", "hello", {"type": "OBJECT", "properties": {}})

    connect, read = seen["timeout"]
    assert connect == ai.CONNECT_TIMEOUT_SECONDS
    assert read <= ai.READ_TIMEOUT_SECONDS
    assert connect + read <= ai.REQUEST_TIMEOUT


# ---------- cooldown ----------
def test_a_failure_stops_repeating_the_same_slow_call(monkeypatch):
    calls = {"n": 0}

    def failing_post(*args, **kwargs):
        calls["n"] += 1
        raise requests.Timeout("read timeout")

    monkeypatch.setattr(ai.requests, "post", failing_post)
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    ai.reset_gemini_state()

    with pytest.raises(ai.InterpreterUnavailable):
        ai.call_gemini("system", "hello", {})

    # Everything after the failure must be answered without the network.
    with pytest.raises(ai.InterpreterUnavailable):
        ai.call_gemini("system", "hello", {})

    ai.interpret("Read the document and write a report", [], {
        "operations": {"read", "save_report"},
        "operation_resource": {"read": "documents", "save_report": "reports"},
    })

    assert calls["n"] == 1
    assert ai.model_available() is False
    assert "after the last failure" in ai.unavailable_reason()


def test_cooldown_is_cleared_by_a_good_response(monkeypatch):
    ai.reset_gemini_state()
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")

    def boom(*args, **kwargs):
        raise requests.ConnectionError("down")

    monkeypatch.setattr(ai.requests, "post", boom)

    with pytest.raises(ai.InterpreterUnavailable):
        ai.call_gemini("system", "hello", {})

    assert ai.model_available() is False

    class Response:
        status_code = 200

        def json(self):
            return {
                "candidates": [
                    {"content": {"parts": [{"text": '{"commentary":"x","proposals":[]}'}]}}
                ]
            }

    ai.clear_cooldown()
    monkeypatch.setattr(ai.requests, "post", lambda *a, **k: Response())
    ai.call_gemini("system", "hello", {})

    assert ai.model_available() is True


def test_reset_leaves_no_state_for_the_next_test():
    ai.trip_cooldown(30)
    assert ai.cooldown_remaining() > 0
    ai.reset_gemini_state()
    assert ai.cooldown_remaining() == 0


# ---------- budget ----------
def test_exhausted_budget_skips_the_network(monkeypatch):
    calls = {"n": 0}

    def counting_post(*args, **kwargs):
        calls["n"] += 1
        raise requests.Timeout("slow")

    monkeypatch.setattr(ai.requests, "post", counting_post)
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    ai.reset_gemini_state()

    with ai.gemini_budget(0.01):
        time.sleep(0.02)

        assert ai.remaining_budget() == 0
        result = ai.interpret(
            "Read the document and write a report",
            [],
            {
                "operations": {"read", "save_report"},
                "operation_resource": {
                    "read": "documents",
                    "save_report": "reports",
                },
            },
        )

    assert calls["n"] == 0
    assert result["degraded"] is True
    assert [p["operation"] for p in result["proposals"]] == ["read", "save_report"]


def test_nested_budgets_share_the_outer_deadline():
    ai.reset_gemini_state()

    with ai.gemini_budget(10):
        first = ai.remaining_budget()

        with ai.gemini_budget(300):
            assert ai.remaining_budget() <= first


# ---------- the workflow still finishes ----------
def build(tmp_path, approval_store=None):
    policy = demo_policy()
    audit = MemoryAudit()
    gateway = SecureGateway(
        PolicyEngine(policy),
        audit_repository=audit,
        approval_store=approval_store,
    )
    workspace = SecureFileWorkspace(
        root=tmp_path / "files",
        artifact_store=ArtifactStore(db_path=tmp_path / "artifacts.db"),
        db_path=tmp_path / "index.db",
    )
    inbox = SpyInbox()
    agent = WorkspaceAgent(
        gateway=gateway,
        reader=FakeReader(),
        artifact_store=ArtifactStore(db_path=tmp_path / "artifacts.db"),
        inbox=inbox,
        policy=policy,
        workspace=workspace,
    )
    return agent, gateway, audit, inbox, workspace


def test_full_workflow_finishes_when_gemini_is_unreachable(tmp_path, monkeypatch):
    """The exact regression: a slow model must not hang the workspace."""

    def never_answers(*args, **kwargs):
        raise requests.Timeout("read timeout")

    monkeypatch.setattr(ai.requests, "post", never_answers)
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    ai.reset_gemini_state()

    agent, gateway, audit, inbox, _ = build(
        tmp_path, approval_store=ApprovalStore(db_path=tmp_path / "approvals.db")
    )

    started = time.monotonic()
    turn = agent.run(
        "Read the document, generate a report, export it as a PDF and "
        "send it to team@example.com",
        documents=[("sample_internal", "First finding. Second finding.")],
    )
    elapsed = time.monotonic() - started

    # Three model-hungry steps, and not one of them waited for the API.
    assert elapsed < 2, f"turn took {elapsed:.1f}s with the model down"
    assert turn["status"] == "APPROVAL_REQUIRED"

    decisions = [(a["operation"], a["decision"]) for a in turn["actions"]]
    assert decisions == [
        ("read", Decision.ALLOW.value),
        ("save_report", Decision.ALLOW.value),
        ("generate_pdf", Decision.ALLOW.value),
        ("deliver", Decision.REQUIRE_APPROVAL.value),
    ]

    # A real file was still produced, from authorized content.
    assert turn["generated"][0]["display_name"].endswith(".pdf")
    assert inbox.calls == []

    # Verify the complete audit trail, including execution outcomes.
    assert audit.events == [
        ("read", "ALLOW", "PENDING"),
        ("read", "ALLOW", "SUCCESS"),
        ("save_report", "ALLOW", "PENDING"),
        ("save_report", "ALLOW", "SUCCESS"),
        ("generate_pdf", "ALLOW", "PENDING"),
        ("generate_pdf", "ALLOW", "SUCCESS"),
        ("deliver", "REQUIRE_APPROVAL", "NOT_EXECUTED"),
    ]


def test_a_pending_delivery_never_runs_while_the_model_is_down(tmp_path, monkeypatch):
    """With no approval authority configured, the turn fails closed."""

    monkeypatch.setattr(
        ai.requests, "post", lambda *a, **k: (_ for _ in ()).throw(
            requests.Timeout("read timeout")
        )
    )
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    ai.reset_gemini_state()

    agent, gateway, audit, inbox, _ = build(tmp_path)

    turn = agent.run(
        "Read the document and send it to team@example.com",
        documents=[("sample_internal", "First finding.")],
    )

    assert turn["status"] == "BLOCKED"
    assert inbox.calls == []
    assert [event[0] for event in audit.events][-1] == "deliver"


def test_a_block_is_still_a_block_with_the_model_down(tmp_path, monkeypatch):
    monkeypatch.setattr(ai.requests, "post", lambda *a, **k: (_ for _ in ()).throw(
        requests.Timeout("read timeout")
    ))
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    ai.reset_gemini_state()

    agent, gateway, audit, inbox, _ = build(tmp_path)
    agent.agent_id = "unknown-agent"

    turn = agent.run(
        "Read the document and generate a report",
        documents=[("sample_internal", "First finding.")],
    )

    assert turn["status"] == "BLOCKED"

    # The unauthorized read is a hard BLOCK, and the follow-on report never
    # gets to run because the blocked read released no content. Nothing in
    # this turn was allowed.
    assert [a["decision"] for a in turn["actions"]] == ["BLOCK", "SKIPPED"]
    assert not any(a["decision"] == Decision.ALLOW.value for a in turn["actions"])
    assert turn["artifact"] == {}
    assert turn["generated"] == []
    assert inbox.calls == []
    assert ("read", "BLOCK", "NOT_EXECUTED") in audit.events
