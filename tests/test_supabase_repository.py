from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from database.supabase_repository import SupabaseRepository
from security.labels import SecurityLabel
from security.policy_engine import ActionRequest, Decision


def make_repo():
    client = MagicMock()
    return SupabaseRepository(client=client), client


def test_trusted_source_label_is_read_from_registry():
    repo, client = make_repo()
    query = (
        client.table.return_value
        .select.return_value
        .eq.return_value
        .limit.return_value
    )
    query.execute.return_value = SimpleNamespace(
        data=[{"source_id": "sample_internal", "label": "INTERNAL"}]
    )

    assert repo.get_trusted_source_label("sample_internal") == SecurityLabel.INTERNAL


def test_unregistered_source_is_rejected():
    repo, client = make_repo()
    query = (
        client.table.return_value
        .select.return_value
        .eq.return_value
        .limit.return_value
    )
    query.execute.return_value = SimpleNamespace(data=[])

    with pytest.raises(ValueError, match="Unregistered source"):
        repo.get_trusted_source_label("unknown_source")


def test_empty_artifact_content_is_rejected_before_database_write():
    repo, client = make_repo()

    with pytest.raises(ValueError, match="cannot be empty"):
        repo.save_artifact(
            "",
            ["sample_internal"],
            [SecurityLabel.INTERNAL],
            "summarization",
        )

    client.table.assert_not_called()


def test_source_label_count_must_match_source_count():
    repo, client = make_repo()

    with pytest.raises(ValueError, match="Every source"):
        repo.save_artifact(
            "Example content",
            ["sample_internal"],
            [],
            "summarization",
        )

    client.table.assert_not_called()


def test_audit_event_is_written_to_supabase():
    repo, client = make_repo()
    client.table.return_value.insert.return_value.execute.return_value = (
        SimpleNamespace(data=[{"id": "audit-test-id"}])
    )

    request = ActionRequest(
        agent_id="research-agent",
        operation="read",
        resource="documents",
        recipient="",
        data_label=SecurityLabel.INTERNAL,
    )

    result = repo.write_audit_event(
        request,
        Decision.ALLOW,
        "Unit test audit event",
        "NOT_EXECUTED",
    )

    assert result["id"] == "audit-test-id"
    client.table.assert_called_once_with("audit_events")
