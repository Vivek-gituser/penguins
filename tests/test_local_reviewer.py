import pytest

from security import local_reviewer


@pytest.fixture(autouse=True)
def clean_state(monkeypatch):
    monkeypatch.delenv("AGENTGATE_REVIEWER_PASSWORD", raising=False)
    local_reviewer.reset_local_reviewer_state()
    yield
    local_reviewer.reset_local_reviewer_state()


def test_reviewing_is_disabled_without_a_credential():
    assert local_reviewer.is_local_reviewer_configured() is False

    with pytest.raises(RuntimeError):
        local_reviewer.unlock_local_reviewer("anything")


def test_correct_credential_returns_a_stable_reviewer_id(monkeypatch):
    monkeypatch.setenv("AGENTGATE_REVIEWER_PASSWORD", "s3cret-passphrase")

    first = local_reviewer.unlock_local_reviewer("s3cret-passphrase")
    second = local_reviewer.unlock_local_reviewer("s3cret-passphrase")

    assert first == second == local_reviewer.local_reviewer_id()
    assert local_reviewer.is_local_reviewer_configured() is True


def test_wrong_credential_is_rejected(monkeypatch):
    monkeypatch.setenv("AGENTGATE_REVIEWER_PASSWORD", "s3cret-passphrase")

    with pytest.raises(PermissionError):
        local_reviewer.unlock_local_reviewer("wrong")


def test_empty_credential_is_rejected(monkeypatch):
    monkeypatch.setenv("AGENTGATE_REVIEWER_PASSWORD", "s3cret-passphrase")

    with pytest.raises(ValueError):
        local_reviewer.unlock_local_reviewer("")


def test_repeated_failures_lock_the_gate(monkeypatch):
    monkeypatch.setenv("AGENTGATE_REVIEWER_PASSWORD", "s3cret-passphrase")

    for _ in range(local_reviewer.MAX_FAILED_ATTEMPTS):
        with pytest.raises(PermissionError):
            local_reviewer.unlock_local_reviewer("wrong")

    with pytest.raises(RuntimeError):
        local_reviewer.unlock_local_reviewer("s3cret-passphrase")


def test_reviewer_id_is_a_uuid(monkeypatch):
    import uuid

    monkeypatch.setenv("AGENTGATE_REVIEWER_PASSWORD", "s3cret-passphrase")

    reviewer_id = local_reviewer.unlock_local_reviewer("s3cret-passphrase")

    assert str(uuid.UUID(reviewer_id)) == reviewer_id
