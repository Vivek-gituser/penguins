
import sqlite3

import pytest

from database.artifact_store import ArtifactStore
from security.labels import SecurityLabel


def test_artifact_label_and_provenance_survive_reload(tmp_path):
    db_path = tmp_path / "persistence_test.db"

    store = ArtifactStore(db_path=str(db_path))

    saved = store.save(
        content="Confidential research summary.",
        source_ids=["sample_internal"],
        source_labels=[SecurityLabel.INTERNAL],
        transformation="extractive_summary",
    )

    artifact_id = saved["artifact_id"]

    # Simulate a new application session using the same database.
    restarted_store = ArtifactStore(db_path=str(db_path))
    loaded = restarted_store.load(artifact_id)

    assert loaded["content"] == "Confidential research summary."
    assert loaded["label"] == "INTERNAL"
    assert loaded["source_ids"] == ["sample_internal"]
    assert loaded["source_labels"] == ["INTERNAL"]
    assert loaded["transformation"] == "extractive_summary"


def test_artifact_store_rejects_fake_lower_source_label(tmp_path):
    store = ArtifactStore(db_path=str(tmp_path / "fake_label.db"))

    with pytest.raises(ValueError, match="trusted source labels"):
        store.save(
            content="Attempt to downgrade classification.",
            source_ids=["sample_internal"],
            source_labels=[SecurityLabel.PUBLIC],
            transformation="summary",
        )


def test_artifact_store_rejects_trusted_source_label_change(tmp_path):
    store = ArtifactStore(db_path=str(tmp_path / "source_change.db"))

    with pytest.raises(ValueError, match="cannot be silently changed"):
        store.register_source("sample_internal", "PUBLIC")


def test_reload_rejects_tampered_artifact_label(tmp_path):
    db_path = tmp_path / "tampered_label.db"
    store = ArtifactStore(db_path=str(db_path))

    saved = store.save(
        content="Internal report.",
        source_ids=["sample_internal"],
        source_labels=[SecurityLabel.INTERNAL],
        transformation="summary",
    )

    # Simulate someone modifying the database directly.
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE artifacts SET label = ? WHERE artifact_id = ?",
            ("PUBLIC", saved["artifact_id"]),
        )

    with pytest.raises(ValueError, match="Artifact label"):
        store.load(saved["artifact_id"])


def test_reload_rejects_tampered_provenance(tmp_path):
    db_path = tmp_path / "tampered_provenance.db"
    store = ArtifactStore(db_path=str(db_path))

    saved = store.save(
        content="Internal report.",
        source_ids=["sample_internal"],
        source_labels=[SecurityLabel.INTERNAL],
        transformation="summary",
    )

    # Simulate tampering with the stored source classification.
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE artifacts SET source_labels = ? WHERE artifact_id = ?",
            ('["PUBLIC"]', saved["artifact_id"]),
        )

    with pytest.raises(ValueError, match="provenance"):
        store.load(saved["artifact_id"])
