import sqlite3
import pytest

from database.artifact_store import ArtifactStore


def test_tampered_artifact_label_is_rejected(tmp_path):
    db_path = tmp_path / "tamper.db"
    store = ArtifactStore(db_path)
    store.register_source("source-1", "RESTRICTED")

    saved = store.save(
        "Sensitive report",
        ["source-1"],
        ["RESTRICTED"],
        "summarization",
    )

    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE artifacts SET label = ? WHERE artifact_id = ?",
            ("PUBLIC", saved["artifact_id"]),
        )

    with pytest.raises(ValueError):
        store.load(saved["artifact_id"])


def test_artifact_content_and_metadata_round_trip(tmp_path):
    store = ArtifactStore(tmp_path / "roundtrip.db")
    store.register_source("doc-a", "INTERNAL")
    store.register_source("doc-b", "CONFIDENTIAL")

    saved = store.save(
        "Quarterly analysis",
        ["doc-a", "doc-b"],
        ["INTERNAL", "CONFIDENTIAL"],
        "aggregation",
    )
    loaded = store.load(saved["artifact_id"])

    assert loaded["content"] == "Quarterly analysis"
    assert loaded["label"] == "CONFIDENTIAL"
    assert loaded["source_ids"] == ["doc-a", "doc-b"]
    assert loaded["transformation"] == "aggregation"
