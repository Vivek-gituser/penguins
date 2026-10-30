import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

from security.labels import SecurityLabel, highest_label

class ArtifactStore:
    """SQLite persistence for artifacts and their provenance metadata."""

    def __init__(self, db_path="database/agentgate.db"):
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS artifacts (
                    artifact_id TEXT PRIMARY KEY,
                    content TEXT NOT NULL,
                    label TEXT NOT NULL,
                    source_ids TEXT NOT NULL,
                    source_labels TEXT NOT NULL,
                    transformation TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)

    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def save(self, content, source_ids, source_labels, transformation):
        if not isinstance(content, str) or not content.strip():
            raise ValueError("Artifact content cannot be empty")
        if not source_ids or len(source_ids) != len(source_labels):
            raise ValueError("Every source must have an ID and a label")
        if not transformation:
            raise ValueError("Transformation description is required")

        labels = [SecurityLabel.parse(label) for label in source_labels]
        effective = highest_label(labels)
        artifact_id = str(uuid.uuid4())
        created_at = datetime.now(timezone.utc).isoformat()

        with self._connect() as conn:
            conn.execute("""
                INSERT INTO artifacts VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                artifact_id,
                content,
                effective.name,
                json.dumps(source_ids),
                json.dumps([label.name for label in labels]),
                transformation,
                created_at,
            ))

        return self.load(artifact_id)

    def load(self, artifact_id):
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM artifacts WHERE artifact_id = ?",
                (artifact_id,),
            ).fetchone()

        if row is None:
            raise KeyError("Artifact not found")

        source_ids = json.loads(row["source_ids"])
        source_labels = json.loads(row["source_labels"])
        if not source_ids or len(source_ids) != len(source_labels):
            raise ValueError("Corrupt provenance metadata")

        expected = highest_label([
            SecurityLabel.parse(label) for label in source_labels
        ])
        stored = SecurityLabel.parse(row["label"])
        if stored != expected:
            raise ValueError("Artifact label does not match source sensitivity")

        return {
            "artifact_id": row["artifact_id"],
            "content": row["content"],
            "label": stored.name,
            "source_ids": source_ids,
            "source_labels": source_labels,
            "transformation": row["transformation"],
            "created_at": row["created_at"],
        }
