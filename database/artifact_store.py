import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

from security.labels import SecurityLabel, highest_label


class ArtifactStore:
    """SQLite artifact storage with trusted source-label verification."""

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
            conn.execute("""
                CREATE TABLE IF NOT EXISTS trusted_sources (
                    source_id TEXT PRIMARY KEY,
                    label TEXT NOT NULL,
                    registered_at TEXT NOT NULL
                )
            """)

        # Trusted demo sources. These labels come from application
        # configuration, never from document instructions or UI input.
        self.register_source("sample_internal", "INTERNAL")
        self.register_source("sample_prompt_injection", "INTERNAL")

    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def register_source(self, source_id, label):
        """Trusted setup/ingestion code only; never expose to agents."""
        if not isinstance(source_id, str) or not source_id.strip():
            raise ValueError("Invalid source ID")

        parsed_label = SecurityLabel.parse(label)
        registered_at = datetime.now(timezone.utc).isoformat()

        with self._connect() as conn:
            existing = conn.execute(
                "SELECT label FROM trusted_sources WHERE source_id = ?",
                (source_id.strip(),)
            ).fetchone()

            if existing:
                if existing["label"] != parsed_label.name:
                    raise ValueError("Source label cannot be silently changed")
                return

            conn.execute("""
                INSERT INTO trusted_sources (source_id, label, registered_at)
                VALUES (?, ?, ?)
            """, (source_id.strip(), parsed_label.name, registered_at))

    def get_trusted_source_label(self, source_id):
        with self._connect() as conn:
            row = conn.execute(
                "SELECT label FROM trusted_sources WHERE source_id = ?",
                (source_id,)
            ).fetchone()

        if row is None:
            raise ValueError(f"Unregistered source: {source_id}")

        return SecurityLabel.parse(row["label"])

    def save(self, content, source_ids, source_labels, transformation):
        if not isinstance(content, str) or not content.strip():
            raise ValueError("Artifact content cannot be empty")

        if not isinstance(source_ids, (list, tuple)) or not source_ids:
            raise ValueError("At least one trusted source is required")

        if not isinstance(source_labels, (list, tuple)):
            raise ValueError("Source labels must be a list")

        if len(source_ids) != len(source_labels):
            raise ValueError("Every source must have an ID and a label")

        if not isinstance(transformation, str) or not transformation.strip():
            raise ValueError("Transformation description is required")

        if any(not isinstance(s, str) or not s.strip() for s in source_ids):
            raise ValueError("Invalid source ID")

        if len(set(source_ids)) != len(source_ids):
            raise ValueError("Duplicate source IDs are not allowed")

        # Never trust caller-provided labels. Resolve labels from the
        # trusted source registry and reject any mismatch.
        trusted_labels = [
            self.get_trusted_source_label(source_id.strip())
            for source_id in source_ids
        ]

        supplied_labels = [
            SecurityLabel.parse(label) for label in source_labels
        ]

        if supplied_labels != trusted_labels:
            raise ValueError("Provided labels do not match trusted source labels")

        effective = highest_label(trusted_labels)
        artifact_id = str(uuid.uuid4())
        created_at = datetime.now(timezone.utc).isoformat()

        with self._connect() as conn:
            conn.execute("""
                INSERT INTO artifacts VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                artifact_id,
                content,
                effective.name,
                json.dumps([s.strip() for s in source_ids]),
                json.dumps([label.name for label in trusted_labels]),
                transformation.strip(),
                created_at,
            ))

        return self.load(artifact_id)

    def load(self, artifact_id):
        if not isinstance(artifact_id, str) or not artifact_id.strip():
            raise ValueError("Invalid artifact ID")

        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM artifacts WHERE artifact_id = ?",
                (artifact_id.strip(),),
            ).fetchone()

        if row is None:
            raise KeyError("Artifact not found")

        source_ids = json.loads(row["source_ids"])
        source_labels = json.loads(row["source_labels"])

        if (
            not source_ids
            or len(source_ids) != len(source_labels)
            or any(not isinstance(s, str) or not s for s in source_ids)
        ):
            raise ValueError("Corrupt provenance metadata")

        # Recheck every source against the trusted registry on reload.
        trusted_labels = [
            self.get_trusted_source_label(source_id)
            for source_id in source_ids
        ]

        stored_source_labels = [
            SecurityLabel.parse(label) for label in source_labels
        ]

        if trusted_labels != stored_source_labels:
            raise ValueError("Stored provenance does not match trusted sources")

        expected = highest_label(trusted_labels)
        stored = SecurityLabel.parse(row["label"])

        if stored != expected:
            raise ValueError("Artifact label does not match source sensitivity")

        return {
            "artifact_id": row["artifact_id"],
            "content": row["content"],
            "label": stored.name,
            "source_ids": source_ids,
            "source_labels": [label.name for label in trusted_labels],
            "transformation": row["transformation"],
            "created_at": row["created_at"],
        }
