"""Workspace file storage confined to one approved directory.

Files are written under a system-generated name, so the name a caller
supplies is only ever metadata. Reads still re-validate every supplied
name and re-check containment, because a workspace path must never be
turned into a path outside the workspace - regardless of what the index
says. Sensitivity comes from the trusted source registry, and a generated
file inherits the highest label of the material it was built from.
"""

import hashlib
import json
import re
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

from security.labels import SecurityLabel, highest_label

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_ROOT = REPO_ROOT / "workspace_files"
DB_PATH = REPO_ROOT / "database" / "agentgate.db"

MAX_FILE_BYTES = 2_000_000
MAX_DISPLAY_NAME_CHARS = 120

UPLOAD_SUFFIXES = (".txt", ".md", ".log", ".csv", ".json", ".pdf", ".docx")
GENERATED_SUFFIXES = (".pdf", ".pptx")
SUPPORTED_SUFFIXES = UPLOAD_SUFFIXES + tuple(
    suffix for suffix in GENERATED_SUFFIXES if suffix not in UPLOAD_SUFFIXES
)

_UNSAFE_NAME = re.compile(r"[^A-Za-z0-9._-]")


class WorkspaceError(ValueError):
    """A file request was refused before it touched the filesystem."""


class SecureFileWorkspace:
    def __init__(self, root=WORKSPACE_ROOT, artifact_store=None,
                 db_path=DB_PATH, max_bytes=MAX_FILE_BYTES):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.artifact_store = artifact_store
        self.db_path = str(db_path)
        self.max_bytes = max_bytes

        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.execute("""
                CREATE TABLE IF NOT EXISTS workspace_files (
                    file_id TEXT PRIMARY KEY,
                    display_name TEXT NOT NULL,
                    stored_name TEXT NOT NULL,
                    suffix TEXT NOT NULL,
                    category TEXT NOT NULL,
                    label TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    source_ids TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    sha256 TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)

    def _connect(self):
        db = sqlite3.connect(self.db_path, timeout=10)
        db.row_factory = sqlite3.Row
        return db

    # ---------- path safety ----------
    @staticmethod
    def validate_name(name):
        """Reject anything that is not a single plain file name."""
        if not isinstance(name, str) or not name.strip():
            raise WorkspaceError("A file name is required")

        candidate = name.strip()

        if len(candidate) > MAX_DISPLAY_NAME_CHARS:
            raise WorkspaceError("That file name is too long")
        if "\x00" in candidate:
            raise WorkspaceError("That file name contains a null byte")
        if ".." in candidate:
            raise WorkspaceError("Path traversal is rejected")
        if candidate.startswith(".") or candidate.startswith("~"):
            raise WorkspaceError("Hidden or home-relative names are rejected")
        if "/" in candidate or "\\" in candidate or ":" in candidate:
            raise WorkspaceError("Directory separators are rejected")
        if _UNSAFE_NAME.search(candidate):
            raise WorkspaceError(
                "File names may only contain letters, numbers, dot, dash "
                "and underscore"
            )

        return candidate

    @staticmethod
    def validate_suffix(suffix, allowed=SUPPORTED_SUFFIXES):
        cleaned = (suffix or "").strip().lower()
        if not re.fullmatch(r"\.[a-z0-9]{1,5}", cleaned or ""):
            raise WorkspaceError(
                "Unsupported file type. Allowed types: "
                + ", ".join(allowed)
            )
        if cleaned not in allowed:
            raise WorkspaceError(
                f"Files of type '{cleaned}' are not supported in the "
                "workspace. Allowed: " + ", ".join(allowed)
            )
        return cleaned

    @staticmethod
    def _suffix_of(name):
        return f".{name.rsplit('.', 1)[-1]}" if "." in name else ""

    def _resolve(self, stored_name):
        """Containment, independent of whatever the index claims."""
        self.validate_name(stored_name)

        candidate = (self.root / stored_name).resolve()

        if not candidate.is_relative_to(self.root):
            raise WorkspaceError("That path escapes the workspace directory")
        if candidate.exists() and not candidate.is_file():
            raise WorkspaceError("That workspace entry is not a regular file")

        return candidate

    # ---------- trusted labels ----------
    def _inherit_label(self, source_ids, claimed_label=None):
        """A derived file can only ever be as sensitive as its sources."""
        if self.artifact_store is None or not source_ids:
            if claimed_label is None:
                raise WorkspaceError(
                    "A generated file needs a trusted classification"
                )
            return SecurityLabel.parse(claimed_label)

        trusted = [
            self.artifact_store.get_trusted_source_label(source_id)
            for source_id in source_ids
        ]
        effective = highest_label(*trusted)

        if claimed_label is not None:
            claimed = SecurityLabel.parse(claimed_label)
            if claimed < effective:
                raise WorkspaceError(
                    "Refusing to lower the classification: the source "
                    f"material is {effective.name}, not {claimed.name}"
                )

        return effective

    # ---------- writes ----------
    def _write(self, display_name, data, category, label, source_id,
               source_ids, allowed=SUPPORTED_SUFFIXES):
        if not isinstance(data, (bytes, bytearray)):
            raise WorkspaceError("File content must be bytes")
        if len(data) == 0:
            raise WorkspaceError("Refusing to store an empty file")
        if len(data) > self.max_bytes:
            raise WorkspaceError(
                f"That file is larger than the {self.max_bytes // 1000} KB "
                "workspace limit"
            )

        name = self.validate_name(display_name)
        suffix = self.validate_suffix(self._suffix_of(name), allowed)

        file_id = str(uuid.uuid4())
        stored_name = f"{file_id}{suffix}"
        path = self._resolve(stored_name)

        with self._connect() as db:
            existing = db.execute(
                "SELECT 1 FROM workspace_files WHERE stored_name = ?",
                (stored_name,),
            ).fetchone()
        if existing:
            raise WorkspaceError("That workspace file already exists")

        # Written atomically inside the approved directory only.
        path.write_bytes(bytes(data))

        record = {
            "file_id": file_id,
            "display_name": name,
            "stored_name": stored_name,
            "suffix": suffix,
            "category": category,
            "label": label.name,
            "source_id": source_id,
            "source_ids": list(source_ids),
            "size_bytes": len(data),
            "sha256": hashlib.sha256(bytes(data)).hexdigest(),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        with self._connect() as db:
            db.execute(
                """
                INSERT INTO workspace_files (
                    file_id, display_name, stored_name, suffix, category,
                    label, source_id, source_ids, size_bytes, sha256,
                    created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    file_id, name, stored_name, suffix, category,
                    label.name, source_id,
                    json.dumps(record["source_ids"]),
                    record["size_bytes"], record["sha256"],
                    record["created_at"],
                ),
            )

        return record

    def ingest(self, display_name, data, label):
        """Store an uploaded document under the operator's classification.

        The label comes from the human who supplied the file. Document text
        never classifies itself and never registers its own source.
        """
        parsed_label = SecurityLabel.parse(label)

        source_id = f"upload-{uuid.uuid4().hex[:12]}"

        if self.artifact_store is not None:
            # Trusted ingestion: the classification is registered here, in
            # application code, before the bytes are ever read again.
            self.artifact_store.register_source(source_id, parsed_label.name)

        return self._write(display_name, data, "upload", parsed_label,
                           source_id, [source_id], allowed=UPLOAD_SUFFIXES)

    def store_generated(self, display_name, data, source_ids,
                        claimed_label=None, transformation="file_export"):
        """Store a generated document, inheriting its source sensitivity."""
        ids = [str(source_id) for source_id in (source_ids or [])]
        if not ids:
            raise WorkspaceError(
                "A generated file needs the source material it came from"
            )

        label = self._inherit_label(ids, claimed_label)

        if self.artifact_store is not None:
            self.artifact_store.save(
                content=_preview_text(data, display_name),
                source_ids=ids,
                source_labels=[
                    self.artifact_store.get_trusted_source_label(source_id).name
                    for source_id in ids
                ],
                transformation=transformation,
            )

        return self._write(
            display_name, data, "generated", label,
            f"generated-{uuid.uuid4().hex[:12]}", ids,
            allowed=GENERATED_SUFFIXES,
        )

    # ---------- reads ----------
    def list_files(self, category=None, limit=200):
        if not isinstance(limit, int) or isinstance(limit, bool):
            raise WorkspaceError("Invalid listing limit")
        if not 1 <= limit <= 1000:
            raise WorkspaceError("Listing limit must be between 1 and 1000")

        clause = ""
        params = []
        if category:
            clause = "WHERE category = ?"
            params.append(str(category))

        with self._connect() as db:
            rows = db.execute(
                f"""
                SELECT * FROM workspace_files {clause}
                ORDER BY created_at DESC LIMIT ?
                """,
                (*params, limit),
            ).fetchall()

        return [self._record(row) for row in rows]

    def get(self, file_ref):
        """Look a file up by ID, or by the exact name shown to the user."""
        ref = (str(file_ref) if file_ref is not None else "").strip()
        if not ref:
            raise WorkspaceError("A file reference is required")

        params = (ref,)
        clause = "file_id = ?"
        if not re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            ref.lower(),
        ):
            clause = "display_name = ? OR stored_name = ? OR source_id = ?"
            params = (ref, ref, ref)

        ordering = "" if clause == "file_id = ?" else " ORDER BY created_at DESC"

        with self._connect() as db:
            row = db.execute(
                f"SELECT * FROM workspace_files WHERE {clause}{ordering} LIMIT 1",
                params,
            ).fetchone()

        if row is None:
            # Still run the containment check, so an unsafe reference is
            # refused for the right reason instead of silently missing.
            self._resolve(ref)
            raise WorkspaceError(
                f"No such workspace file: {ref}. Upload it first."
            )

        return self._record(row)

    def read_bytes(self, file_ref):
        record = self.get(file_ref)
        path = self._resolve(record["stored_name"])

        if not path.exists():
            raise WorkspaceError("That workspace file is no longer present")

        data = path.read_bytes()

        if hashlib.sha256(data).hexdigest() != record["sha256"]:
            raise WorkspaceError(
                "Workspace file integrity check failed; content was not released"
            )

        return record, data

    def read_text(self, file_ref):
        from tools.text_extractor import extract_text

        record, data = self.read_bytes(file_ref)
        text = extract_text(record["suffix"], data)
        return record, text

    def _record(self, row):
        try:
            source_ids = json.loads(row["source_ids"])
        except (ValueError, TypeError):
            source_ids = []

        return {
            "file_id": row["file_id"],
            "display_name": row["display_name"],
            "stored_name": row["stored_name"],
            "suffix": row["suffix"],
            "category": row["category"],
            "label": row["label"],
            "source_id": row["source_id"],
            "source_ids": source_ids,
            "size_bytes": row["size_bytes"],
            "sha256": row["sha256"],
            "created_at": row["created_at"],
        }


def _preview_text(data, display_name):
    """A short, honest stand-in so a binary export still has provenance."""
    suffix = ("." + display_name.rsplit(".", 1)[-1].lower()
              if "." in display_name else "")
    if suffix == ".pdf" and data[:5] == b"%PDF-":
        return f"[PDF export] {len(data)} bytes, header {data[:8]!r}"
    if suffix == ".pptx" and data[:2] == b"PK":
        return f"[PowerPoint export] {len(data)} bytes, OOXML container"
    return f"[binary export {suffix or 'unknown'}] {len(data)} bytes"
