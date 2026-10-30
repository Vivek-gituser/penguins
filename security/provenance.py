from dataclasses import dataclass, field
from datetime import datetime, timezone
from security.labels import SecurityLabel, highest_label

@dataclass
class Provenance:
    source_ids: list
    source_labels: list
    created_by: str = "system"
    transformation: str = "original"
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def effective_label(self):
        if not self.source_labels:
            raise ValueError("Missing source labels: refusing to downgrade")
        return highest_label(*self.source_labels)

    @classmethod
    def derive(cls, artifact_id, parents, transformation, created_by="system"):
        if not parents:
            raise ValueError("Derived artifacts require source provenance")
        return cls(
            source_ids=[sid for p in parents for sid in p.source_ids] + [artifact_id],
            source_labels=[p.effective_label for p in parents],
            created_by=created_by,
            transformation=transformation
        )
