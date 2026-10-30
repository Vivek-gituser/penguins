from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field


class AuditEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timestamp: datetime
    agent_id: str = Field(min_length=1)
    operation: str = Field(min_length=1)
    resource: str = Field(min_length=1)
    recipient: str = ""
    data_label: str = Field(min_length=1)
    decision: str = Field(min_length=1)
    reason: str = Field(min_length=1)
    execution_status: str = Field(min_length=1)


class ArtifactRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    artifact_id: str = Field(min_length=1)
    content: str
    label: str = Field(min_length=1)
    source_ids: list[str] = Field(min_length=1)
    transformation: str = Field(min_length=1)
    created_at: datetime
