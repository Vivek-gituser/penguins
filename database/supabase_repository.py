
from datetime import datetime, timezone
import uuid

from database.supabase_client import get_supabase_client
from security.labels import SecurityLabel, highest_label


class SupabaseRepository:
    """Trusted backend repository for AGENTGATE artifacts and audit events."""

    def __init__(self, client=None):
        self.client = client or get_supabase_client()

    # ---------------------------------------------------------
    # TRUSTED SOURCES
    # ---------------------------------------------------------

    def get_trusted_source_label(self, source_id):
        if not isinstance(source_id, str) or not source_id.strip():
            raise ValueError("Invalid source ID")

        response = (
            self.client.table("trusted_sources")
            .select("source_id,label")
            .eq("source_id", source_id.strip())
            .limit(1)
            .execute()
        )

        if not response.data:
            raise ValueError(f"Unregistered source: {source_id}")

        return SecurityLabel.parse(response.data[0]["label"])

    # ---------------------------------------------------------
    # ARTIFACT SAVE
    # ---------------------------------------------------------

    def save_artifact(self, content, source_ids, source_labels, transformation):
        if not isinstance(content, str) or not content.strip():
            raise ValueError("Artifact content cannot be empty")

        if not isinstance(source_ids, (list, tuple)) or not source_ids:
            raise ValueError("At least one trusted source is required")

        if not isinstance(source_labels, (list, tuple)):
            raise ValueError("Source labels must be a list")

        if len(source_ids) != len(source_labels):
            raise ValueError("Every source must have an ID and label")

        if not isinstance(transformation, str) or not transformation.strip():
            raise ValueError("Transformation is required")

        if any(not isinstance(s, str) or not s.strip() for s in source_ids):
            raise ValueError("Invalid source ID")

        normalized_ids = [s.strip() for s in source_ids]

        if len(set(normalized_ids)) != len(normalized_ids):
            raise ValueError("Duplicate source IDs are not allowed")

        trusted_labels = [
            self.get_trusted_source_label(source_id)
            for source_id in normalized_ids
        ]

        supplied_labels = [
            SecurityLabel.parse(label) for label in source_labels
        ]

        if supplied_labels != trusted_labels:
            raise ValueError(
                "Provided labels do not match trusted source labels"
            )

        effective_label = highest_label(trusted_labels)

        artifact_response = (
            self.client.table("artifacts")
            .insert({
                "content": content,
                "sensitivity": effective_label.name,
                "transformation": transformation.strip(),
            })
            .execute()
        )

        if not artifact_response.data:
            raise RuntimeError("Artifact insert returned no record")

        artifact_id = artifact_response.data[0]["id"]

        try:
            source_rows = [
                {
                    "artifact_id": artifact_id,
                    "source_id": source_id,
                    "source_sensitivity": label.name,
                }
                for source_id, label in zip(normalized_ids, trusted_labels)
            ]

            self.client.table("artifact_sources").insert(
                source_rows
            ).execute()

        except Exception:
            try:
                self.client.table("artifacts").delete().eq(
                    "id", artifact_id
                ).execute()
            except Exception:
                pass
            raise

        return self.load_artifact(artifact_id)

    # ---------------------------------------------------------
    # ARTIFACT LOAD + PROVENANCE VALIDATION
    # ---------------------------------------------------------

    def load_artifact(self, artifact_id):
        if not isinstance(artifact_id, str) or not artifact_id.strip():
            raise ValueError("Invalid artifact ID")

        try:
            artifact_id = str(uuid.UUID(artifact_id.strip()))
        except (ValueError, TypeError, AttributeError):
            raise ValueError("Invalid artifact ID")

        response = (
            self.client.table("artifacts")
            .select("*")
            .eq("id", artifact_id)
            .limit(1)
            .execute()
        )

        if not response.data:
            raise KeyError("Artifact not found")

        artifact = response.data[0]

        source_response = (
            self.client.table("artifact_sources")
            .select("source_id,source_sensitivity")
            .eq("artifact_id", artifact_id)
            .execute()
        )

        sources = source_response.data or []

        if not sources:
            raise ValueError("Artifact has no provenance records")

        source_ids = [row["source_id"] for row in sources]

        if (
            any(not isinstance(s, str) or not s.strip() for s in source_ids)
            or len(set(source_ids)) != len(source_ids)
        ):
            raise ValueError(
                "Invalid or duplicate provenance source IDs"
            )

        stored_labels = [
            SecurityLabel.parse(row["source_sensitivity"])
            for row in sources
        ]

        trusted_labels = [
            self.get_trusted_source_label(source_id)
            for source_id in source_ids
        ]

        if stored_labels != trusted_labels:
            raise ValueError(
                "Stored provenance does not match trusted registry"
            )

        # Original sensitivity comes from trusted sources.
        effective_label = highest_label(trusted_labels)

        # Retrieve complete declassification history.
        history_response = (
            self.client.table("declassification_events")
            .select(
                "id,previous_label,new_label,reviewer_id,reason,created_at"
            )
            .eq("artifact_id", artifact_id)
            .order("created_at")
            .order("id")
            .execute()
        )

        history = history_response.data or []

        # Verify every historical downgrade in sequence.
        for event in history:
            previous = SecurityLabel.parse(event["previous_label"])
            new = SecurityLabel.parse(event["new_label"])

            if previous != effective_label:
                raise ValueError(
                    "Declassification history contains a broken label chain"
                )

            if new >= previous:
                raise ValueError(
                    "Declassification history contains an invalid downgrade"
                )

            reason = event.get("reason")
            reviewer_id = event.get("reviewer_id")

            if not isinstance(reason, str) or len(reason.strip()) < 10:
                raise ValueError("Invalid declassification reason")

            try:
                uuid.UUID(str(reviewer_id))
            except (ValueError, TypeError, AttributeError):
                raise ValueError("Invalid declassification reviewer ID")

            effective_label = new

        stored_artifact_label = SecurityLabel.parse(
            artifact["sensitivity"]
        )

        if stored_artifact_label != effective_label:
            raise ValueError(
                "Artifact sensitivity does not match verified provenance history"
            )

        return {
            "artifact_id": artifact["id"],
            "content": artifact["content"],
            "label": stored_artifact_label.name,
            "source_ids": source_ids,
            "source_labels": [label.name for label in trusted_labels],
            "transformation": artifact["transformation"],
            "created_at": artifact["created_at"],
            "declassification_history": history,
        }

    # ---------------------------------------------------------
    # DECLASSIFICATION
    # ---------------------------------------------------------

    def list_declassification_events(self, artifact_id):
        """Return history after verifying artifact provenance."""

        try:
            artifact_id = str(uuid.UUID(str(artifact_id)))
        except (ValueError, TypeError, AttributeError):
            raise ValueError("Invalid artifact ID")

        artifact = self.load_artifact(artifact_id)

        return artifact["declassification_history"]

    def declassify_artifact(
        self,
        artifact_id,
        new_label,
        reviewer_id,
        reason,
    ):
        """
        Request a database-enforced downgrade.

        The caller must first verify the authenticated reviewer session.
        """

        try:
            artifact_id = str(uuid.UUID(str(artifact_id)))
            reviewer_id = str(uuid.UUID(str(reviewer_id)))
        except (ValueError, TypeError, AttributeError):
            raise ValueError("Invalid artifact or reviewer ID")

        if not isinstance(reason, str) or len(reason.strip()) < 10:
            raise ValueError(
                "A meaningful reason of at least 10 characters is required"
            )

        requested_label = SecurityLabel.parse(new_label)

        # Verify current provenance and history before the RPC.
        artifact = self.load_artifact(artifact_id)
        previous_label = SecurityLabel.parse(artifact["label"])

        if requested_label >= previous_label:
            raise ValueError(
                "Only a lower security label can be requested"
            )

        response = self.client.rpc(
            "declassify_artifact",
            {
                "p_artifact_id": artifact_id,
                "p_previous_label": previous_label.name,
                "p_new_label": requested_label.name,
                "p_reviewer_id": reviewer_id,
                "p_reason": reason.strip(),
            },
        ).execute()

        result = response.data

        if not result:
            raise RuntimeError(
                "Declassification function returned no result"
            )

        # Reload and independently verify the resulting artifact.
        verified_artifact = self.load_artifact(artifact_id)

        if verified_artifact["label"] != requested_label.name:
            raise RuntimeError(
                "Declassification failed post-operation verification"
            )

        return {
            "event": result,
            "artifact": verified_artifact,
        }

    # ---------------------------------------------------------
    # COMPATIBILITY METHODS
    # ---------------------------------------------------------

    def save(self, content, source_ids, source_labels, transformation):
        return self.save_artifact(
            content, source_ids, source_labels, transformation
        )

    def load(self, artifact_id):
        return self.load_artifact(artifact_id)

    # ---------------------------------------------------------
    # AUDIT EVENTS
    # ---------------------------------------------------------

    def write_audit_event(self, req, decision, reason, status):
        if not isinstance(reason, str) or not isinstance(status, str):
            raise ValueError("Invalid audit reason or execution status")

        label = SecurityLabel.parse(req.data_label)

        payload = {
            "agent_id": req.agent_id,
            "operation": req.operation,
            "resource": req.resource,
            "recipient": req.recipient,
            "data_label": label.name,
            "decision": str(getattr(decision, "value", decision)),
            "reason": reason,
            "execution_status": status,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        response = (
            self.client.table("audit_events")
            .insert(payload)
            .execute()
        )

        if not response.data:
            raise RuntimeError("Audit event was not persisted")

        return response.data[0]

    def list_audit_events(self, limit=100):
        if not isinstance(limit, int) or isinstance(limit, bool):
            raise ValueError("Limit must be an integer")

        if not 1 <= limit <= 1000:
            raise ValueError("Limit must be between 1 and 1000")

        response = (
            self.client.table("audit_events")
            .select("*")
            .order("created_at", desc=True)
            .limit(limit)
            .execute()
        )

        return response.data or []

    # ---------------------------------------------------------
    # APPROVAL REQUESTS
    # ---------------------------------------------------------

    @staticmethod
    def _approval_request_fields(request):
        if not all(
            isinstance(value, str) and value.strip()
            for value in (
                request.agent_id,
                request.operation,
                request.resource,
                request.recipient,
            )
        ):
            raise ValueError("Invalid approval action fields")

        return {
            "agent_id": request.agent_id,
            "operation": request.operation,
            "resource": request.resource,
            "recipient": request.recipient,
            "data_label": SecurityLabel.parse(
                request.data_label
            ).name,
        }

    def create(self, request, expiry_minutes=15):
        from datetime import timedelta

        if (
            not isinstance(expiry_minutes, int)
            or isinstance(expiry_minutes, bool)
            or not 1 <= expiry_minutes <= 1440
        ):
            raise ValueError("Invalid approval expiry")

        fields = self._approval_request_fields(request)
        now = datetime.now(timezone.utc)

        payload = {
            "id": str(uuid.uuid4()),
            **fields,
            "status": "PENDING",
            "created_at": now.isoformat(),
            "expires_at": (
                now + timedelta(minutes=expiry_minutes)
            ).isoformat(),
        }

        response = (
            self.client.table("approval_requests")
            .insert(payload)
            .execute()
        )

        if not response.data:
            raise RuntimeError("Approval request was not persisted")

        return response.data[0]

    def get(self, approval_id):
        try:
            approval_id = str(uuid.UUID(str(approval_id)))
        except (ValueError, TypeError, AttributeError):
            raise ValueError("Invalid approval ID")

        response = (
            self.client.table("approval_requests")
            .select("*")
            .eq("id", approval_id)
            .limit(1)
            .execute()
        )

        if not response.data:
            raise ValueError("Approval request not found")

        return response.data[0]

    def list_pending(self, limit=100):
        if (
            not isinstance(limit, int)
            or isinstance(limit, bool)
            or not 1 <= limit <= 1000
        ):
            raise ValueError("Invalid approval limit")

        now = datetime.now(timezone.utc).isoformat()

        self.client.table("approval_requests").update({
            "status": "EXPIRED"
        }).eq(
            "status", "PENDING"
        ).lte(
            "expires_at", now
        ).execute()

        response = (
            self.client.table("approval_requests")
            .select("*")
            .eq("status", "PENDING")
            .order("created_at", desc=True)
            .limit(limit)
            .execute()
        )

        return response.data or []

    def review(self, approval_id, decision, reviewer_id):
        try:
            approval_id = str(uuid.UUID(str(approval_id)))
            reviewer_id = str(uuid.UUID(str(reviewer_id)))
        except (ValueError, TypeError, AttributeError):
            raise ValueError(
                "Approval and reviewer IDs must be valid UUIDs"
            )

        if decision not in ("APPROVED", "REJECTED"):
            raise ValueError("Invalid approval decision")

        now = datetime.now(timezone.utc).isoformat()

        response = (
            self.client.table("approval_requests")
            .update({
                "status": decision,
                "reviewed_by": reviewer_id,
            })
            .eq("id", approval_id)
            .eq("status", "PENDING")
            .gt("expires_at", now)
            .select("*")
            .execute()
        )

        if not response.data:
            raise ValueError(
                "Approval is missing, expired, or already reviewed"
            )

        return response.data[0]

    def consume_approved(self, approval_id, request):
        """Consume one approved ticket bound to an exact action."""

        try:
            approval_id = str(uuid.UUID(str(approval_id)))
        except (ValueError, TypeError, AttributeError):
            raise ValueError("Invalid approval ID")

        expected = self._approval_request_fields(request)
        now = datetime.now(timezone.utc).isoformat()

        record = self.get(approval_id)

        actual = {
            key: record[key]
            for key in expected
        }

        if actual != expected:
            raise ValueError(
                "Approval does not match this exact action"
            )

        if record["status"] != "APPROVED":
            raise ValueError("Approval is not approved")

        expiry = datetime.fromisoformat(
            record["expires_at"].replace("Z", "+00:00")
        )

        if expiry <= datetime.now(timezone.utc):
            self.client.table("approval_requests").update({
                "status": "EXPIRED"
            }).eq(
                "id", approval_id
            ).eq(
                "status", "APPROVED"
            ).execute()

            raise ValueError("Approval has expired")

        response = (
            self.client.table("approval_requests")
            .delete()
            .eq("id", approval_id)
            .eq("status", "APPROVED")
            .eq("agent_id", expected["agent_id"])
            .eq("operation", expected["operation"])
            .eq("resource", expected["resource"])
            .eq("recipient", expected["recipient"])
            .eq("data_label", expected["data_label"])
            .gt("expires_at", now)
            .select("*")
            .execute()
        )

        if not response.data:
            raise ValueError(
                "Approval could not be consumed; it may have expired or been used"
            )

        return response.data[0]
