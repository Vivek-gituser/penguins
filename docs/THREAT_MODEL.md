# Threat Model

## Assets
- Confidential source documents.
- Derived reports and their sensitivity labels.
- Agent identities and authorization policies.
- Recipient authorization data.
- Audit events and provenance metadata.

## Trust boundaries
1. Agent-generated action proposals are untrusted.
2. Document contents and retrieved text are untrusted.
3. Tool outputs are data and cannot modify authorization policy.
4. Policy configuration and registered tool implementations are trusted.
5. SQLite persistence is local demo storage and requires OS-level protection.

## Threats and mitigations

| Threat | Mitigation |
|---|---|
| Prompt injection in a document | Treat document text as untrusted data |
| Unauthorized tool call | Deterministic policy evaluation |
| Caller supplies a malicious callable | Trusted tool registry |
| Unknown agent or recipient | Default deny |
| Sensitivity downgrade by summarization | Highest-source-label inheritance |
| Tampered artifact label | Recompute and validate on load |
| Missing provenance | Reject malformed artifact metadata |
| Audit gaps | Persist execution decision and outcome |

## Known prototype limitations
- Dashboard-entered source labels are not an authoritative classification system.
- Local SQLite is not tamper-proof against a machine administrator.
- No production identity provider or cryptographic audit signing is configured.
- Approval workflow is not a production human identity/approval service.
- No real external email or document service is connected.

## Production requirements
- Trusted source-label registry and controlled classification workflow.
- Authenticated agent identities and least-privilege policy management.
- Append-only or externally protected audit storage.
- Secrets management, encryption at rest, and deployment isolation.
- Security review and adversarial testing before production use.
