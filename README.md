# AGENTGATE — Security Gateway for AI Actions

AGENTGATE is a local demonstration of a deterministic security gateway
for AI-agent tool actions and information-flow control.

## Core design

An AI agent may propose an action, but it cannot authorize that action.
Every tool operation must pass through a trusted gateway and policy engine.

```text
Agent proposal
     |
     v
Action request
     |
     v
Deterministic policy engine
     |
     +---- BLOCK
     |
     +---- REQUIRE_APPROVAL
     |
     +---- ALLOW
              |
              v
       Trusted tool registry
              |
              v
        Audit database
```

## Security controls

- Default-deny authorization.
- Explicit agent, operation, resource and recipient checks.
- Trusted tool registry to prevent caller-supplied tool execution.
- Sensitivity labels: PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED.
- Derived artifacts inherit the highest source sensitivity.
- Provenance metadata persists with saved artifacts.
- Artifact labels are checked again when artifacts are loaded.
- Document content is treated as untrusted data, not policy.
- Mock inbox delivery is a simulation, not real email delivery.
- Human approvals are one-time, expiring tickets bound to the exact action.
- A policy denial can never be overridden by an approval, and policy is
  rechecked immediately before the tool runs.
- Permission changes are reviewer-only, tighten-only, and audited.

## Trusted policy

One policy is enforced: the trusted `demo_policy()` in
`security/policy_engine.py`. It is owned by the application, never by an
agent, a model or a document. Outbound `deliver` actions route to a human
reviewer; reads and report saves that pass every check execute immediately.

`Access Control` layers tighten-only overrides on top of it (revoke an agent
operation, disable an operation on a resource, de-authorize a recipient, or
require approval for an operation). Overrides can remove access or add
friction; they can never grant access. If the override store cannot be read,
requests fail closed.

## Approval workflow

1. The interpreter proposes an action and the gateway evaluates it.
2. `REQUIRE_APPROVAL` writes a pending ticket (agent, operation, resource,
   recipient, sensitivity, expiry) and the protected tool does not run.
3. An authenticated reviewer approves or rejects it in `Approval Center`.
4. On approval the gateway re-evaluates policy, consumes the ticket exactly
   once, then executes the registered tool and records the audit trail.

Rejected, expired, replayed, or mismatched tickets never execute. Audit or
approval-storage failures block execution.

## Dashboard pages

`Overview`, `AI Workspace`, `Agent Chat`, `Action Simulator`,
`Prompt Injection Lab`, `Information Flow`, `Artifact Vault`, `Audit Center`,
`Approval Center`, `Access Control`, and `Declassification Center` when a
cloud reviewer is signed in with the Supabase backend.

## Configuration

Optional values live in `.env` (see `.env.example`); nothing secret is
rendered in the UI, logs, or audit records.

- `SUPABASE_URL` / `SUPABASE_KEY` — cloud audit and reviewer allowlist.
- `GEMINI_API_KEY` / `GEMINI_MODEL` — optional model interpreter. Without a
  key the deterministic interpreter is used, so the demo never depends on
  network access.
- `AGENTGATE_REVIEWER_PASSWORD` — unlocks the local reviewer for the SQLite
  demo database. When unset, local reviewing is disabled.

## Project structure

- `security/` — policy, labels, provenance and content trust controls.
- `gateway.py` — trusted execution gateway.
- `agent/` — deterministic research agent and the AI workspace engine.
- `ai/` — optional Gemini proposer with guaranteed offline fallback.
- `tools/` — document reader, report saver and mock inbox.
- `database/` — audit, artifact, approval and permission persistence.
- `tests/` — authorization, information-flow, approval, persistence,
  interpreter and integrity tests.
- `app.py` — Streamlit demonstration dashboard.

## Setup

Python 3.10 or newer is recommended.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
pytest -q
streamlit run app.py
```

`pytest -q` runs the whole suite from the repository root. Every enforcement
claim above is covered there, including approval execution, rejection,
expiry, replay prevention, policy rechecks and unauthorized tool execution.

## Demo limitations

This is a hackathon prototype, not a production security boundary.
The dashboard's manually entered source labels are demonstration inputs.
A production deployment must obtain labels from a trusted source registry,
authenticate agent identities, protect policy configuration, and prevent
untrusted users from registering or changing source classifications.

The mock inbox does not send real messages. Replay and demo operations
must not be represented as live external execution.

Additional known limits:

- A parked delivery's report body is re-supplied from the session that created
  it. After a restart the reviewer still approves and executes the bound
  action, but the body falls back to a generic demonstration message.
- The local reviewer credential is a single shared demo password, not an
  identity provider. Cloud reviewing still requires the Supabase allowlist.
- Injection detection is advisory. It labels suspicious text for the reviewer;
  enforcement always comes from the gateway, which never accepts a proposal as
  authorization.
- PDF upload needs the optional `pypdf` package; text uploads always work.
- `database/agentgate.db` accumulates audit, artifact and approval rows across
  runs. Delete the file for a clean demonstration.

## Security principle

The LLM proposes. The deterministic policy engine decides.
No model-generated text, document instruction, or tool output can
override trusted authorization policy.
