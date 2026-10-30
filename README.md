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

## Project structure

- `security/` — policy, labels, provenance and content trust controls.
- `gateway.py` — trusted execution gateway.
- `tools/` — document reader, report saver and mock inbox.
- `database/` — audit and artifact persistence.
- `tests/` — authorization, information-flow, persistence and integrity tests.
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

## Demo limitations

This is a hackathon prototype, not a production security boundary.
The dashboard's manually entered source labels are demonstration inputs.
A production deployment must obtain labels from a trusted source registry,
authenticate agent identities, protect policy configuration, and prevent
untrusted users from registering or changing source classifications.

The mock inbox does not send real messages. Replay and demo operations
must not be represented as live external execution.

## Security principle

The LLM proposes. The deterministic policy engine decides.
No model-generated text, document instruction, or tool output can
override trusted authorization policy.
