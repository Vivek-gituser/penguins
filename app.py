import streamlit as st

from database.db import init_db, list_audit_events
from security.policy_engine import PolicyEngine, ActionRequest, demo_policy
from gateway import SecureGateway

from tools.document_reader import DocumentReader
from tools.report_saver import ReportSaver
from tools.mock_inbox import MockInbox


st.set_page_config(
    page_title="AGENTGATE",
    page_icon="🛡️",
    layout="wide"
)

init_db()

st.title("🛡️ AGENTGATE")
st.subheader("Security Gateway for AI Actions and Information-Flow Control")

st.info(
    "AI agents propose actions. The trusted policy engine "
    "authorizes them before registered tools can execute."
)

reader = DocumentReader()
saver = ReportSaver()
inbox = MockInbox()

gateway = SecureGateway(PolicyEngine(demo_policy()))

# Trusted application startup registers the available tools.
gateway.register_tool("read", "documents", reader.read_sample)
gateway.register_tool("save_report", "reports", saver.save_sample)

# Delivery tool uses the selected recipient through a trusted closure.
# The recipient is still independently checked by the policy engine.
def simulated_delivery():
    return inbox.deliver("AGENTGATE demonstration report", selected_recipient)

# Delivery is registered below after the recipient is selected.

with st.sidebar:
    st.header("Agent Action Simulator")

    agent = st.selectbox(
        "Agent",
        ["research-agent", "unknown-agent"]
    )

    operation = st.selectbox(
        "Operation",
        ["read", "save_report", "deliver"]
    )

    resource = st.selectbox(
        "Resource",
        ["documents", "reports", "inbox"]
    )

    sensitivity = st.selectbox(
        "Sensitivity",
        ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"]
    )

    selected_recipient = st.selectbox(
        "Recipient",
        ["", "team@example.com", "public@example.com", "attacker@example.com"]
    )

    run = st.button("Evaluate and Execute", type="primary")

if run:
    if operation == "deliver":
        # Register this recipient-specific trusted action for this run.
        # A fresh gateway prevents stale closures from being reused.
        gateway = SecureGateway(PolicyEngine(demo_policy()))
        gateway.register_tool(
            "deliver",
            "inbox",
            lambda: inbox.deliver(
                "AGENTGATE demonstration report",
                selected_recipient
            )
        )
    elif operation == "read":
        gateway = SecureGateway(PolicyEngine(demo_policy()))
        gateway.register_tool("read", "documents", reader.read_sample)
    elif operation == "save_report":
        gateway = SecureGateway(PolicyEngine(demo_policy()))
        gateway.register_tool("save_report", "reports", saver.save_sample)

    request = ActionRequest(
        agent_id=agent,
        operation=operation,
        resource=resource,
        recipient=selected_recipient,
        data_label=sensitivity
    )

    outcome = gateway.execute(request)

    if outcome.decision.value == "ALLOW":
        st.success("ACCESS ALLOWED")
        st.write(outcome.reason)
        st.json(outcome.result)
    else:
        st.error("ACCESS BLOCKED")
        st.write(outcome.reason)

st.divider()
st.header("Security Audit Dashboard")

events = list_audit_events()

if events:
    col1, col2, col3 = st.columns(3)
    col1.metric("Total Actions", len(events))
    col2.metric("Allowed", sum(e["decision"] == "ALLOW" for e in events))
    col3.metric("Blocked", sum(e["decision"] == "BLOCK" for e in events))
    st.dataframe(events, use_container_width=True, hide_index=True)
else:
    st.info("No security events recorded yet.")

st.caption("AGENTGATE Hackathon Prototype | Mock inbox only.")

# AGENTGATE_ARTIFACT_DASHBOARD
from database.artifact_store import ArtifactStore

st.divider()
st.header("Artifact Vault — Provenance & Persistence")
st.caption("Saved artifacts retain their source labels and provenance across app restarts.")

try:
    artifact_store = ArtifactStore()

    st.subheader("Save a derived report")
    with st.form("agentgate_save_artifact"):
        artifact_content = st.text_area(
            "Report content",
            placeholder="Enter the report content..."
        )
        source_ids_text = st.text_input(
            "Source IDs (comma separated)",
            value="sample_internal"
        )
        source_labels_text = st.text_input(
            "Source labels (comma separated)",
            value="INTERNAL"
        )
        transformation = st.selectbox(
            "Transformation",
            ["summarization", "analysis", "aggregation", "manual_report"]
        )
        save_artifact = st.form_submit_button("Save report securely")

    if save_artifact:
        source_ids = [x.strip() for x in source_ids_text.split(",") if x.strip()]
        source_labels = [x.strip().upper() for x in source_labels_text.split(",") if x.strip()]

        try:
            saved = artifact_store.save(
                artifact_content,
                source_ids,
                source_labels,
                transformation,
            )
            st.success("Artifact saved with inherited sensitivity label.")
            st.code(saved["artifact_id"])
        except Exception as exc:
            st.error(f"Artifact rejected: {exc}")

    st.subheader("Reload saved artifacts")
    artifact_id_to_load = st.text_input("Artifact ID to reload")
    if st.button("Load artifact"):
        try:
            loaded = artifact_store.load(artifact_id_to_load.strip())
            st.success("Artifact loaded and provenance validated.")
            st.write("**Sensitivity:**", loaded["label"])
            st.write("**Source IDs:**", loaded["source_ids"])
            st.write("**Source labels:**", loaded["source_labels"])
            st.write("**Transformation:**", loaded["transformation"])
            st.write("**Created at:**", loaded["created_at"])
            st.text_area(
                "Recovered report",
                value=loaded["content"],
                height=180,
                disabled=True,
                key="loaded_artifact_content",
            )
        except Exception as exc:
            st.error(f"Load rejected: {exc}")

except Exception as exc:
    st.error(f"Artifact Vault unavailable: {exc}")
