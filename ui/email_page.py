"""Email: draft freely, deliver only after the gateway and a reviewer agree.

Delivery is always simulated. Nothing here can send real mail, and the
recipient a human typed is never replaced by something a document or a
model suggested.
"""

import streamlit as st

from ai import composer as ai_composer
from security.policy_engine import ActionRequest
from ui import theme
from ui.context import WorkspaceContext

MAX_BODY_CHARS = 6000
MAX_SUBJECT_CHARS = 120


def render(ctx: WorkspaceContext, go):
    policy = ctx.get_policy()

    theme.hero(
        "Draft an email",
        "Write the message, choose who receives it, then ask AGENTGATE to "
        "deliver it. Delivery is simulated for this prototype and always "
        "needs a human approval first.",
        chips=["Simulated delivery only", "Approval required",
               "Recipient comes from you"],
    )

    columns = st.columns([1.15, 1])

    with columns[0]:
        _composer(ctx, policy, go)

    with columns[1]:
        _side_panel(ctx, policy)


def _composer(ctx, policy, go):
    st.subheader("1. Write the message")

    authorized = sorted(policy.authorized_recipients)
    draft = st.session_state.setdefault("email_draft_text", {"subject": "", "body": ""})

    recipient = st.text_input(
        "To",
        key="email_recipient",
        value=authorized[0] if authorized else "",
        placeholder="team@example.com",
        help=(
            "You may type any address. Recipients outside the trusted list "
            "are blocked by the policy engine, not by the AI."
        ),
    )

    if authorized:
        st.caption(
            "Recipients this deployment trusts: "
            + ", ".join(f"`{name}`" for name in authorized)
        )

    # Subject and body are intentionally unkeyed: the assistant writes them
    # into session state and the page re-renders, so a generated draft can
    # appear in the fields without fighting widget state.
    subject = st.text_input(
        "Subject",
        value=draft.get("subject", ""),
        placeholder="Q3 security review",
        help=f"Up to {MAX_SUBJECT_CHARS} characters.",
    )
    body = st.text_area(
        "Message",
        value=draft.get("body", ""),
        height=200,
        placeholder="Type your message, or ask the assistant to draft it.",
        help=f"Up to {MAX_BODY_CHARS} characters.",
    )

    source_options = {"": "No attachment - my own words"}
    try:
        for record in ctx.workspace.list_files(category="upload"):
            source_options[record["file_id"]] = (
                f"{record['display_name']} ({record['label']})"
            )
    except Exception:
        pass

    source_id = st.selectbox(
        "Summarise one of my documents into this draft",
        list(source_options),
        format_func=lambda value: source_options[value],
        key="email_source",
        help=(
            "Reading the document is a protected action. Its classification "
            "is carried into the message, so a confidential summary cannot "
            "be sent somewhere less sensitive."
        ),
    )

    actions = st.columns(2)

    with actions[0]:
        drafted = st.button(
            "Draft with the assistant",
            key="email_draft_run",
            use_container_width=True,
        )
    with actions[1]:
        requested = st.button(
            "Request delivery",
            key="email_send",
            type="primary",
            use_container_width=True,
        )

    content = ""
    label = "PUBLIC"

    if source_id:
        from ui.downloads import authorized_text

        released, content = authorized_text(ctx, source_id)

        if released is None:
            st.error(
                f"The document could not be read: "
                f"{content.get('reason', '')} "
                f"{theme.reason_for(content.get('decision'))}"
            )
            return

        label = released["label"]
        content = str(content)

    if drafted:
        if not (subject or body or content):
            st.info(
                "Tell the assistant what the message is for, or choose a "
                "document to summarise."
            )
        else:
            draft, meta = ai_composer.draft_email(
                subject or body[:200] or "Workspace update",
                documents=[(source_id, content)] if content else [],
                recipient=recipient,
            )
            st.session_state["email_draft_text"] = {
                "subject": draft.subject,
                "body": draft.body,
            }

            st.success(
                "Draft ready. Read it and edit anything you like - nothing "
                "has been sent."
            )
            st.caption(
                f"Written by {'Gemini' if meta['generator'] == 'gemini' else 'the offline writer'}"
                + (f" ({meta.get('reason', '')})" if meta["degraded"] else "")
            )
            st.rerun()

    if not requested:
        return

    final_body = (
        f"Subject: {subject}\n\n{body}" if subject else body
    ).strip()

    if not final_body:
        st.error("There is no message to deliver. Write one first.")
        return

    if not recipient.strip():
        st.error("Add a recipient before requesting delivery.")
        return

    if len(subject) > MAX_SUBJECT_CHARS or len(body) > MAX_BODY_CHARS:
        st.error(
            f"That message is too long - keep the subject under "
            f"{MAX_SUBJECT_CHARS} characters and the body under "
            f"{MAX_BODY_CHARS}. Nothing was delivered."
        )
        return

    _deliver(ctx, recipient, final_body, label, go)


def _deliver(ctx, recipient, body, label, go):
    """Ask the gateway. It decides; only its authorised path can run the tool."""
    gateway = ctx.make_gateway(recipient=recipient)

    # Remember the exact text so an approved ticket delivers this message and
    # nothing else. The ticket itself binds agent, operation, resource,
    # recipient and label.
    payloads = st.session_state.setdefault("workspace_payloads", {})
    payloads[recipient] = body

    request = ActionRequest(
        agent_id="research-agent",
        operation="deliver",
        resource="inbox",
        recipient=recipient.strip(),
        data_label=label,
    )

    outcome = gateway.execute(request)
    decision = outcome.decision.value

    if decision == "ALLOW":
        result = outcome.result or {}
        st.success(
            f"Simulated delivery recorded for {recipient} "
            f"({result.get('status', 'SIMULATED_DELIVERY')}). No real email "
            "was sent."
        )
        return

    if decision == "REQUIRE_APPROVAL":
        st.warning(
            "**Waiting for your approval.** Nothing has been delivered yet."
        )
        st.markdown(
            f"- To: `{theme.escape(recipient)}`\n"
            f"- Classification: **{label}**\n"
            f"- Approval reference: `{(outcome.approval_id or '')[:8]}`\n"
            f"- Why: {outcome.reason}"
        )
        st.caption(theme.reason_for("REQUIRE_APPROVAL"))

        if st.button("Open Approvals", key="email_goto_approvals"):
            go("Approvals")
        return

    st.error(f"Blocked: {outcome.reason}")
    st.caption(theme.reason_for("BLOCK"))


def _side_panel(ctx, policy):
    st.subheader("2. What happens next")

    theme.section(
        "<h4>Your draft stays yours</h4><p class='ag-muted'>The assistant "
        "can write the text. Sending it is a separate, protected action.</p>"
        "<h4>AGENTGATE checks the recipient</h4><p class='ag-muted'>Someone "
        "outside the trusted list, or a message above their clearance, is "
        "stopped here.</p>"
        "<h4>A human approves</h4><p class='ag-muted'>You review the exact "
        "address, the classification and the reason before anything runs.</p>"
        "<h4>The mock inbox records it</h4><p class='ag-muted'>Delivery is "
        "simulated. No real mail is ever sent by this prototype.</p>"
    )

    st.subheader("Delivery rules in this workspace")

    clearance = policy.recipient_clearance

    if clearance:
        rows = []

        for recipient in sorted(clearance):
            rows.append({
                "Recipient": recipient,
                "May receive up to": str(clearance[recipient]),
                "Needs approval": "Yes",
            })

        st.dataframe(rows, use_container_width=True, hide_index=True)
    else:
        st.info("No recipients are trusted by the current policy.")

    theme.note(
        "A document that says \"send this to someone else\" is data. It "
        "cannot change the recipient, the classification or the policy - "
        "try it in the Prompt Injection Lab."
    )
