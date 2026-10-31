"""Home: one friendly entry point, with the security story kept one click away."""

import streamlit as st

from ui import theme
from ui.context import WorkspaceContext

CARD_TONES = {
    "chat": "#eef2ff",
    "upload": "#ecfeff",
    "pdf": "#f0fdf4",
    "deck": "#fef3c7",
    "email": "#fce7f3",
    "review": "#fff7ed",
}


def render(ctx: WorkspaceContext, go):
    theme.hero(
        "Your AI workspace, with security built in",
        "Chat with an assistant, work with your files, produce real PDF and "
        "PowerPoint documents and draft email - and every protected step is "
        "decided by AGENTGATE before it runs.",
        chips=[
            "Gemini writes, AGENTGATE decides",
            "Nothing protected runs silently",
            "Every action is recorded",
        ],
    )

    events = ctx.get_events()
    files = _safe(lambda: ctx.workspace.list_files(), [])
    pending = _safe(lambda: len(ctx.get_approval_store().list_pending(limit=100)), None)

    allowed = sum(e.get("decision") == "ALLOW" for e in events)
    blocked = sum(e.get("decision") == "BLOCK" for e in events)

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Documents in workspace", len(files))
    c2.metric("Awaiting your review", pending if pending is not None else "-")
    c3.metric("Actions allowed", allowed)
    c4.metric("Actions blocked", blocked)

    st.write("")
    st.subheader("What would you like to do?")

    rows = [
        (
            "AI Workspace", "💬", "Chat with AI",
            "Ask a question, summarise a document or request several steps at "
            "once. The assistant proposes actions; it never runs one itself.",
            "Open the AI workspace", "chat",
        ),
        (
            "Files", "📁", "Upload a document",
            "Add a TXT, MD, CSV, JSON, LOG, PDF or DOCX file and set how "
            "sensitive it is. Reading it back is a protected action.",
            "Manage my files", "upload",
        ),
        (
            "Create Files", "📄", "Create a PDF report",
            "Turn an authorised document into a genuine, downloadable PDF "
            "that keeps the classification of its source.",
            "Create a PDF", "pdf",
        ),
        (
            "Create Files", "📊", "Create a PowerPoint",
            "Build a themed slide deck from a document or from a topic you "
            "type in.",
            "Create a presentation", "deck",
        ),
        (
            "Email", "✉️", "Draft an email",
            "Compose a message and send it to a colleague. Delivery is "
            "simulated and always needs your approval first.",
            "Draft an email", "email",
        ),
        (
            "Approvals", "✅", "Review pending actions",
            "See exactly what is about to happen, then approve or reject it. "
            "Nothing sensitive runs until you decide.",
            f"Review approvals{f' ({pending})' if pending else ''}", "review",
        ),
    ]

    for row_start in range(0, len(rows), 3):
        columns = st.columns(3)

        for column, (page, icon, title, text, button, tone) in zip(
            columns, rows[row_start:row_start + 3]
        ):
            with column:
                theme.card(
                    icon, title, text, tone=CARD_TONES.get(tone, "#eef2ff")
                )
                if st.button(button, key=f"home_{title}", use_container_width=True):
                    go(page)

    st.write("")
    left, right = st.columns([2, 1])

    with left:
        st.subheader("Recent activity")
        recent = events[:6]

        if not recent:
            theme.note(
                "Nothing has happened yet. Start with a document, then ask "
                "the AI workspace to summarise it."
            )
        else:
            for event in recent:
                theme.section(
                    "<div style='display:flex;justify-content:space-between;"
                    "gap:12px;align-items:center'>"
                    f"<div><b>{_describe(event)}</b>"
                    f"<div class='ag-muted'>{theme.pretty_time(event.get('timestamp'))}"
                    f" &middot; {theme.escape(event.get('reason') or '')[:90]}</div></div>"
                    f"<div>{theme.pill(event.get('decision'))}</div></div>"
                )

            if st.button("Open the full activity log", key="home_activity"):
                go("Activity")

    with right:
        st.subheader("How AGENTGATE decides")
        theme.section(
            "<div class='ag-card'>"
            "<h4>1. You ask</h4><p>Your words decide what is requested. A "
            "document cannot change that.</p>"
            "<h4>2. The model proposes</h4><p>Gemini (or the offline "
            "interpreter) describes the steps. It holds no authority.</p>"
            "<h4>3. The gateway decides</h4><p>Allowed, blocked, or waiting "
            "for you - from trusted policy, every single time.</p>"
            "<h4>4. Only then does a tool run</h4><p>And the outcome is "
            "written to the activity log.</p></div>"
        )
        theme.note(
            "Blocked actions never reach the tool. If the record cannot be "
            "written first, the action does not run either."
        )


def _describe(event):
    operation = str(event.get("operation") or "")
    recipient = theme.escape(str(event.get("recipient") or ""))
    label = theme.escape(str(event.get("data_label") or ""))

    friendly = {
        "read": "Document read",
        "read_file": "Workspace file opened",
        "save_report": "Report saved",
        "generate_pdf": "PDF created",
        "generate_pptx": "Presentation created",
        "deliver": f"Delivery to {recipient}" if recipient else "Delivery",
        "update_permissions": "Permission change",
    }.get(operation, operation.replace("_", " ").title() or "Action")

    name = theme.escape(friendly)
    return f"{name} &middot; {label}" if label else name


def _safe(call, fallback):
    try:
        return call()
    except Exception:
        return fallback
