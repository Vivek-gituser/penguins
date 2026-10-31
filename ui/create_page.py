"""Create Files: genuine PDF and PowerPoint exports, decided by the gateway."""

import streamlit as st

from agent.export_service import ExportService
from tools.file_workspace import WorkspaceError
from tools.text_extractor import UnsupportedFormat
from ui import theme
from ui.context import WorkspaceContext

MAX_TOPIC_CHARS = 6000
MAX_TITLE_CHARS = 120


def render(ctx: WorkspaceContext, go):
    theme.hero(
        "Create a document",
        "Build a real PDF report or PowerPoint deck. The classification of "
        "the source material is carried into the file - converting a "
        "document never makes it public.",
        chips=["Real downloadable files", "Classification inherited",
               "Gateway authorises every export"],
    )

    mode = st.radio(
        "What should the document be built from?",
        ["A document in my workspace", "A topic I type in"],
        horizontal=True,
        key="create_mode",
        help=(
            "A workspace document is protected, so reading it and exporting "
            "it are two separate gateway decisions. A topic you type is your "
            "own text, not protected material."
        ),
    )

    kind = st.radio(
        "Output format",
        ["PDF report", "PowerPoint presentation"],
        horizontal=True,
        key="create_kind",
    )

    title = st.text_input(
        "Document title (optional)",
        key="create_title",
        placeholder="Quarterly security review",
        help=f"Up to {MAX_TITLE_CHARS} characters.",
    )

    if title and len(title) > MAX_TITLE_CHARS:
        st.error(
            f"That title is too long. Please keep it under "
            f"{MAX_TITLE_CHARS} characters."
        )
        return

    if mode.startswith("A document"):
        _from_file(ctx, kind, title, go)
    else:
        _from_topic(ctx, kind, title, go)


def _from_file(ctx, kind, title, go):
    try:
        files = [
            record for record in ctx.workspace.list_files()
            if record["category"] == "upload"
        ]
    except Exception as exc:
        st.error(f"The workspace could not be read: {type(exc).__name__}")
        return

    if not files:
        st.info(
            "There is no document here yet. Add one on the Files page, then "
            "come back."
        )
        if st.button("Go to Files", key="create_goto_files"):
            go("Files")
        return

    options = {record["file_id"]: record["display_name"] for record in files}

    file_id = st.selectbox(
        "Choose a document",
        list(options),
        format_func=lambda value: options[value],
        key="create_source_file",
    )
    chosen = next(record for record in files if record["file_id"] == file_id)

    st.markdown(
        f"Source classification: {theme.label_pill(chosen['label'])} "
        "<span class='ag-muted'>The export will keep at least this "
        "classification.</span>",
        unsafe_allow_html=True,
    )

    operation = "generate_pdf" if kind.startswith("PDF") else "generate_pptx"

    if not st.button(
        f"Create the {'PDF report' if kind.startswith('PDF') else 'PowerPoint deck'}",
        key=f"create_run_{operation}",
        type="primary",
    ):
        return

    with st.spinner("Reading the source and building the file..."):
        service = ExportService(ctx.make_gateway(), ctx.workspace)

        try:
            result = service.export_file(
                "pdf" if operation == "generate_pdf" else "pptx",
                file_id,
                title=title,
                prompt=title or f"{kind} from {chosen['display_name']}",
            )
        except (WorkspaceError, UnsupportedFormat, ValueError) as exc:
            _failed(ctx, str(exc))
            return
        except Exception:
            _failed(ctx, "The file could not be built. Nothing was saved.")
            return

    _outcome(ctx, result, go)


def _from_topic(ctx, kind, title, go):
    st.markdown(
        "<div class='ag-note'>You are writing this content yourself, so it "
        "is not protected material. Pick a starting classification; if you "
        "later build from a document, that label wins.</div>",
        unsafe_allow_html=True,
    )

    topic = st.text_area(
        "What should the document say?",
        height=180,
        key="create_topic",
        placeholder=(
            "Q3 security review: the gateway blocked 42 unauthorised "
            "deliveries. Recommend approval for all exports."
        ),
        help=f"Up to {MAX_TOPIC_CHARS} characters.",
    )
    label = st.selectbox(
        "Starting classification",
        list(ctx.labels),
        index=0,
        key="create_topic_label",
    )

    if not st.button(
        f"Create the {'PDF report' if kind.startswith('PDF') else 'PowerPoint deck'}",
        key="create_run_topic",
        type="primary",
    ):
        return

    if not topic.strip():
        _failed(ctx, "Type what the document should cover first.")
        return

    if len(topic) > MAX_TOPIC_CHARS:
        _failed(
            ctx,
            f"That is longer than {MAX_TOPIC_CHARS} characters. Trim it and "
            "try again - nothing was saved.",
        )
        return

    with st.spinner("Building the file..."):
        service = ExportService(ctx.make_gateway(), ctx.workspace)

        try:
            result = service.export(
                "pdf" if kind.startswith("PDF") else "pptx",
                content=topic,
                label=label,
                source_ids=[],
                title=title,
                prompt=title or topic[:200],
            )
        except (WorkspaceError, UnsupportedFormat, ValueError) as exc:
            _failed(ctx, str(exc))
            return
        except Exception:
            _failed(ctx, "The file could not be built. Nothing was saved.")
            return

    _outcome(ctx, result, go)


def _outcome(ctx, result, go):
    decision = str(result.get("status") or "")

    if decision != "ALLOW":
        _failed(
            ctx,
            f"AGENTGATE decided: {decision}. {result.get('reason', '')} "
            f"{theme.reason_for(decision)}",
            approval_id=result.get("approval_id"),
        )
        return

    record = result.get("file") or {}

    if not record:
        _failed(ctx, "No file was produced, so nothing is available to download.")
        return

    st.success(
        f"Your document is ready: **{record.get('display_name', 'file')}**"
    )

    columns = st.columns([2, 1, 1])

    with columns[0]:
        st.markdown(
            f"<div class='ag-muted'>"
            f"{theme.human_size(record.get('size_bytes', 0))}"
            f" &middot; {record.get('slides', 0)} sections &middot; built by "
            f"{_generator_label(record)}</div>",
            unsafe_allow_html=True,
        )

    with columns[1]:
        st.markdown(theme.label_pill(record.get("label", "INTERNAL")),
                    unsafe_allow_html=True)

    with columns[2]:
        from ui.downloads import mime_for

        st.download_button(
            "Download",
            data=_bytes(ctx, record),
            file_name=record.get("display_name", "document"),
            mime=mime_for(record.get("suffix", "")),
            key=f"dl_generated_{record.get('file_id', '')}",
            use_container_width=True,
        )

    st.subheader("What is inside")

    for section in record.get("sections", []):
        st.markdown(
            f"**{theme.escape(section.get('heading', ''))}**"
        )
        for bullet in section.get("bullets", []):
            st.markdown(f"- {theme.escape(bullet)}")

    with st.expander("Security details for this file"):
        st.markdown(
            theme.pills([
                (f"Decision: {decision}", theme.TEAL),
                (f"Classification: {record.get('label')}",
                 theme.LABEL_TONE.get(str(record.get("label")), "#6b7085")),
                (f"Generator: {_generator_label(record)}", "#4f46e5"),
            ]),
            unsafe_allow_html=True,
        )
        st.write("")
        st.caption(
            f"Gateway reason: {result.get('reason', '')}\n\n"
            f"Provenance sources: {', '.join(record.get('source_ids', [])) or 'none (your own text)'}\n\n"
            f"Stored as: {record.get('stored_name', '')} inside the "
            "approved workspace folder."
        )

    if st.button("See it in the file list", key="create_goto_list"):
        st.session_state["files_show_upload"] = record.get("file_id", "")
        go("Files")


def _bytes(ctx, record):
    payload = record.get("payload")

    if isinstance(payload, (bytes, bytearray)):
        return bytes(payload)

    from ui.downloads import authorized_bytes

    file_id = record.get("file_id")

    if not file_id:
        return b""

    released, released_payload = authorized_bytes(ctx, file_id)

    if released is None:
        return (
            f"AGENTGATE did not release this file: "
            f"{released_payload.get('reason', '')}"
        ).encode("utf-8")

    return released_payload


def _generator_label(record):
    if record.get("generator") == "gemini":
        return "Gemini"
    return "the offline writer"


def _failed(ctx, message, approval_id=None):
    st.error(message)

    if approval_id:
        st.warning(
            "This action is waiting for a reviewer. Open Approvals to "
            "review it."
        )
        if st.button("Go to Approvals", key=f"failed_approval_{approval_id[:8]}"):
            st.session_state["requested_page"] = "Approvals"
            st.rerun()
