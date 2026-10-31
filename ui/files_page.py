"""Files: upload, inspect and release workspace documents through the gateway."""

import streamlit as st

from tools.file_workspace import SecureFileWorkspace, WorkspaceError
from tools.text_extractor import UnsupportedFormat
from ui import theme
from ui.context import WorkspaceContext
from ui.downloads import authorized_bytes, mime_for


def render(ctx: WorkspaceContext, go):
    theme.hero(
        "Your files",
        "Everything you add stays in the AGENTGATE workspace folder. You "
        "declare how sensitive a document is - a file can never classify "
        "itself, and the AI can never lower that label.",
        chips=["Approved folder only", "Path traversal rejected",
               "Sensitivity is yours to declare"],
    )

    upload_tab, list_tab = st.tabs(["Add a document", "Workspace contents"])

    with upload_tab:
        _upload_form(ctx, go)

    with list_tab:
        _file_list(ctx, go)

    with st.expander("Why a file name is treated as untrusted input"):
        st.caption(
            "The workspace accepts one plain name inside its own folder. "
            "Anything that tries to climb out is refused before the disk is "
            "touched. Try these: ../../.env, C:/Windows/win.ini, "
            "..\\secrets.txt"
        )
        probe = st.text_input(
            "Name to test", value="notes.txt", key="name_probe"
        )

        if st.button("Test this name", key="name_probe_run"):
            try:
                accepted = SecureFileWorkspace.validate_name(probe)
                st.success(
                    f"'{accepted}' is an acceptable workspace name. It still "
                    "has to be a file you actually uploaded."
                )
            except WorkspaceError as exc:
                st.error(f"Refused: {exc}")
            except Exception:
                st.error("Refused: that name is not safe for the workspace.")


def _upload_form(ctx, go):
    st.subheader("Add a document")

    with st.form("ws_upload_form"):
        upload = st.file_uploader(
            "Pick a file",
            type=[suffix.lstrip(".") for suffix in ctx.upload_suffixes],
            key="files_upload",
        )
        label = st.selectbox(
            "How sensitive is this document?",
            list(ctx.labels),
            index=1,
            key="files_upload_label",
            help=(
                "Your declaration, recorded in the trusted registry. It "
                "controls who this document may later be sent to."
            ),
        )
        submitted = st.form_submit_button(
            "Add to my workspace", use_container_width=True
        )

    if not submitted or upload is None:
        if submitted and upload is None:
            st.info("Choose a file first, then add it to the workspace.")
        return

    raw = upload.getvalue()

    try:
        record = ctx.workspace.ingest(upload.name, raw, label)
    except WorkspaceError as exc:
        st.error(str(exc))
        return
    except UnsupportedFormat as exc:
        st.error(str(exc))
        return
    except Exception:
        st.error(
            "This file could not be added. Check its type and size, then "
            "try again."
        )
        return

    st.success(
        f"Added **{record['display_name']}** "
        f"({theme.human_size(record['size_bytes'])}) classified "
        f"**{record['label']}**."
    )
    st.session_state["files_show_upload"] = record["file_id"]

    if st.button("Open the file list", key="files_after_upload"):
        go("Files")


def _file_list(ctx, go):
    files = []

    try:
        files = ctx.workspace.list_files()
    except Exception as exc:
        st.error(f"The workspace could not be read: {type(exc).__name__}")
        return

    if not files:
        st.info("No files yet. Add a document and it will appear here.")
        return

    uploads = [f for f in files if f["category"] == "upload"]
    generated = [f for f in files if f["category"] == "generated"]

    _group(ctx, "Uploaded documents", uploads)
    _group(ctx, "Generated for you", generated)


def _group(ctx, title, records):
    if not records:
        return

    st.subheader(title)

    for record in records:
        columns = st.columns([3, 1, 1, 2.4])

        with columns[0]:
            st.markdown(
                f"**{theme.escape(record['display_name'])}**"
                f"<div class='ag-muted'>{theme.escape(record['suffix']).lstrip('.').upper()}"
                f" &middot; {theme.human_size(record['size_bytes'])}"
                f" &middot; added {theme.pretty_time(record['created_at'])}</div>",
                unsafe_allow_html=True,
            )

        with columns[1]:
            st.markdown(theme.label_pill(record["label"]), unsafe_allow_html=True)

        with columns[2]:
            ready = record["file_id"] in st.session_state.get(
                "authorized_file_reads", {}
            )
            st.markdown(
                theme.pill("PENDING" if not ready else "ALLOW"),
                unsafe_allow_html=True,
            )

        with columns[3]:
            if ready:
                cached = st.session_state["authorized_file_reads"][
                    record["file_id"]
                ]
                _, data = cached
                payload = data if isinstance(data, (bytes, bytearray)) else str(
                    data
                ).encode("utf-8")
                st.download_button(
                    "Download",
                    data=payload,
                    file_name=record["display_name"],
                    mime=mime_for(record["suffix"]),
                    key=f"dl_{record['file_id']}",
                    use_container_width=True,
                )
            else:
                if st.button(
                    "Release content",
                    key=f"rel_{record['file_id']}",
                    use_container_width=True,
                    help=(
                        "Asks AGENTGATE to authorise reading this file. The "
                        "decision is written to the activity log first."
                    ),
                ):
                    result = authorized_bytes(ctx, record["file_id"])
                    released = result[0]

                    if released is None:
                        decision = result[1]
                        st.error(
                            f"AGENTGATE {decision.get('decision', 'BLOCK')}: "
                            f"{decision.get('reason', '')} "
                            f"{theme.reason_for(decision.get('decision'))}"
                        )
                    else:
                        st.success(
                            "Read authorised. The download is now available."
                        )
                        st.rerun()

        if record["file_id"] == st.session_state.get("files_show_upload"):
            _preview(ctx, record)

        st.divider()


def _preview(ctx, record):
    payload = st.session_state.get("authorized_file_reads", {}).get(
        record["file_id"]
    )
    if not payload:
        return

    _, data = payload

    if isinstance(data, (bytes, bytearray)):
        st.caption(
            f"This export is {theme.human_size(len(data))} of "
            f"{record['suffix'].upper().lstrip('.')} content."
        )
        return

    st.text_area(
        "Untrusted document text (shown as data, never as instructions)",
        value=str(data)[:4000],
        height=180,
        key=f"preview_{record['file_id']}",
        disabled=True,
    )
