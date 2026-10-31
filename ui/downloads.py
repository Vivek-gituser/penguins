"""Download helpers. Content is only ever released through the gateway."""

import streamlit as st

MIME_TYPES = {
    ".txt": "text/plain",
    ".md": "text/markdown",
    ".log": "text/plain",
    ".csv": "text/csv",
    ".json": "application/json",
    ".pdf": "application/pdf",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
}


def mime_for(suffix):
    return MIME_TYPES.get(str(suffix), "application/octet-stream")


def authorized_bytes(ctx, file_ref):
    """Return (record, data) after a gateway-authorized read, or (None, result).

    Reads are cached for the session so re-rendering the page does not add
    duplicate audit events; releasing the bytes is still a real, recorded
    gateway decision the first time.
    """
    return _released(ctx, file_ref, "authorized_file_reads", binary=True)


def authorized_text(ctx, file_ref):
    """The same gateway decision, but with the text extracted from the file."""
    return _released(ctx, file_ref, "authorized_text_reads", binary=False)


def _released(ctx, file_ref, cache_key, binary):
    from agent.export_service import ExportService

    cache = st.session_state.setdefault(cache_key, {})

    if file_ref in cache:
        return cache[file_ref]

    service = ExportService(ctx.make_gateway(), ctx.workspace)
    result = service.read_file(file_ref, binary=binary)

    if result["decision"] != "ALLOW":
        return None, result

    payload = (result["record"], result["data"] if binary else result["content"])
    cache[file_ref] = payload
    return payload

