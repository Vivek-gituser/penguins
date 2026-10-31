"""The shared look for the AGENTGATE workspace.

A friendly productivity application, not a terminal: light surfaces,
rounded cards, one primary colour, and colour that always means the same
thing - green for allowed, amber for needs-review, red for blocked.
"""

import streamlit as st

PRIMARY = "#4f46e5"
TEAL = "#0d9488"
AMBER = "#b45309"
RED = "#dc2626"
INK = "#1f2937"
MUTED = "#667085"

LABEL_TONE = {
    "PUBLIC": "#047857",
    "INTERNAL": "#1d4ed8",
    "CONFIDENTIAL": "#b45309",
    "RESTRICTED": "#b91c1c",
}

DECISION_TONE = {
    "ALLOW": TEAL,
    "ALLOWED_LOCALLY": TEAL,
    "SUCCESS": TEAL,
    "REQUIRE_APPROVAL": AMBER,
    "APPROVAL_REQUIRED": AMBER,
    "PENDING": AMBER,
    "BLOCK": RED,
    "BLOCKED": RED,
    "REJECTED": RED,
    "SKIPPED": MUTED,
    "NO_ACTIONS": MUTED,
}

CSS = """
<style>
/* ---------- surfaces ---------- */
.stApp { background: #f6f7fb; }
.block-container { padding-top: 2.2rem; padding-bottom: 3rem; max-width: 1200px; }
[data-testid="stSidebar"] {
    background: #ffffff;
    border-right: 1px solid #e8eaf1;
}
[data-testid="stSidebar"] .stRadio > label,
[data-testid="stSidebar"] .stSelectbox > label {
    font-size: 12px; letter-spacing: .06em; text-transform: uppercase;
    color: #7982a3;
}
hr { border-color: #e8eaf1; }

/* ---------- type ---------- */
h1, h2, h3 { color: #1f2937; font-weight: 700; letter-spacing: -0.01em; }
.stCaption, small { color: #667085; }

/* ---------- hero ---------- */
.ag-hero {
    background: linear-gradient(118deg, #eef2ff 0%, #ffffff 46%, #ecfeff 100%);
    border: 1px solid #e3e7f5;
    border-radius: 22px;
    padding: 26px 30px;
    margin-bottom: 22px;
    box-shadow: 0 10px 30px rgba(31, 41, 55, .05);
}
.ag-hero h1 { margin: 0 0 6px 0; font-size: 31px; }
.ag-hero p { margin: 0; color: #5b647a; font-size: 15px; }
.ag-chips { margin-top: 14px; display: flex; flex-wrap: wrap; gap: 8px; }

/* ---------- cards ---------- */
.ag-card {
    background: #ffffff;
    border: 1px solid #e8eaf1;
    border-radius: 18px;
    padding: 18px 18px 14px 18px;
    height: 100%;
    box-shadow: 0 4px 16px rgba(31, 41, 55, .04);
}
.ag-card h4 { margin: 0 0 6px 0; font-size: 16px; color: #1f2937; }
.ag-card p { margin: 0 0 8px 0; font-size: 13.5px; color: #667085; line-height: 1.45; }
.ag-icon {
    width: 40px; height: 40px; border-radius: 12px;
    display: flex; align-items: center; justify-content: center;
    font-size: 20px; margin-bottom: 10px; background: #eef2ff;
}
.ag-section {
    background: #ffffff; border: 1px solid #e8eaf1; border-radius: 18px;
    padding: 18px 20px; margin-bottom: 14px;
    box-shadow: 0 4px 16px rgba(31, 41, 55, .04);
}
.ag-muted { color: #667085; font-size: 13px; }
.ag-note {
    background: #f8fafc; border: 1px dashed #d7dbe8; border-radius: 14px;
    padding: 12px 14px; font-size: 13px; color: #4b5563;
}

/* ---------- pills ---------- */
.ag-pill {
    display: inline-block; padding: 3px 11px; border-radius: 999px;
    font-size: 11.5px; font-weight: 700; letter-spacing: .03em;
    color: #ffffff; background: #6b7280;
}
.ag-soft {
    display: inline-block; padding: 3px 10px; border-radius: 999px;
    font-size: 12px; font-weight: 600; background: #eef2ff; color: #4338ca;
}

/* ---------- widgets ---------- */
div[data-testid="stMetric"] {
    background: #ffffff; border: 1px solid #e8eaf1; border-radius: 16px;
    padding: 14px 16px; box-shadow: 0 4px 16px rgba(31, 41, 55, .04);
}
div[data-testid="stMetric"] label { color: #7982a3; }
.stButton > button, .stFormSubmitButton > button, .stDownloadButton > button {
    border-radius: 12px; border: 1px solid #dfe3ef; background: #ffffff;
    color: #1f2937; font-weight: 600; padding: 8px 14px;
    transition: all .15s ease;
}
.stButton > button:hover, .stFormSubmitButton > button:hover,
.stDownloadButton > button:hover {
    border-color: #4f46e5; color: #4f46e5; background: #f5f6ff;
}
[data-testid="stSidebar"] .stButton > button { width: 100%; }
.stTextInput > div, .stTextArea > div, .stNumberInput > div,
.stFileUploader > div { border-radius: 12px; }
.stSuccess, .stInfo, .stWarning, .stError { border-radius: 14px; }
.stSuccess > div { background: #ecfdf5; border-color: #a7f3d0; }
.stInfo > div { background: #eff6ff; border-color: #bfdbfe; }
.stWarning > div { background: #fffbeb; border-color: #fde68a; }
.stError > div { background: #fef2f2; border-color: #fecaca; }
div[data-testid="stChatMessage"] {
    background: #ffffff; border: 1px solid #e8eaf1; border-radius: 16px;
}
</style>
"""


def apply_theme():
    st.markdown(CSS, unsafe_allow_html=True)


def hero(title, subtitle, chips=()):
    marks = "".join(
        f'<span class="ag-soft">{_escape(chip)}</span>' for chip in chips
    )
    st.markdown(
        f"""
        <div class="ag-hero">
            <h1>{_escape(title)}</h1>
            <p>{_escape(subtitle)}</p>
            <div class="ag-chips">{marks}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def card(icon, title, description, tone="#eef2ff", body=None):
    """An opening card block; call st.button after it to make it act."""
    extra = f'<p class="ag-muted">{_escape(body)}</p>' if body else ""
    st.markdown(
        f"""
        <div class="ag-card">
            <div class="ag-icon" style="background:{tone}">{icon}</div>
            <h4>{_escape(title)}</h4>
            <p>{_escape(description)}</p>
            {extra}
        </div>
        """,
        unsafe_allow_html=True,
    )


def section(text):
    st.markdown(f'<div class="ag-section">{text}</div>', unsafe_allow_html=True)


def note(text):
    st.markdown(
        f'<div class="ag-note">{text}</div>', unsafe_allow_html=True
    )


def pill(value, tones=None):
    tone = (tones or DECISION_TONE).get(str(value), "#6b7085")
    return (
        f'<span class="ag-pill" style="background:{tone}">'
        f"{_escape(_humanise(value))}</span>"
    )


def label_pill(label):
    return pill(label, LABEL_TONE)


def pills(pairs):
    return " ".join(
        f'<span class="ag-pill" style="background:{tone}">{_escape(text)}</span>'
        for text, tone in pairs
    )


def _humanise(value):
    text = str(value or "")
    return {
        "ALLOW": "Allowed",
        "ALLOWED_LOCALLY": "Local step",
        "REQUIRE_APPROVAL": "Needs your review",
        "APPROVAL_REQUIRED": "Needs your review",
        "BLOCK": "Blocked",
        "BLOCKED": "Blocked",
        "SKIPPED": "Skipped",
        "NO_ACTIONS": "Nothing to do",
        "PENDING": "Waiting",
        "REJECTED": "Rejected",
    }.get(text, text.replace("_", " ").title())


def _escape(value):
    return (
        str(value or "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


escape = _escape


def human_size(size_bytes):
    try:
        size = float(size_bytes)
    except (TypeError, ValueError):
        return "unknown size"

    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"


def pretty_time(value):
    text = str(value or "")
    if not text:
        return ""
    try:
        return text.replace("T", " ")[:16]
    except (TypeError, ValueError):
        return text[:16]


def reason_for(decision):
    """Plain-language guidance on what to do next."""
    return {
        "ALLOW": "Done. Nothing else is needed.",
        "ALLOWED_LOCALLY": "Handled inside the workspace - no protected tool ran.",
        "REQUIRE_APPROVAL": (
            "Open Approvals, check the details, then approve or reject it. "
            "Nothing runs until you decide."
        ),
        "BLOCK": (
            "The gateway stopped this. Check Access Control or pick a "
            "recipient who is cleared for this classification."
        ),
        "SKIPPED": "Try asking for the document first, then the export.",
        "NO_ACTIONS": "Rephrase the request, or use the page buttons instead.",
    }.get(str(decision), "Review the details below.")
