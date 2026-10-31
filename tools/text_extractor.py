"""Text extraction for the workspace. Bytes are parsed, never executed.

A PDF or DOCX is only ever read for its text. Nothing here runs a macro,
renders a page, or trusts the document to describe its own sensitivity.
"""

import io
import re

TEXT_SUFFIXES = (".txt", ".md", ".log", ".csv", ".json")

MAX_EXTRACTED_CHARS = 400_000


class UnsupportedFormat(ValueError):
    """Raised when no text can be safely recovered from a file."""


def _decode_text(raw):
    for encoding in ("utf-8", "utf-16", "latin-1"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    raise UnsupportedFormat("This file is not readable as text.")


def extract_pdf_text(raw):
    try:
        from pypdf import PdfReader
    except ImportError as exc:
        raise UnsupportedFormat(
            "PDF reading needs the optional pypdf package. Install it with "
            "pip install pypdf, or upload a text file."
        ) from exc

    try:
        reader = PdfReader(io.BytesIO(raw))
    except Exception as exc:
        raise UnsupportedFormat(
            f"This PDF could not be parsed ({type(exc).__name__})."
        ) from exc

    pages = []
    for page in reader.pages[:200]:
        try:
            pages.append(page.extract_text() or "")
        except Exception:
            pages.append("")

    text = "\n".join(pages).strip()
    if not text:
        raise UnsupportedFormat(
            "This PDF contains no extractable text - it is probably a scan. "
            "For this demo, upload a text-based file."
        )
    return text


def extract_docx_text(raw):
    try:
        from docx import Document
    except ImportError as exc:
        raise UnsupportedFormat(
            "Word reading needs the optional python-docx package."
        ) from exc

    try:
        document = Document(io.BytesIO(raw))
    except Exception as exc:
        raise UnsupportedFormat(
            f"This Word file could not be parsed ({type(exc).__name__})."
        ) from exc

    text = "\n\n".join(
        paragraph.text for paragraph in document.paragraphs if paragraph.text
    ).strip()

    if not text:
        raise UnsupportedFormat("This Word file contains no readable text.")
    return text


def extract_text(suffix, raw):
    """Return the document text, or raise UnsupportedFormat with a reason."""
    if not isinstance(raw, (bytes, bytearray)):
        raise UnsupportedFormat("Uploaded content must be raw bytes.")
    if not raw:
        raise UnsupportedFormat("This file is empty.")

    if suffix in TEXT_SUFFIXES:
        text = _decode_text(bytes(raw))
    elif suffix == ".pdf":
        text = extract_pdf_text(bytes(raw))
    elif suffix == ".docx":
        text = extract_docx_text(bytes(raw))
    else:
        raise UnsupportedFormat(
            f"Files of type '{suffix or 'unknown'}' are not supported. "
            "Upload TXT, MD, CSV, JSON, LOG, PDF or DOCX."
        )

    return re.sub(r"\r\n?", "\n", text)[:MAX_EXTRACTED_CHARS]
