"""The single validated content model every document generator consumes.

A generated file is only ever described by this structure, so a heading or
bullet that arrives from a model or an uploaded document cannot escape its
text slot and become layout or markup in the produced file.
"""

import re

from pydantic import BaseModel, Field, field_validator

MAX_TITLE_CHARS = 120
MAX_HEADING_CHARS = 140
MAX_BULLET_CHARS = 400
MAX_SECTION_COUNT = 40
MAX_BULLET_COUNT = 10

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def clean_text(value, limit):
    if not isinstance(value, str):
        raise ValueError("Document text must be a string")
    text = _CONTROL_CHARS.sub(" ", value)
    text = " ".join(text.split())
    if not text:
        raise ValueError("Document text cannot be empty")
    return text[:limit]


class DocumentSection(BaseModel):
    model_config = {"extra": "forbid"}

    heading: str
    bullets: list[str] = Field(default_factory=list)

    @field_validator("heading")
    @classmethod
    def _heading(cls, value):
        return clean_text(value, MAX_HEADING_CHARS)

    @field_validator("bullets")
    @classmethod
    def _bullets(cls, value):
        if not isinstance(value, (list, tuple)):
            raise ValueError("Section bullets must be a list")
        if len(value) > MAX_BULLET_COUNT:
            raise ValueError("A section may hold at most 10 bullets")
        return [clean_text(bullet, MAX_BULLET_CHARS) for bullet in value]


class DocumentSpec(BaseModel):
    """A title, ordered sections and the security label it inherited."""

    model_config = {"extra": "forbid"}

    title: str
    sections: list[DocumentSection]
    label: str
    subtitle: str = ""
    source_ids: list[str] = Field(default_factory=list)
    transformation: str = "agentgate_workspace"

    @field_validator("title")
    @classmethod
    def _title(cls, value):
        return clean_text(value, MAX_TITLE_CHARS)

    @field_validator("subtitle")
    @classmethod
    def _subtitle(cls, value):
        if value is None:
            return ""
        cleaned = " ".join(_CONTROL_CHARS.sub(" ", value).split())
        return cleaned[:MAX_TITLE_CHARS]

    @field_validator("sections")
    @classmethod
    def _sections(cls, value):
        if not isinstance(value, (list, tuple)) or not value:
            raise ValueError("A document needs at least one section")
        if len(value) > MAX_SECTION_COUNT:
            raise ValueError("A document may hold at most 40 sections")
        return [
            section if isinstance(section, DocumentSection)
            else DocumentSection.model_validate(section)
            for section in value
        ]

    @field_validator("label")
    @classmethod
    def _label(cls, value):
        from security.labels import SecurityLabel

        return SecurityLabel.parse(value).name

    @property
    def slide_count(self):
        return len(self.sections) + 1


_BULLET_PREFIX = re.compile(r"^\s*([-*•·>]+|\d+[.)])\s*")


def spec_from_text(title, content, label, source_ids=(), transformation="workspace_report"):
    """Turn plain report text into a structured document.

    Paragraph headings become section headings; sentences and list lines
    become bullets. Nothing here invents sensitivity: the caller supplies
    the label the trusted registry already holds.
    """
    if not isinstance(content, str) or not content.strip():
        raise ValueError("There is no report content to turn into a document")

    paragraphs = [
        block.strip()
        for block in re.split(r"\n\s*\n|\r\n\s*\r\n", content)
        if block and block.strip()
    ]
    if not paragraphs:
        raise ValueError("There is no report content to turn into a document")

    sections = []

    for index, block in enumerate(paragraphs[:MAX_SECTION_COUNT]):
        lines = [
            line.strip()
            for line in re.split(r"[\r\n]+", block)
            if line.strip()
        ]

        heading = ""
        body_lines = lines

        if len(lines) > 1 and len(lines[0]) <= MAX_HEADING_CHARS:
            candidate = lines[0]
            # A short leading line that is not itself a sentence reads as a
            # heading; anything else is treated as body text.
            if not re.search(r"[.!?]$", candidate) or len(candidate) <= 60:
                heading = _BULLET_PREFIX.sub("", candidate).strip("#*: ").strip()
                body_lines = lines[1:]

        if not heading:
            heading = f"Section {index + 1}"

        bullets = []
        for line in body_lines or lines:
            stripped = _BULLET_PREFIX.sub("", line).strip()
            if not stripped:
                continue
            for bullet in _split_sentences(stripped)[:MAX_BULLET_COUNT]:
                if len(bullets) >= MAX_BULLET_COUNT:
                    break
                bullets.append(bullet[:MAX_BULLET_CHARS])

        if not bullets:
            bullets = [heading[:MAX_BULLET_CHARS]]
            heading = f"Section {index + 1}"

        sections.append({"heading": heading, "bullets": bullets})

    if not sections:
        raise ValueError("The report produced no sections")

    return DocumentSpec(
        title=title,
        subtitle="",
        sections=sections,
        label=label,
        source_ids=[str(s) for s in source_ids],
        transformation=transformation,
    )


def _split_sentences(text):
    parts = re.split(r"(?<=[.!?])\s+", text)
    return [part.strip() for part in parts if part.strip()]
