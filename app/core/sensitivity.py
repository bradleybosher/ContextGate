"""Second-layer defence: scan permitted documents for secrets and either
redact or drop them before they reach the prompt.

Access control already filters by role; this module exists because even
role-permitted documents may contain artefacts (rotated-but-not-scrubbed
API keys, embedded PII, committed-by-mistake credentials) that should not
appear verbatim in an LLM context window.

Modes:
  - "redact" (default): replace matches with [REDACTED:<type>], keep the doc.
  - "block": drop the whole doc from context if any secret is detected.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Literal, Tuple

from app.models.schemas import Document, Redaction


Mode = Literal["redact", "block"]


@dataclass(frozen=True)
class _Detector:
    name: str
    pattern: re.Pattern[str]


_DETECTORS: Tuple[_Detector, ...] = (
    _Detector("openai_key", re.compile(r"sk-[A-Za-z0-9_\-]{16,}")),
    _Detector("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    _Detector("email", re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")),
    _Detector(
        "keyed_secret",
        re.compile(
            r"(?i)(?:password|api[_-]?key|secret|token)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{6,})['\"]?"
        ),
    ),
)


def _scan_text(text: str) -> Tuple[str, List[Tuple[str, int]]]:
    """Return (cleaned, [(type, count)]). Redacts matches in-place."""
    cleaned = text
    counts: dict[str, int] = {}
    for det in _DETECTORS:
        def _sub(m: re.Match[str], _name: str = det.name) -> str:
            counts[_name] = counts.get(_name, 0) + 1
            return f"[REDACTED:{_name}]"

        cleaned = det.pattern.sub(_sub, cleaned)
    return cleaned, list(counts.items())


def scan_document(doc: Document, mode: Mode) -> Tuple[Document | None, List[Redaction]]:
    """Apply sensitivity policy to a single document.

    Returns (possibly-transformed doc OR None if blocked, redaction list).
    """
    cleaned, counts = _scan_text(doc.content)
    redactions = [Redaction(doc_id=doc.id, type=t, count=c) for t, c in counts]

    if not counts:
        return doc, []

    if mode == "block":
        return None, redactions

    # redact mode: return a shallow copy with cleaned content
    return doc.model_copy(update={"content": cleaned}), redactions


def scan_documents(
    docs: List[Document], mode: Mode
) -> Tuple[List[Document], List[Redaction]]:
    kept: List[Document] = []
    all_redactions: List[Redaction] = []
    for d in docs:
        transformed, rs = scan_document(d, mode)
        all_redactions.extend(rs)
        if transformed is not None:
            kept.append(transformed)
    return kept, all_redactions
