"""Retrieval-layer access control.

This is the load-bearing safety boundary of ContextGate. Documents the user's
role cannot access are *removed from the pipeline entirely* — the LLM never
sees them, so there is nothing for a prompt-injection attack to extract.

Rule: a document is allowed iff
  - its sensitivity is PUBLIC, OR
  - the caller's role is literally listed in doc.allowed_roles, OR
  - doc.allowed_roles contains the wildcard "*".

Returning (allowed, denied) rather than just allowed lets the audit log
record *what was withheld* — essential for incident review.
"""
from __future__ import annotations

from typing import List, Tuple

from app.models.schemas import RetrievalHit, Sensitivity


def is_allowed(doc_sensitivity: Sensitivity, allowed_roles: List[str], role: str) -> bool:
    # PUBLIC docs have no role restriction by definition; skip role checking entirely.
    if doc_sensitivity == Sensitivity.PUBLIC:
        return True
    if "*" in allowed_roles:
        return True
    return role in allowed_roles


def filter_by_role(
    hits: List[RetrievalHit], role: str
) -> Tuple[List[RetrievalHit], List[RetrievalHit]]:
    allowed: List[RetrievalHit] = []
    denied: List[RetrievalHit] = []
    for hit in hits:
        if is_allowed(hit.doc.sensitivity, hit.doc.allowed_roles, role):
            allowed.append(hit)
        else:
            denied.append(hit)
    return allowed, denied
