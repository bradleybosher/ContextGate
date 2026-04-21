"""Retrieval-layer access control.

This is the load-bearing safety boundary of ContextGate. Documents the user's
role cannot access are *removed from the pipeline entirely* — the LLM never
sees them, so there is nothing for a prompt-injection attack to extract.

Rule: a document is allowed iff
  - its sensitivity is PUBLIC, OR
  - the caller's role is literally listed in doc.allowed_roles, OR
  - doc.allowed_roles contains the wildcard "*".

Returning (allowed, denied, denial_reasons) rather than just allowed lets the
audit log record *what was withheld and why* — essential for incident review.
"""
from __future__ import annotations

from typing import Dict, List, Tuple

from app.models.schemas import RetrievalHit, Sensitivity


# Exhaustive set of valid roles. filter_by_role() rejects unknown roles loudly
# rather than silently denying — a misconfigured role is a server bug, not a
# user error, and should surface immediately.
KNOWN_ROLES: frozenset[str] = frozenset({"engineer", "hr", "admin", "intern"})


def is_allowed(doc_sensitivity: Sensitivity, allowed_roles: List[str], role: str) -> bool:
    if doc_sensitivity == Sensitivity.PUBLIC:
        return True              # public docs bypass role check entirely
    if "*" in allowed_roles:
        return True              # wildcard grant
    if role in allowed_roles:
        return True              # explicit grant
    return False                 # DEFAULT DENY


def _denial_reason(allowed_roles: List[str], role: str) -> str:
    return f"role {role!r} not in allowed_roles {allowed_roles!r}"


def filter_by_role(
    hits: List[RetrievalHit], role: str
) -> Tuple[List[RetrievalHit], List[RetrievalHit], Dict[str, str]]:
    """Partition hits into (allowed, denied, denial_reasons).

    denial_reasons maps doc_id → human-readable explanation for each denial,
    so audit entries can answer "why was this doc withheld?" without re-running
    the policy.

    Raises ValueError for unrecognised roles — a misconfigured role is a server
    error and must not silently fall through to deny.
    """
    if role not in KNOWN_ROLES:
        raise ValueError(f"Unknown role {role!r}; expected one of {sorted(KNOWN_ROLES)}")
    allowed: List[RetrievalHit] = []
    denied: List[RetrievalHit] = []
    denial_reasons: Dict[str, str] = {}
    for hit in hits:
        if is_allowed(hit.doc.sensitivity, hit.doc.allowed_roles, role):
            allowed.append(hit)
        else:
            denied.append(hit)
            denial_reasons[hit.doc.id] = _denial_reason(hit.doc.allowed_roles, role)
    return allowed, denied, denial_reasons
