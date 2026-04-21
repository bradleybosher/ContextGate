"""Pure retrieval stage — no access control, no redaction.

Those live in their own modules so each stage is independently testable and
the audit log can record what each stage dropped. Retrieval is deliberately
permissive: it returns whatever the index thinks is most similar, and the
downstream gate decides what the user is allowed to see.
"""
from __future__ import annotations

from typing import List

from app.core.vector_store import FaissStore
from app.models.schemas import RetrievalHit


def retrieve(store: FaissStore, query: str, top_k: int) -> List[RetrievalHit]:
    return store.search(query, top_k)
