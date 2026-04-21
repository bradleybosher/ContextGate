"""Intentionally unfiltered vector search.

Returns ALL documents that match the query above the similarity threshold.
No role checking. No sensitivity filtering. The caller is responsible for
passing the result through filter_by_role() before any further processing.

WHY over-retrieval is deliberate: the access-control gate needs the full
candidate set to make deny decisions and record them in the audit log.
Filtering here would produce a silent allow — denied docs would simply
disappear with no audit trail.

In a naive system, the result of retrieve() flows directly into the prompt.
That is the failure mode ContextGate exists to demonstrate.
"""
from __future__ import annotations

from typing import List

from app.core.vector_store import FaissStore
from app.models.schemas import RetrievalHit

# Alias makes the caller's obligation explicit: this output is unsafe until
# it has passed through filter_by_role() and scan_documents().
UnfilteredHits = List[RetrievalHit]


def retrieve(store: FaissStore, query: str, top_k: int) -> UnfilteredHits:
    return store.search(query, top_k)
