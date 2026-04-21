from __future__ import annotations

from typing import Dict, List

import faiss
import numpy as np

from app.core.embeddings import HashingEmbedder
from app.models.schemas import Document, RetrievalHit


class FaissStore:
    """In-memory FAISS IndexFlatIP over hashing-embedded documents."""

    def __init__(self, embedder: HashingEmbedder | None = None) -> None:
        self.embedder = embedder or HashingEmbedder()
        self.index = faiss.IndexFlatIP(self.embedder.dim)
        self._docs: Dict[int, Document] = {}

    def add(self, docs: List[Document]) -> None:
        if not docs:
            return
        texts = [f"{d.title}\n{d.content}" for d in docs]
        vecs = self.embedder.embed_many(texts)
        start = self.index.ntotal
        self.index.add(vecs)
        for offset, doc in enumerate(docs):
            self._docs[start + offset] = doc

    def search(self, query: str, top_k: int) -> List[RetrievalHit]:
        """Return top-k hits without any filtering.

        Intentionally permissive — access control and sensitivity scanning run
        downstream. Keeping retrieval separate lets the audit log record exactly
        what each stage accepted or dropped.
        """
        if self.index.ntotal == 0:
            return []
        qv = self.embedder.embed(query).reshape(1, -1)
        k = min(top_k, self.index.ntotal)
        scores, ids = self.index.search(qv, k)
        hits: List[RetrievalHit] = []
        for score, idx in zip(scores[0].tolist(), ids[0].tolist()):
            if idx == -1:
                continue
            hits.append(RetrievalHit(doc=self._docs[idx], score=float(score)))
        return hits

    @property
    def size(self) -> int:
        return self.index.ntotal

    def all_docs(self) -> List[Document]:
        return list(self._docs.values())
