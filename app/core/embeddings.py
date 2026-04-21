"""Deterministic, offline embedder.

We deliberately avoid a real embedding model. The point of ContextGate is the
access-control gate, not retrieval quality; a hashing bag-of-tokens vector is
plenty for the 6-doc demo corpus and keeps tests hermetic (no model download,
no network).
"""
from __future__ import annotations

import hashlib
import re
from typing import Iterable, List

import numpy as np


_TOKEN_RE = re.compile(r"[A-Za-z0-9_]+")

EMBED_DIM = 256


def _tokenize(text: str) -> List[str]:
    return [t.lower() for t in _TOKEN_RE.findall(text)]


def _hash_token(tok: str) -> int:
    h = hashlib.blake2b(tok.encode("utf-8"), digest_size=4).digest()
    return int.from_bytes(h, "big") % EMBED_DIM


class HashingEmbedder:
    """Token-hash → fixed-dim L2-normalized vector. Cosine sim via inner product."""

    dim: int = EMBED_DIM

    def embed(self, text: str) -> np.ndarray:
        vec = np.zeros(self.dim, dtype=np.float32)
        for tok in _tokenize(text):
            vec[_hash_token(tok)] += 1.0
        norm = float(np.linalg.norm(vec))
        if norm > 0:
            vec /= norm
        return vec

    def embed_many(self, texts: Iterable[str]) -> np.ndarray:
        return np.vstack([self.embed(t) for t in texts]).astype(np.float32)
