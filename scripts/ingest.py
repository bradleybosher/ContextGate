"""Build the in-memory FAISS index from app/data/sample_docs.json.

Importable: app.main calls build_index() on startup.
Runnable:   python -m scripts.ingest  (prints a summary)
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import List

from app.core.vector_store import FaissStore
from app.models.schemas import Document


ROOT = Path(__file__).resolve().parent.parent
DOCS_PATH = ROOT / "app" / "data" / "sample_docs.json"


def load_documents(path: Path = DOCS_PATH) -> List[Document]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    return [Document.model_validate(r) for r in raw]


def build_index(path: Path = DOCS_PATH) -> FaissStore:
    docs = load_documents(path)
    store = FaissStore()
    store.add(docs)
    return store


def main() -> None:
    store = build_index()
    print(f"Indexed {store.size} documents from {DOCS_PATH}")
    for d in store.all_docs():
        print(f"  - {d.id:<8} [{d.sensitivity.value:<12}] roles={d.allowed_roles}  {d.title}")


if __name__ == "__main__":
    main()
