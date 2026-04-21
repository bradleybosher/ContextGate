from __future__ import annotations

import os

from dotenv import load_dotenv
from fastapi import FastAPI

from app.api.routes import router
from app.core.llm_provider import LLMProvider, get_provider
from app.core.vector_store import FaissStore
from app.audit.audit import AuditLogger
from scripts.ingest import build_index


def create_app(
    store: FaissStore | None = None,
    provider: LLMProvider | None = None,
    audit: AuditLogger | None = None,
) -> FastAPI:
    load_dotenv(override=False)

    app = FastAPI(
        title="ContextGate",
        description=(
            "Retrieval-layer data boundaries for LLM apps. "
            "Access control and sensitivity filtering run BEFORE prompt construction."
        ),
        version="0.1.0",
    )

    app.state.store = store or build_index()
    app.state.provider = provider or get_provider()
    app.state.audit = audit or AuditLogger(os.getenv("CONTEXTGATE_AUDIT_LOG", "./audit.log"))

    app.include_router(router)
    return app


app = create_app()
