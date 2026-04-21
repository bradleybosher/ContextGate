"""HTTP surface.

/ask        — the protected pipeline (access control + sensitivity + audit)
/ask_naive  — the failure-mode foil (no gate, only prompt instructions)
/docs_meta  — metadata only, proves that knowing a doc exists != reading it
/healthz    — liveness

Both ask endpoints accept {user_id, query}. user_id is trusted from the body;
a real deployment would derive role from an authenticated session.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, List

from fastapi import APIRouter, HTTPException, Request

from app.core import access_control, prompt_builder, sensitivity
from app.core.retrieval import retrieve
from app.audit.audit import AuditEntry, AuditLogger, now_iso, preview
from app.models.schemas import (
    AskRequest,
    AskResponse,
    Document,
    Redaction,
    RetrievalHit,
)


router = APIRouter()

_USERS_PATH = Path(__file__).resolve().parent.parent / "data" / "users.json"


def _load_users() -> Dict[str, Dict[str, str]]:
    return json.loads(_USERS_PATH.read_text(encoding="utf-8"))


def _resolve_role(user_id: str) -> str:
    users = _load_users()
    user = users.get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail=f"unknown user_id: {user_id}")
    return user["role"]


def _top_k(req: AskRequest) -> int:
    try:
        default = int(os.getenv("CONTEXTGATE_TOP_K", "5"))
        max_k = int(os.getenv("CONTEXTGATE_MAX_TOP_K", "50"))
    except ValueError:
        default, max_k = 5, 50
    k = req.top_k if req.top_k is not None else default
    return min(k, max_k)


def _sensitivity_mode() -> str:
    return "block" if os.getenv("CONTEXTGATE_BLOCK_ON_SECRET", "0") == "1" else "redact"


@router.get("/healthz")
def healthz() -> dict:
    return {"ok": True}


@router.get("/docs_meta")
def docs_meta(request: Request) -> List[dict]:
    """Return document metadata (id, title, sensitivity) to any caller.

    INTENTIONAL DESIGN: no access control here. Security rationale: knowing a
    document exists is not the same as reading its content. However, titles can
    carry sensitive signal (e.g. "Termination Memo — [Name]"), so production
    deployments should require authentication and review titles for information
    leakage before exposing this endpoint.
    """
    store = request.app.state.store
    return [
        {"id": d.id, "title": d.title, "sensitivity": d.sensitivity.value}
        for d in store.all_docs()
    ]


@router.post("/ask", response_model=AskResponse)
def ask(req: AskRequest, request: Request) -> AskResponse:
    store = request.app.state.store
    provider = request.app.state.provider
    audit: AuditLogger = request.app.state.audit
    role = _resolve_role(req.user_id)

    # 1. retrieval
    hits: List[RetrievalHit] = retrieve(store, req.query, _top_k(req))
    retrieved_ids = [h.doc.id for h in hits]

    # 2. access control — drops restricted docs BEFORE sensitivity scanning and prompt construction
    allowed_hits, denied_hits = access_control.filter_by_role(hits, role)
    allowed_ids = [h.doc.id for h in allowed_hits]
    denied_ids = [h.doc.id for h in denied_hits]

    # 3. sensitivity scan — redact or drop secrets even in permitted docs
    mode = _sensitivity_mode()
    safe_docs: List[Document]
    redactions: List[Redaction]
    safe_docs, redactions = sensitivity.scan_documents(
        [h.doc for h in allowed_hits], mode=mode  # type: ignore[arg-type]
    )

    # docs allowed by AC but dropped by sensitivity (visible in audit, not in prompt)
    safe_doc_ids = {d.id for d in safe_docs}
    sensitivity_blocked_ids = [i for i in allowed_ids if i not in safe_doc_ids]

    # 4. prompt assembly — sees only safe_docs
    system, user = prompt_builder.build_protected_prompt(req.query, safe_docs)
    answer = provider.chat(system, user)

    audit.log(
        AuditEntry(
            ts=now_iso(),
            pipeline="protected",
            user_id=req.user_id,
            role=role,
            query=req.query,
            retrieved_ids=retrieved_ids,
            allowed_ids=allowed_ids,
            denied_ids=denied_ids,
            sensitivity_blocked_ids=sensitivity_blocked_ids,
            sensitivity_mode=mode,
            redactions=redactions,
            final_prompt_preview=preview(user),
            provider=provider.name,
            answer_preview=preview(answer),
        )
    )

    return AskResponse(
        answer=answer,
        pipeline="protected",
        retrieved_ids=retrieved_ids,
        allowed_ids=allowed_ids,
        denied_ids=denied_ids,
        redactions=redactions,
    )


@router.post("/ask_naive", response_model=AskResponse)
def ask_naive(req: AskRequest, request: Request) -> AskResponse:
    """Intentionally unsafe. Exists so adversarial tests can contrast behaviors.

    There is NO access control and NO sensitivity filter here. The only
    defence is a stern instruction in the system prompt. The test suite
    proves that instruction is insufficient.
    """
    store = request.app.state.store
    provider = request.app.state.provider
    audit: AuditLogger = request.app.state.audit
    role = _resolve_role(req.user_id)

    hits = retrieve(store, req.query, _top_k(req))
    retrieved_ids = [h.doc.id for h in hits]
    all_docs = [h.doc for h in hits]

    system, user = prompt_builder.build_naive_prompt(req.query, all_docs)
    answer = provider.chat(system, user)

    audit.log(
        AuditEntry(
            ts=now_iso(),
            pipeline="naive",
            user_id=req.user_id,
            role=role,
            query=req.query,
            retrieved_ids=retrieved_ids,
            allowed_ids=retrieved_ids,
            denied_ids=[],
            sensitivity_blocked_ids=[],
            sensitivity_mode="redact",
            redactions=[],
            final_prompt_preview=preview(user),
            provider=provider.name,
            answer_preview=preview(answer),
        )
    )

    return AskResponse(
        answer=answer,
        pipeline="naive",
        retrieved_ids=retrieved_ids,
        allowed_ids=retrieved_ids,
        denied_ids=[],
        redactions=[],
    )
