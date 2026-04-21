from __future__ import annotations

from enum import Enum
from typing import List, Literal, Optional

from pydantic import BaseModel, Field


class Sensitivity(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"


class Role(str, Enum):
    INTERN = "intern"
    ENGINEER = "engineer"
    HR = "hr"
    ADMIN = "admin"


class Document(BaseModel):
    id: str
    title: str
    sensitivity: Sensitivity
    allowed_roles: List[str]
    content: str


class User(BaseModel):
    user_id: str
    role: str
    display_name: str


class RetrievalHit(BaseModel):
    doc: Document
    score: float


class Redaction(BaseModel):
    doc_id: str
    type: str
    count: int


class AskRequest(BaseModel):
    user_id: str
    query: str
    top_k: Optional[int] = None


class AskResponse(BaseModel):
    answer: str
    pipeline: Literal["protected", "naive"]
    retrieved_ids: List[str]
    allowed_ids: List[str]
    denied_ids: List[str]
    redactions: List[Redaction]


class AuditEntry(BaseModel):
    ts: str
    pipeline: Literal["protected", "naive"]
    user_id: str
    role: str
    query: str
    retrieved_ids: List[str]
    allowed_ids: List[str]
    denied_ids: List[str]
    sensitivity_blocked_ids: List[str] = Field(default_factory=list)
    sensitivity_mode: Literal["redact", "block"] = "redact"
    redactions: List[Redaction] = Field(default_factory=list)
    final_prompt_preview: str
    provider: str
    answer_preview: str
