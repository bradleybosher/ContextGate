from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.llm_provider import MockProvider
from app.audit.audit import AuditLogger
from app.main import create_app
from scripts.ingest import build_index


@pytest.fixture()
def audit_path(tmp_path: Path) -> Path:
    return tmp_path / "audit.log"


@pytest.fixture()
def audit(audit_path: Path) -> AuditLogger:
    return AuditLogger(audit_path)


@pytest.fixture()
def client(audit: AuditLogger):
    app = create_app(store=build_index(), provider=MockProvider(), audit=audit)
    with TestClient(app) as c:
        yield c
