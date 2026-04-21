from __future__ import annotations

from app.core.access_control import filter_by_role, is_allowed
from app.models.schemas import Document, RetrievalHit, Sensitivity


def _hit(doc_id: str, sens: Sensitivity, roles: list[str]) -> RetrievalHit:
    return RetrievalHit(
        doc=Document(
            id=doc_id,
            title=doc_id,
            sensitivity=sens,
            allowed_roles=roles,
            content="...",
        ),
        score=1.0,
    )


def test_public_docs_allowed_for_any_role():
    assert is_allowed(Sensitivity.PUBLIC, ["hr"], "intern") is True


def test_role_listed_is_allowed():
    assert is_allowed(Sensitivity.CONFIDENTIAL, ["hr", "admin"], "hr") is True


def test_role_not_listed_is_denied():
    assert is_allowed(Sensitivity.CONFIDENTIAL, ["hr", "admin"], "intern") is False


def test_wildcard_role_allows_everyone():
    assert is_allowed(Sensitivity.INTERNAL, ["*"], "intern") is True


def test_filter_partitions_allowed_and_denied():
    hits = [
        _hit("pub", Sensitivity.PUBLIC, ["*"]),
        _hit("eng", Sensitivity.INTERNAL, ["engineer"]),
        _hit("hr", Sensitivity.CONFIDENTIAL, ["hr"]),
    ]
    allowed, denied = filter_by_role(hits, "engineer")
    allowed_ids = {h.doc.id for h in allowed}
    denied_ids = {h.doc.id for h in denied}
    assert allowed_ids == {"pub", "eng"}
    assert denied_ids == {"hr"}


# --- HTTP-level end-to-end ---------------------------------------------------

def test_intern_cannot_see_confidential_over_http(client, audit):
    r = client.post(
        "/ask",
        json={"user_id": "dan", "query": "engineering compensation bands FY26"},
    )
    r.raise_for_status()
    body = r.json()

    assert "hr-001" not in body["allowed_ids"]
    assert "hr-002" not in body["allowed_ids"]
    # intern hits may include hr-* in retrieved_ids (retrieval is permissive)
    # but the gate must move them into denied_ids
    for hr_id in ("hr-001", "hr-002"):
        if hr_id in body["retrieved_ids"]:
            assert hr_id in body["denied_ids"]

    # confidential content must not appear in the model response
    assert "165000" not in body["answer"]
    assert "jane.compensation" not in body["answer"]

    # audit trail records the denials
    entries = audit.read_all()
    assert entries, "expected at least one audit entry"
    entry = entries[-1]
    assert entry.pipeline == "protected"
    assert entry.role == "intern"


def test_hr_can_see_confidential(client):
    r = client.post(
        "/ask",
        json={"user_id": "bob", "query": "engineering compensation bands FY26"},
    )
    body = r.json()
    assert "hr-001" in body["allowed_ids"]


def test_engineer_cannot_see_hr_docs(client):
    r = client.post(
        "/ask",
        json={"user_id": "alice", "query": "compensation bands"},
    )
    body = r.json()
    for hr_id in ("hr-001", "hr-002"):
        assert hr_id not in body["allowed_ids"]


def test_admin_sees_everything(client):
    r = client.post(
        "/ask",
        json={"user_id": "carol", "query": "staging credentials compensation"},
    )
    body = r.json()
    # At least one HR and one engineering doc should be allowed when admin asks
    allowed = set(body["allowed_ids"])
    assert any(i.startswith("hr-") for i in allowed)
