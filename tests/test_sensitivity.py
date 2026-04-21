from __future__ import annotations

from app.core.sensitivity import scan_document, scan_documents
from app.models.schemas import Document, Sensitivity


def _doc(content: str) -> Document:
    return Document(
        id="t",
        title="t",
        sensitivity=Sensitivity.INTERNAL,
        allowed_roles=["*"],
        content=content,
    )


def test_openai_style_key_is_redacted():
    d = _doc("key is sk-test-ABCD1234EFGH5678IJKLMNOP done")
    out, reds = scan_document(d, mode="redact")
    assert out is not None
    assert "sk-test-ABCD1234EFGH5678" not in out.content
    assert "[REDACTED:openai_key]" in out.content
    assert any(r.type == "openai_key" for r in reds)


def test_aws_key_is_redacted():
    d = _doc("access = AKIAIOSFODNN7EXAMPLE end")
    out, reds = scan_document(d, mode="redact")
    assert out is not None
    assert "AKIAIOSFODNN7EXAMPLE" not in out.content
    assert any(r.type == "aws_access_key" for r in reds)


def test_email_is_redacted():
    d = _doc("contact alice@acme.example.com please")
    out, reds = scan_document(d, mode="redact")
    assert out is not None
    assert "alice@acme.example.com" not in out.content
    assert "[REDACTED:email]" in out.content


def test_block_mode_drops_the_document():
    d = _doc("key sk-test-ABCD1234EFGH5678IJKLMN")
    out, reds = scan_document(d, mode="block")
    assert out is None
    assert reds  # detections still recorded


def test_clean_text_is_unchanged():
    d = _doc("nothing sensitive here, just prose about robots.")
    out, reds = scan_document(d, mode="redact")
    assert out is not None
    assert out.content == d.content
    assert reds == []


def test_db_connection_string_is_redacted():
    d = _doc("connect via postgresql://admin:s3cr3t@db.internal:5432/prod done")
    out, reds = scan_document(d, mode="redact")
    assert out is not None
    assert "postgresql://admin:s3cr3t" not in out.content
    assert "[REDACTED:db_connection_string]" in out.content
    assert any(r.type == "db_connection_string" for r in reds)


def test_scan_documents_preserves_clean_drops_blocked():
    clean = _doc("safe content")
    dirty = _doc("api_key=supersecretvalue123")
    kept, reds = scan_documents([clean, dirty], mode="block")
    assert [d.content for d in kept] == ["safe content"]
    assert reds  # keyed_secret detected in the dropped doc
