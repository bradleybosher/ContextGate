"""Lightweight evaluation suite.

Surfaces three evaluation signals as assertions with metric-style failure messages:

  1. Block rate   — protected endpoint blocks 100% of (query × marker) pairs.
  2. Harness sanity — naive endpoint leaks at least one pair (validates test data).
  3. False-positive redaction rate — 0 redactions on clean public-doc queries.

These pass/fail; the failure messages are written to read like evaluation outputs
so reviewers can quickly understand the significance of a failure.
"""
from __future__ import annotations

import pytest

from tests.test_adversarial import ADVERSARIAL_QUERIES, CONFIDENTIAL_MARKERS


@pytest.mark.parametrize(
    "query,marker",
    [(q, m) for q in ADVERSARIAL_QUERIES for m in CONFIDENTIAL_MARKERS],
)
def test_protected_blocks_all_query_marker_pairs(client, query: str, marker: str):
    """Block rate must be 100%: protected endpoint must suppress every
    (adversarial query, confidential marker) combination."""
    r = client.post("/ask", json={"user_id": "dan", "query": query})
    r.raise_for_status()
    body = r.json()
    assert marker not in body["answer"], (
        f"EVALUATION FAILURE — block rate < 100%\n"
        f"  query:  {query!r}\n"
        f"  marker: {marker!r}\n"
        f"  leaked in answer: {body['answer'][:200]!r}"
    )


def test_naive_leaks_at_least_one_pair(client):
    """Sanity check: naive endpoint must leak, confirming test data and mock
    LLM are wired correctly.  If this fails the whole evaluation is invalid."""
    leaked: list[tuple[str, str]] = []
    for query in ADVERSARIAL_QUERIES:
        r = client.post("/ask_naive", json={"user_id": "dan", "query": query})
        r.raise_for_status()
        answer = r.json()["answer"]
        for marker in CONFIDENTIAL_MARKERS:
            if marker in answer:
                leaked.append((query, marker))

    assert leaked, (
        "EVALUATION FAILURE — naive endpoint did not leak.\n"
        "Test harness is broken: check mock LLM echo behaviour and sample_docs.json."
    )


def test_zero_false_positive_redactions_on_public_docs(client):
    """False-positive rate must be 0%: a query that only retrieves public docs
    should produce no redactions."""
    r = client.post(
        "/ask",
        json={"user_id": "dan", "query": "Acme Robotics product overview and careers"},
    )
    r.raise_for_status()
    body = r.json()
    assert not body["redactions"], (
        f"EVALUATION FAILURE — false-positive redactions on public docs: "
        f"{len(body['redactions'])} redaction(s) detected: {body['redactions']}"
    )
