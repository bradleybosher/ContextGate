# Architecture

ContextGate is a FastAPI service wrapping a tiny RAG pipeline. The distinguishing
feature is that the retrieval pipeline is broken into explicit stages and
each sensitive decision happens *before* prompt construction.

## Pipeline

```
  HTTP /ask (user_id, query)
        │
        ▼
  [1] resolve role           app/api/routes.py::_resolve_role   ← users.json
        │
        ▼
  [2] vector search          app/core/retrieval.py              ← FAISS (IndexFlatIP)
        │
        ▼
  [3] access control         app/core/access_control.py         ← drops restricted docs
        │
        ▼
  [4] sensitivity scan       app/core/sensitivity.py            ← redact or block
        │
        ▼
  [5] prompt assembly        app/core/prompt_builder.py         ← sees only safe_docs
        │
        ▼
  [6] LLM call               app/core/llm_provider.py           ← Mock or Anthropic
        │
        ▼
  [7] audit log              app/audit/audit.py                 ← JSONL, one entry / req
        │
        ▼
     response
```

The parallel `/ask_naive` endpoint skips stages [3] and [4] and relies on
wording in the system prompt. It exists exclusively so the adversarial test
suite can contrast it with `/ask`. Do not build on top of it.

## Module map

| Concern                       | File                                      |
|-------------------------------|-------------------------------------------|
| HTTP routes                   | `app/api/routes.py`                       |
| App factory + startup wiring  | `app/main.py`                             |
| Pydantic schemas              | `app/models/schemas.py`                   |
| Hashing embedder              | `app/core/embeddings.py`                  |
| FAISS wrapper                 | `app/core/vector_store.py`                |
| Retrieval orchestration       | `app/core/retrieval.py`                   |
| **Access control (load-bearing)** | `app/core/access_control.py`          |
| **Sensitivity filter (load-bearing)** | `app/core/sensitivity.py`         |
| Prompt assembly               | `app/core/prompt_builder.py`              |
| Provider abstraction          | `app/core/llm_provider.py`                |
| Audit log                     | `app/audit/audit.py`                      |
| Ingest / index build          | `scripts/ingest.py`                       |
| Sample data                   | `app/data/sample_docs.json`, `users.json` |

## Data flow invariants

* `retrieve()` never filters — it returns raw hits. Filtering is the next
  stage's job so the audit log can record what each stage dropped.
* `filter_by_role()` returns `(allowed, denied)` — denied hits are audited,
  never forwarded.
* `scan_documents()` runs only on role-permitted docs. Secret content in
  permitted docs is either redacted (default) or the doc is dropped entirely.
* `build_protected_prompt()` only ever sees `safe_docs`. There is no code
  path by which a denied or unscrubbed doc can reach it.
