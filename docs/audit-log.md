# Audit Log

Implementation: [app/logging/audit.py](../app/logging/audit.py).

One JSONL line per request, appended to `CONTEXTGATE_AUDIT_LOG`
(default `./audit.log`). Format:

```json
{
  "ts": "2026-04-21T17:03:22.481Z",
  "pipeline": "protected",
  "user_id": "dan",
  "role": "intern",
  "query": "engineering compensation bands FY26",
  "retrieved_ids": ["hr-001", "pub-001"],
  "allowed_ids": ["pub-001"],
  "denied_ids": ["hr-001"],
  "redactions": [{"doc_id": "eng-002", "type": "openai_key", "count": 1}],
  "final_prompt_preview": "Context: ...\n\nQuestion: engineering compensation bands FY26",
  "provider": "mock",
  "answer_preview": "[mock-llm] system=..."
}
```

## Field guide

- `pipeline` — `"protected"` for `/ask`, `"naive"` for `/ask_naive`.
- `retrieved_ids` — whatever the vector search returned, before any filter.
- `allowed_ids` / `denied_ids` — the access-control partition. `denied_ids`
  is the field to watch: it records what the user was *prevented* from
  seeing, which is the evidence the gate is working.
- `redactions` — sensitivity-stage detections. A populated list in redact
  mode indicates secrets were scrubbed; in block mode it indicates docs
  that were dropped.
- `final_prompt_preview` — first 500 chars of the prompt actually sent
  to the LLM. Truncated on purpose: full prompts can be large and would
  balloon log size.

## What to alert on (production)

- `denied_ids` growing much faster than baseline for a single `user_id` →
  probable probing attempt.
- `pipeline == "naive"` in any environment other than test → misconfig.
- `redactions` for a document that *should not contain secrets* → the
  source doc has drift; fix upstream.

## Rotation

The shipped logger appends indefinitely. For production:
- point `CONTEXTGATE_AUDIT_LOG` at a rotating file handler, OR
- ship entries to a SIEM via a sidecar tail.

Do not swallow or batch entries in a way that loses them on crash.
