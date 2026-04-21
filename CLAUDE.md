# ContextGate — Session Orientation

ContextGate is a FastAPI demo showing that **sensitive-data leakage in LLM apps is a
retrieval-layer problem, not a prompt-layer problem.** Access control and sensitivity
redaction run upstream of prompt construction; the LLM never sees what the caller
is not authorized to see.

## The one invariant

**Safety is enforced at the retrieval layer — never via prompt wording.**

Do not respond to feature or bug requests by adding safety language to
`app/core/prompt_builder.py`, by adding a prompt-injection classifier in front of
`/ask`, or by hardening the system prompt. Those are the exact failure modes this
project exists to disprove. The naive pipeline (`/ask_naive`) exists as a foil and
must keep leaking — if it stops leaking, the demo has failed.

If a proposed change would move a decision from code into prompt text, push back
or route the fix to the gate stages instead: access control
(`app/core/access_control.py`) or sensitivity scan (`app/core/sensitivity.py`).

## Architecture entry point

Start at **[docs/README.md](docs/README.md)** — it indexes the modular docs
(architecture, threat model, access control, sensitivity filters, audit log,
adversarial testing, extension guide). Read `docs/architecture.md` first for the
pipeline diagram and module map.

## Commands

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows
pip install -e .[dev]
pytest -q                       # full suite; adversarial tests must show naive-leak + protected-safe
uvicorn app.main:app --reload   # run service
```

## Notes

- Audit logic lives in `app/audit/audit.py`. Do not create a package named `logging` — it shadows the stdlib module and breaks uvicorn multiprocessing.
- `user_id` is trusted from the request body. Demo simplification — documented in the README.
- Audit log append-only at `CONTEXTGATE_AUDIT_LOG` (default `./audit.log`).
