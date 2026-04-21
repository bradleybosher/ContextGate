# ContextGate Documentation

**This is the canonical entry point for understanding ContextGate's design.**
Future contributors (human or LLM) should start here before touching the code.
The top-level `README.md` is user-facing (what it is, how to run it, demo);
this `docs/` tree is where architecture and rationale live.

## Start here

1. **[architecture.md](architecture.md)** — the pipeline, stage by stage, with file paths.
2. **[threat-model.md](threat-model.md)** — what ContextGate defends against, and what it deliberately does not.
3. **[access-control.md](access-control.md)** — the role + doc model and how filtering decides.
4. **[sensitivity-filters.md](sensitivity-filters.md)** — regex detectors, redact vs block, false-positive notes.
5. **[audit-log.md](audit-log.md)** — audit entry schema and operational guidance.
6. **[adversarial-testing.md](adversarial-testing.md)** — the attack catalogue and why each one matters.
7. **[extending.md](extending.md)** — how to add a provider, swap the embedder, plug a different vector store — without weakening the gate.

## The invariant

There is exactly one invariant ContextGate exists to preserve:

> **Safety is enforced at the retrieval layer, not via prompt wording.**
> A document the current user's role cannot read must never reach the LLM's
> context window. Prompt-level instructions ("do not reveal…") are
> demonstrably unreliable under adversarial input and are not a boundary.

If you are considering a change that adds safety-relevant wording to
`prompt_builder.py`, or that reaches the LLM before access control has
filtered, re-read [threat-model.md](threat-model.md) first.
