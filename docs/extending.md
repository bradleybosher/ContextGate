# Extending ContextGate

The critical constraint: **changes must not move safety decisions from the
retrieval layer into the prompt layer.** If a change would require adding
safety language to `prompt_builder.py`, it's wrong.

## Add an LLM provider

1. Subclass `LLMProvider` in [app/core/llm_provider.py](../app/core/llm_provider.py).
   Implement `chat(system, user) -> str` and set `name`.
2. Extend `get_provider()` with a new branch keyed on the env var.
3. Add any required config (API keys, model names) to `.env.example`.

The gate runs upstream of this layer, so provider choice has zero safety
impact. The test suite should pass with any compliant provider.

## Swap the embedder

[app/core/embeddings.py](../app/core/embeddings.py) exposes `HashingEmbedder`
with an `embed()` / `embed_many()` / `dim` contract. Any class honouring
that shape can replace it:

1. Write a new embedder class (e.g. wrapping `sentence-transformers`).
2. Wire it through `FaissStore(embedder=...)` in
   [scripts/ingest.py](../scripts/ingest.py).
3. Rebuild the index — note that the index must be rebuilt from scratch
   when the embedder changes; embeddings from different models are not
   comparable.

## Swap the vector store

Implement a class with the `FaissStore` surface (`add`, `search`,
`all_docs`, `size`). Inject it at app startup via `create_app(store=...)`.
Keep the contract: `search` returns hits; it does NOT filter.

## Add a sensitivity detector

See [sensitivity-filters.md](sensitivity-filters.md#adding-a-detector).

## Add a role

1. Add the user to `app/data/users.json`.
2. Add the role string to any doc's `allowed_roles` that should grant it.
3. Extend `Role` enum in [app/models/schemas.py](../app/models/schemas.py)
   if you want type-checking (it is not currently enforced at the API
   boundary — a deliberate demo simplification).

## Anti-goals

- Do not add a prompt-injection classifier in front of `/ask`. The
  protected pipeline does not need one: the model never sees restricted
  content, so there is nothing to inject into.
- Do not add safety instructions to `build_protected_prompt`. Prompt
  wording is not a boundary.
- Do not bypass `filter_by_role` for performance. The demo corpus is
  tiny; at real scale, push filtering into the vector store's metadata
  filter, but keep it pre-prompt.
