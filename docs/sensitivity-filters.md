# Sensitivity Filters

Implementation: [app/core/sensitivity.py](../app/core/sensitivity.py).

This stage runs *after* access control. Its job is to catch secrets in docs
the user *is* allowed to read — for example, a staging-credentials runbook
that legitimately belongs to engineers but shouldn't be echoed verbatim into
an LLM context window.

## Detector catalogue

| Name               | Pattern (simplified)                                         |
|--------------------|--------------------------------------------------------------|
| `openai_key`       | `sk-[A-Za-z0-9_\-]{16,}`                                     |
| `aws_access_key`   | `AKIA[0-9A-Z]{16}`                                           |
| `email`            | standard RFC-ish email regex                                 |
| `keyed_secret`     | `password|api_key|secret|token  [:=]  <value 6+ chars>`      |

Detectors run on every role-permitted document's `content` before prompt
construction.

## Modes

Set via `CONTEXTGATE_BLOCK_ON_SECRET`:

- `0` (default) — **redact**: matches are replaced with `[REDACTED:<type>]`
  and the (modified) document proceeds to the prompt.
- `1` — **block**: any document containing a match is dropped from context
  entirely.

Redactions are always recorded in the audit entry, regardless of mode.

## Known false-positive patterns

- Long base64 payloads in engineering notes may match the generic key
  pattern. The shipped regex is deliberately conservative (`sk-` prefix or
  `AKIA` prefix) to reduce this, at the cost of missing generic high-entropy
  strings. For high-stakes environments, use block mode and accept the
  recall cost, or swap in a real DLP scanner.
- Email-like strings in URLs (`user@host/path`) can match the email
  detector. For the demo corpus this is benign.

## Adding a detector

1. Append a `_Detector(name, pattern)` to `_DETECTORS` in
   [app/core/sensitivity.py](../app/core/sensitivity.py).
2. Add a test in [tests/test_sensitivity.py](../tests/test_sensitivity.py)
   covering one true positive and one true negative.
3. Document the detector's name and pattern in the table above.
