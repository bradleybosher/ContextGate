# Access Control

Implementation: [app/core/access_control.py](../app/core/access_control.py).

## Document schema

```json
{
  "id": "hr-001",
  "title": "Engineering Compensation Bands — FY26",
  "sensitivity": "public | internal | confidential",
  "allowed_roles": ["hr", "admin"],
  "content": "..."
}
```

`sensitivity` is a classification label (public / internal / confidential).
`allowed_roles` is the authoritative access list — the label is descriptive;
the roles list is prescriptive.

## Decision rule

A hit is allowed iff any of:

1. `doc.sensitivity == "public"`, OR
2. `"*"` appears in `doc.allowed_roles`, OR
3. the caller's role is literally present in `doc.allowed_roles`.

That is all. There is no inheritance, no role hierarchy, no regex matching.
Keeping the rule boring keeps it auditable.

## Role model (demo)

`app/data/users.json`:

| user_id | role     |
|---------|----------|
| alice   | engineer |
| bob     | hr       |
| carol   | admin    |
| dan     | intern   |

Intern has no entries in any non-public doc's `allowed_roles`, which is why
they are the canonical adversarial-test subject.

## Extension points

- **Real auth.** Replace `_resolve_role` in [app/api/routes.py](../app/api/routes.py)
  with a session-aware resolver. Do not pass `role` from the client.
- **Per-field access.** The current rule is per-document. For structured
  records needing per-field redaction, add a field-level policy and apply
  it inside `scan_documents` rather than `filter_by_role`.
- **Role hierarchy.** If you need `admin ⊇ engineer`, expand the role to
  a set *before* calling `is_allowed`. Do not bake hierarchy into the
  access-control predicate; keep it literal.
