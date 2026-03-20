Create or update a spec for a feature or design change.

Arguments: $ARGUMENTS

## Workflow

1. List existing specs in `specs/` to determine the next number
2. If updating an existing spec, check its Status field:
   - If **Implemented** or **Superseded**: do NOT modify it. Instead, create a new spec that references and supersedes it.
   - If **Proposed** or **Accepted**: update it in place.
3. Read `docs/development.md` for the full spec template and format conventions.
4. For new specs, create `specs/NNN-<slug>.md` with this structure:

```
# ADR NNN: <Title>

## Status
Proposed

## Context
Why this change is needed. Problem statement, constraints, prior art.
What exists today that this feature touches or changes.

## Decision
The concrete design. Be specific enough that implementation is mechanical.
Include: data structures, protocol changes, state machine changes, code sketches, config changes, migration path.

## Consequences

### Positive
What this enables. Why the trade-offs are worth it.

### Negative
Costs, complexity added, limitations, things that get harder.

## Security Analysis

### Threat Model Impact
How this feature changes the threat model in `docs/security.md`.
New trust boundaries, new attack surface, changed assumptions.

### Attack Vectors
| # | Vector | Severity | Description |
|---|--------|----------|-------------|
| 1 | ... | Critical/High/Medium/Low | ... |

### Planned Mitigations
| Vector | Mitigation | Mechanism |
|--------|-----------|-----------|
| 1 | ... | (code-level detail: where and how) |

### Residual Risk
Attacks that remain possible after mitigations, and why they're acceptable.

### Implementation Security Notes
_Filled during finalization. Leave empty when writing the spec._
```

5. The Security Analysis section is required and must be substantive — enumerate actual attack vectors with severity, not just "we'll be careful." Cross-reference the threat model in `docs/security.md`.
6. Update CLAUDE.md if the spec introduces new conventions or gotchas.

After writing the spec, do NOT implement it. The spec is for review and alignment first.
