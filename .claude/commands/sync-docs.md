Synchronize documentation with the current state of the codebase.

Arguments: $ARGUMENTS

If arguments specify a doc, update that doc. Otherwise check all docs.

## Process

1. For each doc in `docs/`:
   - Read the doc
   - Read the code it describes
   - Identify any discrepancies (outdated descriptions, missing features, removed features, wrong file paths)
   - Update the doc to match reality
2. Check `CLAUDE.md`:
   - Are all gotchas still accurate?
   - Are there new gotchas from recent changes not yet documented?
   - Are file paths and binary names correct?
3. Do NOT update specs — specs are historical records once implemented. If a spec's decisions have been revised, note this in the doc that covers that area instead.
4. Do NOT add speculative content — only document what exists in the code today.
