Deep audit of a specific crate or module for security and code quality.

Arguments: $ARGUMENTS

## Process

1. Read every source file in the specified crate/module
2. Trace data flow from entry points (public API, IPC handlers, CLI commands) through to exit points (SDK calls, file I/O, network)
3. For each flow, evaluate:
   - Can untrusted input reach a sensitive operation without validation?
   - Are error paths handled correctly (no silent failures, no information leaks)?
   - Is the code auditable — could a security reviewer follow the logic?
4. Check for complexity that harms auditability:
   - Unnecessary abstractions or indirection
   - Implicit behavior (trait impls that do surprising things)
   - Magic constants without explanation
5. Cross-reference against `docs/security.md` and relevant specs
6. Report findings organized by severity, with concrete recommendations

Prioritize findings that affect the threat model in `docs/security.md`. Note where code is correct but hard to audit — simplicity IS security for this project.
