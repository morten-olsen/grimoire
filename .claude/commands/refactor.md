Refactor code for simplicity and auditability.

Arguments: $ARGUMENTS

## Principles

This is a security product. Refactoring must improve auditability — the ability of a reviewer to verify correctness by reading the code. Clever is the enemy of auditable.

## Process

1. Read the code to be refactored and understand its current behavior completely
2. Identify what makes it hard to audit:
   - Unnecessary indirection or abstraction layers
   - Implicit behavior (trait impls, deref coercions, blanket impls)
   - Mixed concerns in a single function
   - Unclear error handling paths
3. Plan the refactoring — keep the external behavior identical
4. Implement changes:
   - Each function should do one thing, visibly
   - Error paths should be explicit and traceable
   - Prefer concrete types over trait objects when the set of implementations is fixed
   - Keep data flow linear and readable top-to-bottom
5. Run `cargo test --workspace` — all existing tests must still pass
6. Run `cargo clippy --workspace -- -D warnings`
7. If the refactoring changes any public API surface, update docs
8. Commit as: `refactor(scope): what was simplified and why`
