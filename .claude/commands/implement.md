Implement a feature from an existing spec.

Arguments: $ARGUMENTS

## Workflow

1. Read the spec file referenced in the arguments (e.g., `specs/010-feature.md`)
2. Verify the spec Status is **Proposed** or **Accepted** — refuse to implement Superseded specs
3. Read related docs and code referenced in the spec to understand the full context
4. Read the spec's **Security Analysis** section carefully — understand the attack vectors and planned mitigations before writing code
5. Plan the implementation:
   - Identify all files to create or modify
   - Map each planned mitigation to specific code locations
   - Identify what tests are needed (including tests for each attack vector)
6. Implement the changes following these principles:
   - **Minimal surface area**: only add what the spec calls for
   - **No unsafe code** without explicit justification in the spec
   - **Error handling**: use typed errors (thiserror), no `.unwrap()` on fallible operations in non-test code
   - **Secrets**: never log, serialize to debug output, or hold longer than necessary
   - **Serde structs**: use `deny_unknown_fields` on protocol types (see CLAUDE.md)
7. Run `cargo clippy --workspace -- -D warnings` and `cargo test --workspace`
8. Fill in the spec's **Implementation Security Notes** section:
   - Deviations from planned mitigations and why
   - Additional mitigations not in the original plan
   - Which attack vectors have regression tests
9. Update the spec Status to **Implemented**
10. Update `docs/` if the feature changes user-facing behavior or architecture
11. Update `docs/security.md` if the threat model changed
12. Update CLAUDE.md if you discover new gotchas or conventions
