Add or improve tests for a specific area.

Arguments: $ARGUMENTS

## Process

1. Read the code to be tested and understand all code paths — happy paths, error paths, edge cases
2. Identify what's currently untested or under-tested:
   - Use `cargo test --workspace -- --list` to see existing tests
   - Check for missing edge cases, error conditions, boundary values
3. For security-sensitive code, test:
   - Input validation boundaries (malformed input, overflow, empty strings)
   - State machine transitions (valid and invalid)
   - Error messages don't leak secrets
   - Permission checks can't be bypassed
4. Write tests that are:
   - Named descriptively: `test_<function>_<scenario>_<expected_behavior>`
   - Self-contained — no shared mutable state between tests
   - Testing behavior, not implementation details
5. Run `cargo test --workspace` to verify everything passes
6. Commit as: `test(scope): add tests for <what>`
