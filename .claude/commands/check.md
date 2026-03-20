Run the full quality check pipeline: format check, clippy, and tests.

1. Run `cargo fmt --all -- --check` to verify formatting
2. Run `cargo clippy --workspace -- -D warnings` to catch lint issues
3. Run `cargo test --workspace` to run all tests

Report results for each step. If any step fails, stop and report the failure with details on what needs fixing.
