Diagnose and fix a bug.

Arguments: $ARGUMENTS

## Process

1. Understand the bug from the arguments — reproduce it mentally by reading the relevant code paths
2. Identify the root cause, not just the symptom
3. Check if the bug is in a security-sensitive path (auth, crypto, IPC, prompt, SSH agent):
   - If yes: read `docs/security.md` and relevant specs before making changes
   - Consider whether the bug has security implications beyond the immediate failure
4. Implement the minimal fix:
   - Prefer fixing the root cause over adding defensive checks around the symptom
   - Don't refactor surrounding code — stay focused on the bug
   - Add a test that would have caught this bug
5. Run `cargo clippy --workspace -- -D warnings` and `cargo test --workspace`
6. If docs or CLAUDE.md describe behavior that the bug contradicts, update them
7. Prepare an atomic commit: `fix(scope): description of what was wrong`
