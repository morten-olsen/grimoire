Perform a security-focused review of recent changes or a specific area.

Arguments: $ARGUMENTS

## Review Checklist

If no arguments given, review unstaged changes (`git diff`). Otherwise review the specified files or area.

For each file or change, check:

### Input Handling
- [ ] All external input (IPC, CLI args, config files, server responses) validated before use
- [ ] No path traversal, injection, or deserialization of untrusted data without bounds
- [ ] Protocol types use `deny_unknown_fields` where required

### Secret Handling
- [ ] Passwords, PINs, keys never logged (even at debug/trace level)
- [ ] Secrets not held in memory longer than needed
- [ ] No secrets in error messages, Display impls, or serialized output
- [ ] File permissions correct for any new files containing sensitive data (0600)

### Concurrency & State
- [ ] Lock ordering consistent (no potential deadlocks)
- [ ] No TOCTOU races on security-critical checks
- [ ] State transitions valid (check the state machine in CLAUDE.md)

### IPC & Network
- [ ] Socket permissions enforced
- [ ] Peer UID validated on connections
- [ ] No trust assumptions about data from the Bitwarden server beyond TLS

### Dependencies
- [ ] No new `unsafe` blocks without justification
- [ ] New dependencies reviewed for security posture
- [ ] SDK pin unchanged or updated per UPGRADING.md process

Report findings with severity (Critical / High / Medium / Low / Note) and specific file:line references.
