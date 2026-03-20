# Tutorial: Headless Servers

BitSafe works on machines without a display — remote servers, CI runners, SSH sessions. The experience is different from desktop usage because there's no GUI prompt, but the core functionality is the same.

## The Difference: No GUI

On a desktop, BitSafe uses GUI prompts for:
- Unlocking the vault
- Access approval (biometric/PIN/password verification)

On a headless machine, there's no display for these prompts. You have two options:
1. Use **terminal prompts** — type your password in the terminal
2. Use **`bitsafe authorize`** — pre-approve access for your terminal session

The security model shifts: on desktop, the GUI prompt is the defense against blind RCE (attacker has shell but can't interact with the dialog). On headless, that defense isn't available — the terminal is the only authentication boundary.

## Setup for Headless

### Configuration

```toml
# ~/.config/bitsafe/config.toml
[server]
url = "https://vault.example.com"

[prompt]
method = "terminal"       # skip GUI prompt discovery, go straight to terminal
```

For fully automated CI environments:

```toml
[prompt]
method = "none"           # never prompt — caller must provide password in RPC params
```

Access approval is always required and cannot be disabled. In automated environments, use `bitsafe authorize` with the master password piped to stdin.

### Service

On a server with systemd:

```bash
bitsafe service install
```

Without systemd (tmux, screen, or background):

```bash
bitsafe-service &
```

## Daily Usage: SSH Sessions

### First Connection

```bash
# SSH into the server
ssh user@server

# Log in (first time only)
bitsafe login you@example.com

# Unlock and authorize in one step
bitsafe unlock --terminal
# or just run a vault command — it auto-prompts:
bitsafe list
```

When you unlock with a direct password (terminal mode), access approval is automatically granted for your terminal session. You don't need a separate `bitsafe authorize` step.

### Subsequent Connections

If the service is still running and the vault is unlocked (hasn't auto-locked):

```bash
ssh user@server
bitsafe authorize         # re-authorize this new session
bitsafe list              # works
```

If the vault has auto-locked:

```bash
ssh user@server
bitsafe list              # auto-prompts for password, unlocks, shows list
```

### Multiple Terminal Sessions

Each SSH connection is a different terminal session. Approval is scoped per session by default, so you need to authorize each one:

```bash
# Terminal 1
bitsafe authorize         # approved

# Terminal 2 (separate SSH connection)
bitsafe authorize         # need to authorize again
```

This is intentional — it prevents a background process from riding on your interactive session's approval.

## CI / Automated Pipelines

For fully automated usage, you need to provide the password programmatically and disable interactive approval.

### Script Usage

```bash
#!/bin/bash
set -euo pipefail

# Start service if not running
pgrep -x bitsafe-service >/dev/null || bitsafe-service &
sleep 1

# Login (if not already logged in)
if ! bitsafe status 2>/dev/null | grep -q "Unlocked\|Locked"; then
  echo "$BITSAFE_PASSWORD" | bitsafe login "$BITSAFE_EMAIL" --server "$BITSAFE_SERVER"
fi

# Unlock (if locked) — also grants approval for this session
if bitsafe status 2>/dev/null | grep -q "Locked"; then
  echo "$BITSAFE_PASSWORD" | bitsafe unlock --terminal
fi

# Re-authorize if approval expired (approval lasts 5 min)
echo "$BITSAFE_PASSWORD" | bitsafe authorize

# Use secrets
DB_PASS="bitsafe:prod-db/password" bitsafe run -- ./deploy.sh
```

### Security Notes for CI

- The master password must be available to the CI runner — store it as a CI secret (GitHub Actions secret, GitLab CI variable, etc.)
- Access approval is always required — CI scripts must use `bitsafe authorize` to grant it
- Approval lasts 5 minutes — long-running jobs may need periodic re-authorization
- Consider whether you actually need BitSafe in CI, or whether your CI platform's native secret management is sufficient
- The vault should be locked/logged out at the end of the job

## Using SSH Agent on Headless

The SSH agent works on headless machines. Pre-authorize before using it:

```bash
# Set the socket
export SSH_AUTH_SOCK="${XDG_RUNTIME_DIR}/bitsafe/ssh-agent.sock"

# Authorize for this session
bitsafe authorize

# Now SSH agent signing works
ssh-add -l               # lists keys
ssh git@github.com       # signs successfully
git push                 # commit signing works too
```

Without `bitsafe authorize`, the agent will attempt a GUI prompt, fail (no display), and reject the signing request. The SSH client sees "signing failed."

## Troubleshooting

### "No display available" or prompt hangs

The service is trying to launch a GUI prompt on a machine with no display.

Fix: set `method = "terminal"` in config, or use `bitsafe unlock --terminal`.

### Auto-lock keeps locking the vault during long jobs

The auto-lock timeout is hardcoded at 15 minutes and cannot be changed. For long-running jobs, have your script periodically run a vault command (e.g. `bitsafe status`) to reset the timer, or re-unlock when needed.

### SSH agent says "no identities" after a while

The vault auto-locked. SSH agent requests don't reset the inactivity timer. Either:
- Increase `auto_lock_seconds`
- Have your script run `bitsafe status` periodically
- Re-unlock when needed

### `bitsafe authorize` says "already authorized"

Your session is already approved. The approval might have been granted by a previous `bitsafe unlock --terminal` in the same session.

### Scripts fail with "vault is locked" but password piping doesn't work

Make sure you're piping to stdin correctly:

```bash
echo "$PASSWORD" | bitsafe unlock --terminal
```

Not:

```bash
bitsafe unlock --terminal <<< "$PASSWORD"  # this also works
```

## What's Next

- **[Quick Reference](../quickstart.md)** — all commands and config options
- **[Security Model](../security.md)** — understand what headless mode gives up
- **[SSH Agent Reference](../ssh-agent.md)** — detailed agent protocol and troubleshooting
