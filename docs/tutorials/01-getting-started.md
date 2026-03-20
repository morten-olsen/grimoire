# Tutorial: Getting Started

This tutorial walks you through your first session with BitSafe — from login to retrieving your first secret. It assumes you've already [installed BitSafe](../install.md) and have a running Vaultwarden (or Bitwarden-compatible) server.

## Before We Start: What You're Getting Into

BitSafe is a daemon. When you interact with `bitsafe` on the command line, you're not talking to your server directly — you're talking to a local service (`bitsafe-service`) that holds your decrypted vault keys in memory and mediates all access to them.

This means:
- You log in **once** — the service remembers your credentials across restarts
- You unlock the vault — the service holds decrypted keys until it locks (auto-lock or manual)
- Every vault operation goes through the service — the CLI is just a thin JSON-RPC client

It also means the service is the thing keeping your secrets safe. If it's compromised, your vault is compromised. Read the [security model](../security.md) when you get a chance. We'll wait.

## Step 1: Start the Service

If you ran `bitsafe service install` during setup, the service is already running. Check with:

```bash
bitsafe status
```

If it's not running, start it:

```bash
bitsafe-service &
```

Or, for a one-time test without backgrounding:

```bash
bitsafe-service
# (runs in foreground, Ctrl+C to stop)
```

## Step 2: Log In

Login is a one-time operation. It authenticates you against your server and saves encrypted credentials so you only need to unlock (not re-login) in the future.

```bash
bitsafe login you@example.com --server https://vault.example.com
```

You'll be prompted for your master password in the terminal. This is the only time BitSafe asks for your password in the terminal by design — all subsequent password entries go through the GUI prompt, which requires physical access to your display.

If your server URL is in your config file, you can omit `--server`:

```toml
# ~/.config/bitsafe/config.toml
[server]
url = "https://vault.example.com"
```

```bash
bitsafe login you@example.com
```

### What Just Happened

The service:
1. Fetched your KDF parameters from the server (prelogin)
2. Derived your master key hash using the Bitwarden SDK
3. Authenticated against the server and received encrypted vault keys
4. Initialized the SDK's crypto with your keys
5. Synced your vault from the server
6. Saved encrypted login state to `~/.local/share/bitsafe/login.json`

Your master password was used to derive keys and then... well, it's still somewhere in heap memory as a `String`. We're working on that. The SDK zeroizes its own internal key material, but our wrapper layer doesn't yet. See? Honest.

## Step 3: Explore Your Vault

List everything:

```bash
bitsafe list
```

Search for something specific:

```bash
bitsafe list --search github
```

Get the full details of an item (use the ID from the list output):

```bash
bitsafe get <id>
```

### Getting Specific Fields

The `-f` flag extracts a single field, which is useful for piping:

```bash
# Get just the password
bitsafe get <id> -f password

# Get the username
bitsafe get <id> -f username

# Get TOTP code
bitsafe get <id> -f totp
# or equivalently:
bitsafe totp <id>
```

### Copying to Clipboard

```bash
# Linux (X11)
bitsafe get <id> -f password | xclip -selection clipboard

# Linux (Wayland)
bitsafe get <id> -f password | wl-copy

# macOS
bitsafe get <id> -f password | pbcopy
```

## Step 4: Understanding Access Approval

Here's where BitSafe differs from most CLI password managers. By default, every vault operation requires **access approval** — a check that the person requesting access is actually you, sitting at the machine, right now.

The first time you run a vault command after unlock, you'll see a GUI prompt asking for biometric verification (fingerprint), a PIN, or your master password. Once you approve, the approval is cached for your terminal session (default: 5 minutes).

```bash
bitsafe list          # GUI prompt appears on first access
bitsafe get <id>      # no prompt — same session, still approved
# ... 5 minutes pass ...
bitsafe list          # GUI prompt again
```

This is the defense against blind RCE: if an attacker gets shell access to your machine, they can run `bitsafe list`, but they can't interact with the GUI prompt that appears on your display. They'd need physical access (or a display server exploit) to approve the operation.

### Setting Up a PIN

After the first biometric or password verification, you can set a PIN for faster re-verification:

```bash
# PIN is set during the first GUI prompt interaction
# Subsequent prompts will offer: biometric → PIN → password
```

### Headless Environments

Access approval cannot be disabled — it's a hardcoded security invariant. On headless machines without a GUI, use `bitsafe authorize` to grant approval via master password in the terminal:

```bash
bitsafe authorize    # prompts for master password
bitsafe list         # approved for this terminal session (5 min)
```

See the [Headless Tutorial](04-headless.md) for the full story.

## Step 5: Locking and Unlocking

Lock the vault manually:

```bash
bitsafe lock
```

Or let it auto-lock after inactivity (default: 15 minutes). When locked, vault operations prompt you to unlock:

```bash
bitsafe list
# "Vault is locked" → GUI prompt appears → enter password → list shows
```

BitSafe auto-prompts on locked vault. You don't need a separate `unlock` step — just use it, and it'll ask for your password when needed.

To unlock explicitly:

```bash
bitsafe unlock              # GUI prompt (default — requires display access)
bitsafe unlock --terminal   # terminal prompt (for SSH sessions)
```

### Why GUI Unlock by Default?

Because terminal unlock means any process that can send keystrokes to your terminal can unlock your vault. GUI unlock requires interacting with a separate window on your display, which is a stronger authentication boundary.

## Step 6: Syncing

BitSafe syncs your vault automatically in the background (default: every 5 minutes). To force a sync:

```bash
bitsafe sync
```

## Step 7: Logging Out

When you're done (or want to clear all saved state):

```bash
bitsafe logout
```

This deletes the persistent login state (`~/.local/share/bitsafe/login.json`). You'll need to `bitsafe login` again next time.

Versus locking:
- **Lock**: keys scrubbed from memory, need password to unlock. Login state preserved.
- **Logout**: everything cleared, need full login next time.

## What's Next

- **[SSH Agent Tutorial](02-ssh-agent.md)** — use your vault's SSH keys for authentication and git signing
- **[Secret Injection Tutorial](03-secret-injection.md)** — inject secrets into process environments
- **[Headless Servers Tutorial](04-headless.md)** — run BitSafe on machines without a display
- **[Quick Reference](../quickstart.md)** — all commands at a glance
