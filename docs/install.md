# Installation Guide

BitSafe runs on Linux and macOS, with experimental support for Android via Termux. This guide covers every way to get it running.

## From Prebuilt Binaries (Recommended)

Download the latest release for your platform from [GitHub Releases](../../releases).

Each release archive contains:
- `bitsafe` — the CLI client
- `bitsafe-service` — the background daemon
- `bitsafe-prompt` — the generic GUI/terminal prompt agent
- `bitsafe-prompt-linux` or `bitsafe-prompt-macos` — the native prompt (when available)
- `contrib/` — systemd and launchd service files

### Linux (x86_64 / aarch64)

```bash
# Download and extract
tar xzf bitsafe-v*.tar.gz
cd bitsafe-v*

# Install binaries
sudo install -m 755 bitsafe bitsafe-service bitsafe-prompt /usr/local/bin/

# Install native prompt if present
[ -f bitsafe-prompt-linux ] && sudo install -m 755 bitsafe-prompt-linux /usr/local/bin/

# Set up the service (auto-start on login)
bitsafe service install
```

### macOS (Apple Silicon / Intel)

```bash
# Download and extract
tar xzf bitsafe-v*.tar.gz
cd bitsafe-v*

# Install binaries
sudo install -m 755 bitsafe bitsafe-service bitsafe-prompt /usr/local/bin/

# Install native prompt if present
[ -f bitsafe-prompt-macos ] && sudo install -m 755 bitsafe-prompt-macos /usr/local/bin/

# Set up the service (auto-start on login)
bitsafe service install
```

## From Source

### Prerequisites

| Dependency | Required | Purpose |
|------------|----------|---------|
| Rust 1.88+ | Yes | Core build toolchain |
| `libgtk-4-dev` | Linux, optional | Native GTK4 prompt UI |
| `libadwaita-1-dev` | Linux, optional | Native libadwaita prompt UI |
| Xcode CLI Tools | macOS, optional | Native Swift prompt |
| `zenity` or `kdialog` | Linux, optional | Fallback GUI prompt (usually pre-installed) |

Install Rust:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### Build Everything

If you have [go-task](https://taskfile.dev/) installed:

```bash
task build    # builds workspace + native prompts for your platform
task install  # installs all binaries to ~/.cargo/bin
```

Or manually:

```bash
# Core workspace
cargo build --workspace --release

# Install core binaries
cargo install --path crates/bitsafe-cli
cargo install --path crates/bitsafe-service
cargo install --path crates/bitsafe-prompt
```

### Native Prompts (Optional but Recommended)

The native prompts provide proper system-integrated password dialogs instead of generic zenity/kdialog.

**Linux (GTK4/libadwaita):**

```bash
# Install dependencies (Debian/Ubuntu)
sudo apt install libgtk-4-dev libadwaita-1-dev

# Fedora
sudo dnf install gtk4-devel libadwaita-devel

# Arch
sudo pacman -S gtk4 libadwaita

# Build and install
cd native/linux && cargo build --release
cp target/release/bitsafe-prompt-linux ~/.cargo/bin/
```

**macOS (Swift):**

```bash
# Requires Xcode Command Line Tools
xcode-select --install

# Build and install
cd native/macos && swift build -c release
cp .build/release/bitsafe-prompt-macos ~/.cargo/bin/
```

The service discovers prompt binaries in this order:
1. `bitsafe-prompt-{platform}` next to the service binary
2. `bitsafe-prompt` next to the service binary
3. PATH lookup
4. Terminal fallback (always available)

## Service Setup

### Auto-Start on Login

The easiest way:

```bash
bitsafe service install
```

This creates a systemd user unit (Linux) or launchd LaunchAgent (macOS) and starts the service immediately.

To stop and remove:

```bash
bitsafe service uninstall
```

### Manual Start

If you prefer to run the service yourself:

```bash
bitsafe-service
```

It runs in the foreground and logs to stderr. You can background it, wrap it in a tmux session, or manage it however you like.

### Verify

```bash
bitsafe status
```

Should show `Service is running` and the current vault state.

## Shell Completions

```bash
# Bash — add to ~/.bashrc
bitsafe completions bash >> ~/.bashrc

# Zsh — create completion file
bitsafe completions zsh > ~/.zfunc/_bitsafe

# Fish
bitsafe completions fish > ~/.config/fish/completions/bitsafe.fish
```

## Android (Termux)

BitSafe works in Termux with terminal-only prompts (no native GUI). This is experimental.

### Prerequisites

```bash
# Install Rust in Termux
pkg install rust binutils

# OpenSSL for the SDK's HTTP
pkg install openssl
```

### Build

```bash
git clone https://github.com/user/bitsafe.git
cd bitsafe
cargo install --path crates/bitsafe-cli
cargo install --path crates/bitsafe-service
cargo install --path crates/bitsafe-prompt
```

### Configuration

Since Termux has no GUI environment, configure the prompt to always use terminal mode:

```toml
# ~/.config/bitsafe/config.toml
[server]
url = "https://vault.example.com"

[prompt]
method = "terminal"
```

Access approval is always required. On Termux, use `bitsafe authorize` to grant approval for your terminal session (prompts for master password).

### Running

Start the service manually:

```bash
bitsafe-service &
```

For auto-start on boot, you can use [Termux:Boot](https://wiki.termux.com/wiki/Termux:Boot):

```bash
mkdir -p ~/.termux/boot
cat > ~/.termux/boot/bitsafe.sh << 'EOF'
#!/data/data/com.termux/files/usr/bin/sh
bitsafe-service &
EOF
chmod +x ~/.termux/boot/bitsafe.sh
```

### Limitations on Termux

- No biometric or GUI prompts — terminal password entry only
- No `mlockall` or `PR_SET_DUMPABLE` — Android's security model is different
- SSH agent works if you set `SSH_AUTH_SOCK` correctly
- Access approval works via `bitsafe authorize` (master password in terminal)

## Configuration

Create `~/.config/bitsafe/config.toml`:

```toml
[server]
url = "https://vault.example.com"    # your Vaultwarden/Bitwarden server

[prompt]
method = "auto"                      # auto | gui | terminal | none

[ssh_agent]
enabled = true                       # embedded SSH agent (default: true)
```

All settings are optional — sensible defaults are used when omitted.

Security parameters are hardcoded constants — not configurable. This is deliberate: configurability in security-critical paths is attack surface. An attacker who can modify your config file could weaken your security posture.

| Parameter | Value | Purpose |
|-----------|-------|---------|
| Auto-lock timeout | 900s (15 min) | Vault locks after inactivity |
| Background sync | 300s (5 min) | Periodic vault sync |
| Approval duration | 300s (5 min) | How long a session approval lasts |
| Approval scope | Terminal session | Scoped to session leader PID |
| PIN max attempts | 3 | Auto-lock after 3 wrong PINs |
| Access approval | Always required | Cannot be disabled |

## Vaultwarden Server Requirements

If you use SSH keys in your vault, your Vaultwarden instance needs this environment variable:

```
EXPERIMENTAL_CLIENT_FEATURE_FLAGS=fido2-vault-credentials,ssh-key-vault-item,ssh-agent
```

Without it, SSH key ciphers (type 5) are silently filtered from sync responses. Restart Vaultwarden after adding it.

## Uninstalling

```bash
# Remove service auto-start
bitsafe service uninstall

# Remove binaries
rm ~/.cargo/bin/bitsafe ~/.cargo/bin/bitsafe-service ~/.cargo/bin/bitsafe-prompt
rm -f ~/.cargo/bin/bitsafe-prompt-linux ~/.cargo/bin/bitsafe-prompt-macos

# Remove data (login state, logs)
rm -rf ~/.local/share/bitsafe

# Remove config
rm -rf ~/.config/bitsafe
```

## Next Steps

- **[Tutorial: Getting Started](tutorials/01-getting-started.md)** — first login and basic usage
- **[Tutorial: SSH Agent](tutorials/02-ssh-agent.md)** — set up SSH authentication with vault keys
- **[Quick Reference](quickstart.md)** — command cheat sheet
