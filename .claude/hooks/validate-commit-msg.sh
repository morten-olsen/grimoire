#!/usr/bin/env bash
# Validates that git commit messages follow conventional commit format.
# Called as a PreToolUse hook on Bash commands matching "git commit".
# Reads the tool input JSON from stdin.
set -euo pipefail

INPUT=$(cat)
COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // empty')

# Only validate git commit commands
if ! echo "$COMMAND" | grep -qE 'git commit'; then
  exit 0
fi

# Extract the commit message from -m flag or heredoc
# Check for conventional commit pattern in the command
# Pattern: type(scope): description  OR  type: description  OR  type(scope)!: description
PATTERN='^(feat|fix|refactor|docs|test|chore|security|perf|style|ci|build)(\([a-z0-9_-]+\))?\!?: .+'

# Try to extract message from heredoc (our standard format)
MSG=$(echo "$COMMAND" | grep -oP "(?<=<<'EOF'\n|<<'EOF'\s)[\s\S]*" | head -1 || true)

# Try -m flag
if [ -z "$MSG" ]; then
  MSG=$(echo "$COMMAND" | grep -oP '(?<=-m ")[^"]*' | head -1 || true)
fi

# Try heredoc more broadly - look for the first non-empty line after EOF marker
if [ -z "$MSG" ]; then
  MSG=$(echo "$COMMAND" | grep -oP '(?<=cat <<..EOF...\n)[^\n]+' | head -1 || true)
fi

# If we can't extract the message, let it through (don't block on parsing edge cases)
if [ -z "$MSG" ]; then
  exit 0
fi

# Trim leading whitespace
MSG=$(echo "$MSG" | sed 's/^[[:space:]]*//')

if echo "$MSG" | grep -qP "$PATTERN"; then
  exit 0
else
  echo '{"hookSpecificOutput":{"decision":"block","reason":"Commit message must follow conventional format: type(scope): description\nValid types: feat, fix, refactor, docs, test, chore, security, perf, style, ci, build\nValid scopes: cli, service, sdk, protocol, prompt, common, ssh, auth, sync, ipc\nExample: feat(ssh): add RSA key support"}}'
  exit 2
fi
