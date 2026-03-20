#!/usr/bin/env bash
# Runs cargo check after Rust file edits to catch compilation errors early.
# Called as a PostToolUse hook on Edit|Write for .rs files.
set -euo pipefail

INPUT=$(cat)
FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // empty')

# Only check Rust files
if [[ "$FILE_PATH" != *.rs ]]; then
  exit 0
fi

# Only check files in our workspace
if [[ "$FILE_PATH" != */crates/* ]]; then
  exit 0
fi

cd "$CLAUDE_PROJECT_DIR"

# Run cargo check (much faster than clippy, good for edit-time feedback)
if ! cargo check --workspace --message-format=short 2>&1 | tail -20; then
  echo "Compilation errors detected after editing $FILE_PATH" >&2
  # Don't block (exit 0) — just surface the error for context
fi

exit 0
