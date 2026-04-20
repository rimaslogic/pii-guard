#!/usr/bin/env bash
# Symlink skill/ into ~/.claude/skills/pii-guard for local development.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="$HOME/.claude/skills/pii-guard"
mkdir -p "$HOME/.claude/skills"
if [ -e "$TARGET" ] && [ ! -L "$TARGET" ]; then
  echo "Refusing to overwrite non-symlink at $TARGET"
  exit 1
fi
rm -f "$TARGET"
ln -s "$HERE/skill" "$TARGET"
echo "Linked $TARGET → $HERE/skill"
