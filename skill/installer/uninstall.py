#!/usr/bin/env python3
"""
PII Guard uninstaller.

- Removes the UserPromptSubmit hook entry from settings.json (backup first)
- With --purge, also deletes ~/.claude/pii-guard/
"""
from __future__ import annotations

import argparse
import json
import pathlib
import shutil
import sys
import time

HOME = pathlib.Path.home()
SETTINGS = HOME / ".claude" / "settings.json"
RUNTIME = HOME / ".claude" / "pii-guard"
HOOK_COMMAND_SUBSTR = "pii-guard/guard.py"
HOOK_EVENT = "UserPromptSubmit"


def log(msg: str) -> None:
    print(f"[pii-guard] {msg}")


def strip_hook() -> bool:
    if not SETTINGS.exists():
        log("no settings.json — nothing to strip")
        return False
    try:
        settings = json.loads(SETTINGS.read_text())
    except json.JSONDecodeError:
        log(f"settings.json invalid JSON — leaving untouched: {SETTINGS}")
        return False

    hooks = settings.get("hooks", {})
    ups = hooks.get(HOOK_EVENT, [])
    new_ups = []
    removed = 0
    for entry in ups:
        remaining = [
            h for h in entry.get("hooks", [])
            if HOOK_COMMAND_SUBSTR not in h.get("command", "")
        ]
        if not remaining:
            removed += len(entry.get("hooks", []))
            continue
        removed += len(entry.get("hooks", [])) - len(remaining)
        entry["hooks"] = remaining
        new_ups.append(entry)

    if removed == 0:
        log("no pii-guard hook entries in settings.json")
        return False

    # backup then write
    ts = time.strftime("%Y%m%d-%H%M%S")
    backup = SETTINGS.with_suffix(f".json.bak-{ts}")
    shutil.copy2(SETTINGS, backup)
    log(f"backup: {backup.name}")

    if new_ups:
        hooks[HOOK_EVENT] = new_ups
    else:
        hooks.pop(HOOK_EVENT, None)
    if not hooks:
        settings.pop("hooks", None)
    SETTINGS.write_text(json.dumps(settings, indent=2) + "\n")
    log(f"removed {removed} hook entr{'y' if removed == 1 else 'ies'}")
    return True


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--yes", action="store_true")
    ap.add_argument(
        "--purge",
        action="store_true",
        help="also delete ~/.claude/pii-guard/ runtime directory",
    )
    args = ap.parse_args()

    if not args.yes:
        resp = input("Remove pii-guard hook from settings.json? [y/N] ").strip().lower()
        if resp != "y":
            log("aborted.")
            sys.exit(0)

    strip_hook()

    if args.purge:
        if RUNTIME.exists():
            shutil.rmtree(RUNTIME)
            log(f"purged runtime: {RUNTIME}")
        else:
            log("runtime dir already gone")

    log("✅ uninstalled. /reload Claude Code so the hook stops firing.")


if __name__ == "__main__":
    main()
