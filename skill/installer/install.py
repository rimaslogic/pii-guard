#!/usr/bin/env python3
"""
PII Guard installer.

- Copies runtime + patterns into $HOME/.claude/pii-guard/
- Writes default state.json and policy.json
- Patches $HOME/.claude/settings.json to register the UserPromptSubmit hook,
  creating a timestamped backup of the existing settings file first
- Verifies the hook works end-to-end before exiting
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import shutil
import subprocess
import sys
import time

HOME = pathlib.Path.home()
SETTINGS = HOME / ".claude" / "settings.json"
RUNTIME = HOME / ".claude" / "pii-guard"
SKILL_DIR = pathlib.Path(__file__).resolve().parent.parent
SOURCE_RUNTIME = SKILL_DIR / "runtime"

# Quoted so paths containing spaces (e.g. macOS "Active Directory" homes)
# still execute correctly when Claude Code passes the command to a shell.
HOOK_COMMAND = f'python3 "{RUNTIME / "guard.py"}"'
HOOK_EVENT = "UserPromptSubmit"

DEFAULT_POLICY = {
    "credentials": "block",
    "financial": "block",
    "national_id": "block",
    "crypto_wallet": "block",
    "contact": "block",
}
DEFAULT_STATE = {
    "enabled": True,
    "disabled_until": None,
    "disabled_categories": [],
}


def log(msg: str) -> None:
    print(f"[pii-guard] {msg}")


def copy_runtime() -> None:
    RUNTIME.mkdir(parents=True, exist_ok=True)
    for item in SOURCE_RUNTIME.iterdir():
        dest = RUNTIME / item.name
        if item.is_dir():
            if dest.exists():
                shutil.rmtree(dest)
            shutil.copytree(item, dest)
        else:
            shutil.copy2(item, dest)
    log(f"runtime → {RUNTIME}")


def write_defaults() -> None:
    state_file = RUNTIME / "state.json"
    policy_file = RUNTIME / "policy.json"
    if not state_file.exists():
        state_file.write_text(json.dumps(DEFAULT_STATE, indent=2) + "\n")
    if not policy_file.exists():
        policy_file.write_text(json.dumps(DEFAULT_POLICY, indent=2) + "\n")
    log("state.json + policy.json written (enabled by default)")


def load_settings() -> dict:
    if not SETTINGS.exists():
        return {}
    try:
        return json.loads(SETTINGS.read_text())
    except json.JSONDecodeError:
        raise SystemExit(f"[pii-guard] settings.json is not valid JSON: {SETTINGS}")


def backup_settings() -> pathlib.Path | None:
    if not SETTINGS.exists():
        return None
    ts = time.strftime("%Y%m%d-%H%M%S")
    backup = SETTINGS.with_suffix(f".json.bak-{ts}")
    shutil.copy2(SETTINGS, backup)
    log(f"backup: {backup.name}")
    return backup


def patch_settings() -> None:
    settings = load_settings()
    hooks = settings.setdefault("hooks", {})
    ups = hooks.setdefault(HOOK_EVENT, [])

    for entry in ups:
        for h in entry.get("hooks", []):
            if h.get("command") == HOOK_COMMAND:
                log("hook already registered; skipping")
                return

    ups.append({"hooks": [{"type": "command", "command": HOOK_COMMAND}]})
    SETTINGS.parent.mkdir(parents=True, exist_ok=True)
    SETTINGS.write_text(json.dumps(settings, indent=2) + "\n")
    log("hook registered in settings.json")


def verify() -> bool:
    guard = RUNTIME / "guard.py"
    if not guard.exists():
        log(f"verify failed: {guard} missing")
        return False
    test_input = {"prompt": "my card is 4111 1111 1111 1111"}
    try:
        res = subprocess.run(
            [sys.executable, str(guard)],
            input=json.dumps(test_input),
            capture_output=True,
            text=True,
            timeout=10,
        )
    except Exception as e:
        log(f"verify failed to run guard: {e}")
        return False
    # Expect a block decision in stdout JSON, exit 0.
    if res.returncode != 0:
        log(f"verify failed: guard exited {res.returncode} (expected 0 with block JSON)")
        return False
    try:
        parsed = json.loads(res.stdout)
    except Exception:
        log("verify failed: guard stdout was not JSON")
        return False
    if parsed.get("decision") != "block":
        log(f"verify failed: expected decision=block, got {parsed!r}")
        return False
    log("verify ok: sample card produced a block decision")
    return True


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--yes", action="store_true", help="non-interactive")
    args = ap.parse_args()

    log("detected host: claude-code")
    copy_runtime()
    write_defaults()
    backup_settings()
    patch_settings()

    if verify():
        log("✅ installed and enabled.")
        log("restart Claude Code (or /reload) for the hook to take effect.")
    else:
        log("⚠️  installed, but post-install verification failed. Check runtime files.")
        sys.exit(1)


if __name__ == "__main__":
    main()
