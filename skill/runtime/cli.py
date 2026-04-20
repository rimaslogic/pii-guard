#!/usr/bin/env python3
"""
PII Guard CLI — status, enable, disable, test, policy.

Usage:
  cli.py status
  cli.py enable
  cli.py disable [--duration 30m|2h|1d] [--category contact] [--confirm]
  cli.py test "text to scan"
  cli.py policy [--show] [--set category=action ...]
"""
from __future__ import annotations

import argparse
import io
import json
import os
import pathlib
import re
import sys
import time

ROOT = pathlib.Path(
    os.environ.get("PII_GUARD_HOME", pathlib.Path.home() / ".claude" / "pii-guard")
)
STATE_FILE = ROOT / "state.json"
POLICY_FILE = ROOT / "policy.json"
GUARD = ROOT / "guard.py"

CATEGORIES = ("credentials", "financial", "national_id", "crypto_wallet", "contact")
ACTIONS = ("block", "redact", "warn", "allow")
DEFAULT_POLICY = {
    "credentials": "block",
    "financial": "redact",
    "national_id": "redact",
    "crypto_wallet": "redact",
    "contact": "warn",
}
DEFAULT_STATE = {
    "enabled": True,
    "disabled_until": None,
    "disabled_categories": [],
}


def load(path: pathlib.Path, default: dict) -> dict:
    try:
        return json.loads(path.read_text())
    except Exception:
        return dict(default)


def save(path: pathlib.Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n")


def parse_duration(s: str) -> int:
    m = re.fullmatch(r"(\d+)\s*([mhd])", s.strip().lower())
    if not m:
        raise SystemExit(f"bad duration: {s!r} (examples: 30m, 2h, 1d)")
    n = int(m.group(1))
    unit = m.group(2)
    return n * {"m": 60, "h": 3600, "d": 86400}[unit]


def cmd_status(_: argparse.Namespace) -> None:
    st = load(STATE_FILE, DEFAULT_STATE)
    pol = {**DEFAULT_POLICY, **load(POLICY_FILE, {})}
    print("PII Guard status")
    print(f"  runtime : {ROOT}")
    print(f"  enabled : {st.get('enabled', True)}")
    until = st.get("disabled_until")
    if until:
        remaining = int(until - time.time())
        if remaining > 0:
            print(f"  temp-off: {remaining}s remaining")
    disabled_cats = st.get("disabled_categories") or []
    if disabled_cats:
        print(f"  off cats: {', '.join(disabled_cats)}")
    print("  policy  :")
    for cat in CATEGORIES:
        print(f"    {cat:<14} {pol.get(cat)}")


def cmd_enable(_: argparse.Namespace) -> None:
    st = load(STATE_FILE, DEFAULT_STATE)
    st["enabled"] = True
    st["disabled_until"] = None
    st["disabled_categories"] = []
    save(STATE_FILE, st)
    print("[pii-guard] enabled.")


def cmd_disable(args: argparse.Namespace) -> None:
    st = load(STATE_FILE, DEFAULT_STATE)
    if args.category:
        if args.category not in CATEGORIES:
            raise SystemExit(f"unknown category: {args.category}")
        if args.category == "credentials" and not args.confirm:
            raise SystemExit(
                "refusing to disable 'credentials' without --confirm "
                "(this would allow API keys / tokens to pass through)."
            )
        cats = set(st.get("disabled_categories") or [])
        cats.add(args.category)
        st["disabled_categories"] = sorted(cats)
        save(STATE_FILE, st)
        print(f"[pii-guard] category disabled: {args.category}")
        return

    if args.duration:
        secs = parse_duration(args.duration)
        st["disabled_until"] = int(time.time()) + secs
        save(STATE_FILE, st)
        print(f"[pii-guard] disabled for {args.duration} "
              f"(until {time.strftime('%H:%M', time.localtime(st['disabled_until']))}).")
        return

    st["enabled"] = False
    save(STATE_FILE, st)
    print("[pii-guard] disabled until enabled again.")


def cmd_test(args: argparse.Namespace) -> None:
    if not GUARD.exists():
        raise SystemExit(f"guard.py not found at {GUARD} — is pii-guard installed?")
    sys.path.insert(0, str(ROOT))
    import importlib.util
    spec = importlib.util.spec_from_file_location("guard", GUARD)
    guard = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(guard)  # type: ignore[union-attr]

    buf_out = io.StringIO()
    buf_err = io.StringIO()
    real_out, real_err = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = buf_out, buf_err
    try:
        guard.run(args.text)
        code = 0
    except SystemExit as e:
        code = int(e.code or 0)
    finally:
        sys.stdout, sys.stderr = real_out, real_err

    print(f"exit code: {code}")
    out = buf_out.getvalue().strip()
    err = buf_err.getvalue().strip()
    if out:
        try:
            parsed = json.loads(out)
            print("stdout   :")
            print(json.dumps(parsed, indent=2, ensure_ascii=False))
        except json.JSONDecodeError:
            print(f"stdout   : {out}")
    if err:
        print(f"stderr   : {err}")
    if not out and not err:
        print("stdout   : (empty — prompt passes through unchanged)")


def cmd_policy(args: argparse.Namespace) -> None:
    pol = {**DEFAULT_POLICY, **load(POLICY_FILE, {})}
    if args.set:
        for pair in args.set:
            if "=" not in pair:
                raise SystemExit(f"bad --set value: {pair!r} (expected category=action)")
            cat, action = pair.split("=", 1)
            cat, action = cat.strip(), action.strip()
            if cat not in CATEGORIES:
                raise SystemExit(f"unknown category: {cat}")
            if action not in ACTIONS:
                raise SystemExit(f"unknown action: {action} (one of {', '.join(ACTIONS)})")
            pol[cat] = action
        save(POLICY_FILE, pol)
        print("[pii-guard] policy updated.")
    for cat in CATEGORIES:
        print(f"  {cat:<14} {pol.get(cat)}")


def cmd_transcript(args: argparse.Namespace) -> None:
    """Enable/disable/view the transcript log (off by default).

    When on, guard.py writes each hook invocation (input + output) to
    ~/.claude/pii-guard/transcript.log. Useful to verify that what reaches
    the model matches what you expect. WARNING: the log contains the
    original UNREDACTED prompt.
    """
    st = load(STATE_FILE, DEFAULT_STATE)
    transcript_log = ROOT / "transcript.log"

    if args.action == "on":
        st["transcript"] = True
        save(STATE_FILE, st)
        print("[pii-guard] transcript ON.")
        print(f"  log: {transcript_log}")
        print("  ⚠️  this file contains your ORIGINAL prompts including PII. "
              "Delete when done auditing.")
        return
    if args.action == "off":
        st["transcript"] = False
        save(STATE_FILE, st)
        print("[pii-guard] transcript OFF.")
        return
    if args.action == "clear":
        if transcript_log.exists():
            transcript_log.unlink()
            print(f"[pii-guard] cleared: {transcript_log}")
        else:
            print("[pii-guard] nothing to clear.")
        return
    if args.action == "show":
        if not transcript_log.exists():
            print("[pii-guard] no transcript yet.")
            return
        n = args.lines or 1
        lines = transcript_log.read_text().splitlines()[-n:]
        for line in lines:
            try:
                evt = json.loads(line)
                print(json.dumps(evt, indent=2, ensure_ascii=False))
                print("-" * 60)
            except json.JSONDecodeError:
                print(line)
        return


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pii-guard")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("status").set_defaults(func=cmd_status)
    sub.add_parser("enable").set_defaults(func=cmd_enable)

    d = sub.add_parser("disable")
    d.add_argument("--duration", help="e.g. 30m, 2h, 1d")
    d.add_argument("--category", choices=CATEGORIES)
    d.add_argument("--confirm", action="store_true", help="required to disable credentials")
    d.set_defaults(func=cmd_disable)

    t = sub.add_parser("test")
    t.add_argument("text")
    t.set_defaults(func=cmd_test)

    po = sub.add_parser("policy")
    po.add_argument("--set", action="append", default=[], metavar="CAT=ACTION")
    po.add_argument("--show", action="store_true")
    po.set_defaults(func=cmd_policy)

    tr = sub.add_parser(
        "transcript",
        help="enable/disable/view the on-disk transcript of what the hook sends",
    )
    tr.add_argument("action", choices=["on", "off", "show", "clear"])
    tr.add_argument("--lines", "-n", type=int, default=1,
                    help="for 'show': how many recent entries to print")
    tr.set_defaults(func=cmd_transcript)

    return p


def main() -> None:
    args = build_parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
