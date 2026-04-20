#!/usr/bin/env python3
"""
PII Guard — UserPromptSubmit hook filter.

Reads Claude Code hook JSON on stdin, applies detectors against the `prompt`
field, and either:
  - exits 0 with a modified prompt JSON on stdout (redact / warn / pass)
  - exits 2 with a rejection message on stderr (block)

See: https://docs.claude.com/en/docs/claude-code/hooks
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import sys
import time
from datetime import datetime, timezone

ROOT = pathlib.Path(
    os.environ.get("PII_GUARD_HOME", pathlib.Path.home() / ".claude" / "pii-guard")
)
SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
STATE_FILE = ROOT / "state.json"
POLICY_FILE = ROOT / "policy.json"
PATTERNS_DIR = ROOT / "patterns"
FALLBACK_PATTERNS_DIR = SCRIPT_DIR / "patterns"
AUDIT_LOG = ROOT / "audit.log"

INLINE_BYPASS = "!pii-allow"
CATEGORIES = ("credentials", "financial", "national_id", "crypto_wallet", "contact")
DEFAULT_POLICY = {
    "credentials": "block",
    "financial": "redact",
    "national_id": "redact",
    "crypto_wallet": "redact",
    "contact": "warn",
}

# ---------- checksum validators ----------

def luhn_ok(s: str) -> bool:
    d = [int(c) for c in re.sub(r"\D", "", s)]
    if not 13 <= len(d) <= 19:
        return False
    total, alt = 0, False
    for x in reversed(d):
        if alt:
            x *= 2
            if x > 9:
                x -= 9
        total += x
        alt = not alt
    return total % 10 == 0


def iban_ok(s: str) -> bool:
    s = re.sub(r"\s+", "", s).upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{11,30}", s):
        return False
    rearranged = s[4:] + s[:4]
    numeric = "".join(str(ord(c) - 55) if c.isalpha() else c for c in rearranged)
    try:
        return int(numeric) % 97 == 1
    except ValueError:
        return False


def pesel_ok(s: str) -> bool:
    if not re.fullmatch(r"\d{11}", s):
        return False
    weights = [1, 3, 7, 9, 1, 3, 7, 9, 1, 3]
    total = sum(int(s[i]) * weights[i] for i in range(10))
    check = (10 - (total % 10)) % 10
    return check == int(s[10])


def nip_ok(s: str) -> bool:
    if not re.fullmatch(r"\d{10}", s):
        return False
    weights = [6, 5, 7, 2, 3, 4, 5, 6, 7]
    total = sum(int(s[i]) * weights[i] for i in range(9))
    check = total % 11
    return check < 10 and check == int(s[9])


VALIDATORS = {
    "luhn": luhn_ok,
    "iban": iban_ok,
    "pesel": pesel_ok,
    "nip": nip_ok,
}

# ---------- state & policy ----------

def load_json(path: pathlib.Path, default):
    try:
        return json.loads(path.read_text())
    except Exception:
        return default


def state() -> dict:
    return load_json(
        STATE_FILE,
        {"enabled": True, "disabled_until": None, "disabled_categories": []},
    )


def policy() -> dict:
    p = load_json(POLICY_FILE, {})
    return {**DEFAULT_POLICY, **p}


def active_categories() -> set:
    st = state()
    if not st.get("enabled", True):
        return set()
    until = st.get("disabled_until")
    if until and time.time() < until:
        return set()
    disabled = set(st.get("disabled_categories") or [])
    return set(CATEGORIES) - disabled


def load_patterns() -> dict:
    """Load patterns from PATTERNS_DIR with fallback to bundled patterns
    (shipped next to guard.py). Lets the hook work even before the installer
    has copied anything to ~/.claude/pii-guard/ (e.g. when invoked as a plugin)."""
    merged = {cat: [] for cat in CATEGORIES}
    for fname in ("builtin.json", "custom.json"):
        path = PATTERNS_DIR / fname
        if not path.exists():
            path = FALLBACK_PATTERNS_DIR / fname
        data = load_json(path, {})
        for cat, items in data.items():
            if cat in merged and isinstance(items, list):
                merged[cat].extend(items)
    return merged

# ---------- detection ----------

def find_matches(text: str) -> dict:
    """Return {category: [(match_text, kind), ...]}."""
    found: dict = {cat: [] for cat in CATEGORIES}
    patterns = load_patterns()
    for cat, items in patterns.items():
        for item in items:
            pat = item.get("pattern")
            kind = item.get("kind", "unknown")
            validator = item.get("validator")
            if not pat:
                continue
            try:
                for m in re.finditer(pat, text):
                    hit = m.group(0)
                    if validator and not VALIDATORS.get(validator, lambda _: True)(hit):
                        continue
                    found[cat].append((hit, kind))
            except re.error:
                continue
    return found


def apply_redactions(text: str, matches: dict, policy_map: dict, active: set) -> tuple[str, dict]:
    """Return (new_text, actions) where actions is {category: action_applied}."""
    actions: dict = {}
    # highest severity categories first
    order = ["credentials", "financial", "national_id", "crypto_wallet", "contact"]
    for cat in order:
        if cat not in active:
            continue
        hits = matches.get(cat, [])
        if not hits:
            continue
        action = policy_map.get(cat, "warn")
        actions[cat] = action
        if action in ("redact", "block"):
            counter: dict = {}
            for hit, kind in hits:
                counter.setdefault(kind, 0)
                counter[kind] += 1
                token = f"[{kind.upper()}_{counter[kind]}]"
                text = text.replace(hit, token)
    return text, actions


def audit(event: dict) -> None:
    try:
        AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        event["ts"] = datetime.now(timezone.utc).isoformat()
        with AUDIT_LOG.open("a") as fh:
            fh.write(json.dumps(event, ensure_ascii=False) + "\n")
    except Exception:
        pass

# ---------- main ----------

def passthrough() -> None:
    """Exit 0 with no output => Claude Code uses the prompt unchanged."""
    sys.exit(0)


def emit_prompt(new_prompt: str) -> None:
    json.dump({"prompt": new_prompt}, sys.stdout, ensure_ascii=False)
    sys.exit(0)


def block(reason: str) -> None:
    sys.stderr.write(f"[pii-guard] blocked: {reason}\n")
    sys.exit(2)


def run(input_text: str) -> None:
    active = active_categories()
    if not active:
        passthrough()

    prompt = input_text
    bypassed = False
    if prompt.lstrip().startswith(INLINE_BYPASS):
        bypassed = True
        prompt = prompt.lstrip()[len(INLINE_BYPASS):].lstrip()

    matches = find_matches(prompt)

    # credentials are ALWAYS enforced, even with bypass
    if bypassed:
        active = {"credentials"}

    pol = policy()
    actions_by_cat: dict = {}

    # Block if any active category with 'block' policy has hits
    for cat in active:
        if pol.get(cat) == "block" and matches.get(cat):
            kinds = sorted({k for _, k in matches[cat]})
            audit({"action": "block", "category": cat, "kinds": kinds})
            block(f"{cat} detected ({', '.join(kinds)}) — remove before resending.")

    new_prompt, actions = apply_redactions(prompt, matches, pol, active)

    summary_bits = []
    for cat in CATEGORIES:
        if cat in actions:
            n = len(matches.get(cat, []))
            summary_bits.append(f"{cat}:{n} ({actions[cat]})")

    if not summary_bits and not bypassed:
        passthrough()

    audit({
        "action": "modify",
        "bypassed": bypassed,
        "counts": {c: len(matches.get(c, [])) for c in CATEGORIES if matches.get(c)},
        "actions": actions,
    })

    banner = f"\n\n[🛡️ PII Guard: {', '.join(summary_bits) if summary_bits else 'passthrough'}]"
    emit_prompt(new_prompt + banner)


def main() -> None:
    raw = sys.stdin.read()
    if not raw:
        passthrough()
    # Hook input is JSON; fall back to raw text if parsing fails (test mode).
    try:
        data = json.loads(raw)
        prompt = data.get("prompt", "")
    except json.JSONDecodeError:
        prompt = raw
    if not prompt:
        passthrough()
    run(prompt)


if __name__ == "__main__":
    main()
