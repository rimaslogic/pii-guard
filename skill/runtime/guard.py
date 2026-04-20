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
TRANSCRIPT_LOG = ROOT / "transcript.log"

INLINE_BYPASS = "!pii-allow"
CATEGORIES = ("credentials", "financial", "national_id", "crypto_wallet", "contact")
DEFAULT_POLICY = {
    "credentials": "block",
    "financial": "block",
    "national_id": "block",
    "crypto_wallet": "block",
    "contact": "block",
}
# Only 'block' and 'allow' are honest actions. Claude Code's UserPromptSubmit
# hook cannot rewrite the user's text — it can only block it or pass through.
# The legacy 'redact' / 'warn' actions were misleading and are now treated as
# aliases for 'block' (with a suggested safe rewrite shown in the block reason).
LEGACY_ACTION_MAP = {"redact": "block", "warn": "block"}

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
    merged = {**DEFAULT_POLICY, **p}
    # Map legacy actions to 'block' so old policy files still behave safely.
    return {k: LEGACY_ACTION_MAP.get(v, v) for k, v in merged.items()}


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


def audit(event: dict) -> None:
    try:
        AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        event["ts"] = datetime.now(timezone.utc).isoformat()
        with AUDIT_LOG.open("a") as fh:
            fh.write(json.dumps(event, ensure_ascii=False) + "\n")
    except Exception:
        pass


def transcript(event: dict) -> None:
    """Opt-in: record the exact input and output bytes that crossed the hook.
    Enabled by setting state.transcript = true (via `cli.py transcript on`).
    WARNING: the transcript file contains the ORIGINAL unredacted prompt.
    """
    if not state().get("transcript"):
        return
    try:
        TRANSCRIPT_LOG.parent.mkdir(parents=True, exist_ok=True)
        event["ts"] = datetime.now(timezone.utc).isoformat()
        with TRANSCRIPT_LOG.open("a") as fh:
            fh.write(json.dumps(event, ensure_ascii=False) + "\n")
    except Exception:
        pass

# ---------- main ----------

def passthrough(input_text: str, reason: str) -> None:
    """Exit 0 with no output => Claude Code uses the prompt unchanged."""
    transcript({"action": "passthrough", "reason": reason,
                "input": input_text, "output": input_text})
    sys.exit(0)


def emit_block(reason: str) -> None:
    """Emit the documented block JSON. Claude Code shows `reason` to the user
    and discards the original prompt — it does NOT reach the model."""
    json.dump({"decision": "block", "reason": reason},
              sys.stdout, ensure_ascii=False)
    sys.exit(0)


def build_suggested_rewrite(prompt: str, matches: dict, active: set) -> str:
    """Produce a PII-free version of the prompt the user can copy and resend.
    This string is shown to the USER, not sent to the model."""
    # Replace every hit in every active category with a labelled token.
    out = prompt
    counters: dict = {}
    for cat in ("credentials", "financial", "national_id", "crypto_wallet", "contact"):
        if cat not in active:
            continue
        for hit, kind in matches.get(cat, []):
            counters.setdefault(kind, 0)
            counters[kind] += 1
            out = out.replace(hit, f"[{kind.upper()}_{counters[kind]}]")
    return out


def run(input_text: str) -> None:
    active = active_categories()
    if not active:
        passthrough(input_text, "disabled")
        return

    prompt = input_text
    bypassed = False
    if prompt.lstrip().startswith(INLINE_BYPASS):
        bypassed = True
        prompt = prompt.lstrip()[len(INLINE_BYPASS):].lstrip()

    matches = find_matches(prompt)

    # Inline bypass: credentials are ALWAYS enforced, other categories skipped.
    if bypassed:
        active = {"credentials"} & active

    pol = policy()

    # Any active category with action=block that has hits?
    blocked_hits: dict = {}
    for cat in active:
        if pol.get(cat) == "block" and matches.get(cat):
            blocked_hits[cat] = matches[cat]

    if not blocked_hits:
        # No PII in blocking categories — let the prompt through untouched.
        passthrough(input_text, "no-block-matches")
        return

    # Build user-facing block message with a safe rewrite suggestion.
    summary = []
    for cat, hits in blocked_hits.items():
        kinds = sorted({k for _, k in hits})
        summary.append(f"{cat} ({', '.join(kinds)})")

    # Rewrite suggestion covers ALL matches (not only the blocking ones) so the
    # user can paste something clean even if they later loosen the policy.
    suggested = build_suggested_rewrite(prompt, matches, set(CATEGORIES))

    reason = (
        "🛡️  PII Guard blocked your prompt before it reached the model.\n\n"
        f"Detected: {'; '.join(summary)}\n\n"
        "Safe rewrite (copy, edit as needed, and resend):\n"
        f"\n{suggested}\n\n"
        "To override for everything except credentials, prefix your prompt with `!pii-allow`.\n"
        "To change what gets blocked, run `pii-guard policy --set <category>=allow`."
    )

    audit({"action": "block", "bypassed": bypassed,
           "categories": sorted(blocked_hits.keys())})
    transcript({"action": "block", "input": input_text, "output": None,
                "bypassed": bypassed, "reason": reason,
                "categories": sorted(blocked_hits.keys())})
    emit_block(reason)


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
