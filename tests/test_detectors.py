"""
Unit tests for PII Guard. v0.2.0 contract:
- guard.py either passes through (exit 0, empty stdout) or blocks
  (exit 0, stdout JSON {"decision": "block", "reason": "..."}).
- Exit 2 is no longer used; 'redact' / 'warn' policies no longer exist.
"""
from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
SKILL_RUNTIME = ROOT / "skill" / "runtime"
GUARD = SKILL_RUNTIME / "guard.py"


def _fresh_home(tmp_path: pathlib.Path, policy_override: dict | None = None,
                state_override: dict | None = None) -> pathlib.Path:
    home = tmp_path / "pii-guard"
    home.mkdir()
    (home / "patterns").mkdir()
    shutil.copy2(SKILL_RUNTIME / "patterns" / "builtin.json", home / "patterns" / "builtin.json")
    shutil.copy2(SKILL_RUNTIME / "patterns" / "custom.json", home / "patterns" / "custom.json")
    shutil.copy2(GUARD, home / "guard.py")
    state = {"enabled": True, "disabled_until": None, "disabled_categories": []}
    if state_override:
        state.update(state_override)
    (home / "state.json").write_text(json.dumps(state))
    policy = {
        "credentials": "block",
        "financial": "block",
        "national_id": "block",
        "crypto_wallet": "block",
        "contact": "block",
    }
    if policy_override:
        policy.update(policy_override)
    (home / "policy.json").write_text(json.dumps(policy))
    return home


def _run(home: pathlib.Path, prompt: str) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["PII_GUARD_HOME"] = str(home)
    return subprocess.run(
        [sys.executable, str(home / "guard.py")],
        input=json.dumps({"prompt": prompt}),
        capture_output=True,
        text=True,
        env=env,
        timeout=10,
    )


def _decision(proc: subprocess.CompletedProcess) -> dict | None:
    """Parse guard.py's block-decision JSON, or return None if passthrough."""
    if not proc.stdout.strip():
        return None
    return json.loads(proc.stdout)


# -------- passthrough cases --------

def test_clean_prompt_passes_through(tmp_path):
    home = _fresh_home(tmp_path)
    r = _run(home, "what's the weather today?")
    assert r.returncode == 0
    assert r.stdout.strip() == ""  # nothing emitted = prompt unchanged


def test_disabled_passes_through_even_with_pii(tmp_path):
    home = _fresh_home(tmp_path, state_override={"enabled": False})
    r = _run(home, "card 4111 1111 1111 1111")
    assert r.returncode == 0
    assert r.stdout.strip() == ""


def test_category_allow_lets_it_through(tmp_path):
    home = _fresh_home(tmp_path, policy_override={"contact": "allow"})
    r = _run(home, "email me at demo@example.com")
    assert r.returncode == 0
    assert r.stdout.strip() == ""


# -------- block cases --------

def test_valid_card_is_blocked(tmp_path):
    home = _fresh_home(tmp_path)
    r = _run(home, "my card is 4111 1111 1111 1111 and something else")
    d = _decision(r)
    assert d and d["decision"] == "block"
    # Reason contains detected category and a safe rewrite suggestion.
    assert "financial" in d["reason"]
    assert "[CARD_1]" in d["reason"]
    # Reason goes to the USER, so the original digits MAY appear in it for
    # diagnostic purposes — but NOT in the separate "output" path to the model.
    # (The block decision itself replaces the prompt; model gets nothing.)


def test_invalid_card_is_not_blocked(tmp_path):
    home = _fresh_home(tmp_path)
    r = _run(home, "order id 1234 5678 9012 3456")  # fails Luhn
    assert _decision(r) is None  # passthrough


def test_aws_key_is_blocked(tmp_path):
    home = _fresh_home(tmp_path)
    r = _run(home, "here is the key AKIAIOSFODNN7EXAMPLE")
    d = _decision(r)
    assert d and d["decision"] == "block"
    assert "credentials" in d["reason"]


def test_email_is_blocked_by_default(tmp_path):
    home = _fresh_home(tmp_path)
    r = _run(home, "email me at demo@example.com")
    d = _decision(r)
    assert d and d["decision"] == "block"
    assert "contact" in d["reason"]


def test_valid_iban_is_blocked(tmp_path):
    home = _fresh_home(tmp_path)
    r = _run(home, "my iban is GB82WEST12345698765432")
    d = _decision(r)
    assert d and d["decision"] == "block"


def test_pesel_checksum_enforced(tmp_path):
    home = _fresh_home(tmp_path)
    r1 = _run(home, "pesel 44051401458")                  # valid
    assert _decision(r1)["decision"] == "block"
    r2 = _run(home, "reference 12345678901")              # invalid checksum
    assert _decision(r2) is None


# -------- inline bypass --------

def test_bypass_lets_contact_through(tmp_path):
    home = _fresh_home(tmp_path)
    r = _run(home, "!pii-allow email me at demo@example.com")
    assert _decision(r) is None  # bypass → passthrough for non-credentials


def test_bypass_still_blocks_credentials(tmp_path):
    home = _fresh_home(tmp_path)
    r = _run(home, "!pii-allow key AKIAIOSFODNN7EXAMPLE")
    d = _decision(r)
    assert d and d["decision"] == "block"


# -------- transcript --------

def test_transcript_off_by_default(tmp_path):
    home = _fresh_home(tmp_path)
    _run(home, "card 4111 1111 1111 1111")
    assert not (home / "transcript.log").exists()


def test_transcript_on_captures_block(tmp_path):
    home = _fresh_home(tmp_path, state_override={"transcript": True})
    _run(home, "card 4111 1111 1111 1111")
    lines = (home / "transcript.log").read_text().strip().splitlines()
    assert len(lines) == 1
    evt = json.loads(lines[0])
    assert evt["action"] == "block"
    assert "4111 1111 1111 1111" in evt["input"]
    assert evt["output"] is None  # nothing was sent to the model


# -------- legacy policy values map to block --------

def test_legacy_redact_policy_still_blocks(tmp_path):
    home = _fresh_home(tmp_path, policy_override={"financial": "redact"})
    r = _run(home, "card 4111 1111 1111 1111")
    d = _decision(r)
    assert d and d["decision"] == "block"


# -------- modern credential shapes --------

def test_openai_project_key_blocked(tmp_path):
    home = _fresh_home(tmp_path)
    # Modern OpenAI project key shape: sk-proj-<alnum/underscore/dash>+
    r = _run(home, "export OPENAI_API_KEY=sk-proj-AbCd_1234-EfGh-IjKl-MnOp-QrSt-UvWxYz0987654321")
    d = _decision(r)
    assert d and d["decision"] == "block"
    assert "credentials" in d["reason"]


def test_openai_service_account_key_blocked(tmp_path):
    home = _fresh_home(tmp_path)
    r = _run(home, "key=sk-svcacct-ABCDEF1234567890abcdefGHIJKLMNOP_-XYZ123")
    d = _decision(r)
    assert d and d["decision"] == "block"


def test_encrypted_private_key_header_blocked(tmp_path):
    home = _fresh_home(tmp_path)
    r = _run(home, "here it is:\n-----BEGIN ENCRYPTED PRIVATE KEY-----\nblah")
    d = _decision(r)
    assert d and d["decision"] == "block"


# -------- log file permissions --------

def test_logs_are_mode_0600(tmp_path):
    home = _fresh_home(tmp_path, state_override={"transcript": True})
    _run(home, "card 4111 1111 1111 1111")
    import stat
    for name in ("audit.log", "transcript.log"):
        p = home / name
        assert p.exists(), name
        mode = stat.S_IMODE(p.stat().st_mode)
        assert mode == 0o600, f"{name} mode={oct(mode)}"
