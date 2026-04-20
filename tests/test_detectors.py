"""
Unit tests for PII Guard detectors. Runs guard.py against a temporary
PII_GUARD_HOME so the tests never touch the user's real runtime.
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


def _fresh_home(tmp_path: pathlib.Path, policy_override: dict | None = None) -> pathlib.Path:
    home = tmp_path / "pii-guard"
    home.mkdir()
    (home / "patterns").mkdir()
    shutil.copy2(SKILL_RUNTIME / "patterns" / "builtin.json", home / "patterns" / "builtin.json")
    shutil.copy2(SKILL_RUNTIME / "patterns" / "custom.json", home / "patterns" / "custom.json")
    shutil.copy2(GUARD, home / "guard.py")
    (home / "state.json").write_text(json.dumps(
        {"enabled": True, "disabled_until": None, "disabled_categories": []}
    ))
    policy = {
        "credentials": "block",
        "financial": "redact",
        "national_id": "redact",
        "crypto_wallet": "redact",
        "contact": "warn",
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


def test_email_is_warned_not_redacted_by_default(tmp_path):
    home = _fresh_home(tmp_path)
    r = _run(home, "contact me at demo@example.com please")
    assert r.returncode == 0
    assert "demo@example.com" in r.stdout  # warn keeps the value visible
    assert "contact:1" in r.stdout


def test_valid_card_is_redacted(tmp_path):
    home = _fresh_home(tmp_path)
    r = _run(home, "my card is 4111 1111 1111 1111 expires tomorrow")
    assert r.returncode == 0
    assert "4111 1111 1111 1111" not in r.stdout
    assert "[CARD_1]" in r.stdout


def test_invalid_card_is_ignored(tmp_path):
    home = _fresh_home(tmp_path)
    r = _run(home, "order id 1234 5678 9012 3456")  # fails Luhn
    assert r.returncode == 0
    # nothing to redact, no actions triggered → passthrough (empty stdout)
    assert r.stdout.strip() == ""


def test_aws_key_is_blocked(tmp_path):
    home = _fresh_home(tmp_path)
    r = _run(home, "here is the key AKIAIOSFODNN7EXAMPLE")
    assert r.returncode == 2
    assert "blocked" in r.stderr
    assert "credentials" in r.stderr


def test_github_pat_is_blocked(tmp_path):
    home = _fresh_home(tmp_path)
    r = _run(home, "token ghp_abcdefghijklmnopqrstuvwxyz0123456789")
    assert r.returncode == 2


def test_valid_iban_is_redacted(tmp_path):
    home = _fresh_home(tmp_path)
    r = _run(home, "my iban is GB82WEST12345698765432")
    assert r.returncode == 0
    assert "GB82WEST12345698765432" not in r.stdout
    assert "[IBAN_1]" in r.stdout


def test_pesel_checksum_enforced(tmp_path):
    home = _fresh_home(tmp_path)
    # valid PESEL
    r1 = _run(home, "pesel 44051401458")
    assert "[PL_PESEL_1]" in r1.stdout
    # random 11 digits that fail checksum → ignored
    r2 = _run(home, "reference 12345678901")
    assert "[PL_PESEL_1]" not in r2.stdout


def test_inline_bypass_allows_emails_but_not_credentials(tmp_path):
    home = _fresh_home(tmp_path)
    r = _run(home, "!pii-allow contact me at demo@example.com")
    # credentials still checked; nothing blocks; email passes through
    assert r.returncode == 0
    # bypassed email stays, no contact redaction happened
    assert "demo@example.com" in r.stdout or r.stdout.strip() == ""

    r2 = _run(home, "!pii-allow key AKIAIOSFODNN7EXAMPLE")
    assert r2.returncode == 2  # credentials still blocked


def test_disabled_passthrough(tmp_path):
    home = _fresh_home(tmp_path)
    (home / "state.json").write_text(json.dumps({"enabled": False}))
    r = _run(home, "card 4111 1111 1111 1111")
    assert r.returncode == 0
    assert r.stdout.strip() == ""  # passthrough


def test_policy_redact_contact(tmp_path):
    home = _fresh_home(tmp_path, policy_override={"contact": "redact"})
    r = _run(home, "email demo@example.com")
    assert "demo@example.com" not in r.stdout
    assert "[EMAIL_1]" in r.stdout
