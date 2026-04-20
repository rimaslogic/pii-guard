# pii-guard

A Claude Code plugin that **blocks prompts containing PII or credentials** before they reach the model. If your prompt contains a credit card, API key, SSN, IBAN, email, or a handful of other sensitive categories, the prompt never leaves your laptop — Claude Code shows you a block message with a suggested safe rewrite.

## Design note — what this can and can't do

Claude Code's `UserPromptSubmit` hook API can **block** a prompt or **pass it through**, but it cannot silently rewrite what you typed. Versions 0.1.x of this plugin pretended to "redact" prompts, but the rewritten text was never actually substituted — the raw PII still reached the model. **v0.2.0 is honest:** every detected hit blocks the prompt. If you want a rewritten version, you copy it from the block message and resend.

If you need silent in-flight redaction, that requires a local network proxy sitting between Claude Code and `api.anthropic.com`. That's tracked as a future project, not this one.

## What it catches (v0.2.0)

| Category | Default | Examples |
|---|---|---|
| `credentials` | block | AWS keys, GitHub PATs, OpenAI/Anthropic keys, Stripe/Slack/Google API keys, JWTs, private key blocks |
| `financial` | block | Credit card numbers (Luhn-validated), IBAN (mod-97 validated) |
| `national_id` | block | US SSN, PL PESEL (checksum), PL NIP (checksum) |
| `crypto_wallet` | block | BTC, ETH addresses |
| `contact` | block | Emails, international phone numbers, IPv4 |

Checksum validation (Luhn for cards, mod-97 for IBAN, checksums for PESEL/NIP) prevents false positives on random 16-digit strings like order IDs.

## Install

```
/plugin marketplace add rimaslogic/pii-guard
/plugin install pii-guard@rimaslogic
```

Then **fully restart Claude Code** (Cmd+Q, reopen).

> ⚠️ If you already had an earlier version installed, uninstall it first:
> `/plugin uninstall pii-guard@rimaslogic`

## Usage

Once installed, every prompt is scanned. Clean prompts pass through silently; prompts with PII are blocked with a message like:

```
🛡️  PII Guard blocked your prompt before it reached the model.

Detected: financial (card)

Safe rewrite (copy, edit as needed, and resend):

    my card is [CARD_1] and my favorite word is BANANAPLUM42

To override for everything except credentials, prefix your prompt with `!pii-allow`.
To change what gets blocked, run `pii-guard policy --set <category>=allow`.
```

### CLI

```bash
CLI=~/.claude/plugins/cache/rimaslogic/pii-guard/0.2.0/skill/runtime/cli.py

python3 "$CLI" status
python3 "$CLI" test "my card is 4111 1111 1111 1111"
python3 "$CLI" policy --set contact=allow
python3 "$CLI" disable --duration 30m
python3 "$CLI" disable --category contact
python3 "$CLI" enable
```

### Inline bypass

Prefix any prompt with `!pii-allow` to skip checks for everything except credentials. Credentials are always blocked; this is by design.

```
!pii-allow send a reminder to demo@example.com
```

### Verifying it works

Turn on the transcript log, send a few prompts, then read the log:

```bash
python3 "$CLI" transcript on
# ... use Claude Code as normal, including a prompt with a test card ...
python3 "$CLI" transcript show -n 5
python3 "$CLI" transcript clear   # delete when done — log contains raw PII
python3 "$CLI" transcript off
```

Each entry records the action taken (`passthrough` / `block`), the exact input you typed, and (for blocks) what was detected and why.

## How it works

1. Plugin install wires a `UserPromptSubmit` hook via `hooks/hooks.json` using `${CLAUDE_PLUGIN_ROOT}`.
2. On every prompt, Claude Code pipes the hook payload (JSON with your prompt) to `python3 .../guard.py`.
3. `guard.py` scans the prompt with regex + checksum validators (Luhn for cards, mod-97 for IBAN, checksums for PESEL/NIP).
4. If any active category with policy `block` has a hit, the hook emits `{"decision": "block", "reason": "..."}` — Claude Code **discards the prompt** and shows the user the reason. The model never sees the prompt.
5. Otherwise the prompt passes through unchanged.

No network calls; everything runs locally.

## Uninstall

```
/plugin uninstall pii-guard@rimaslogic
```

Or if you installed via the standalone zip:

```bash
python3 <skill-dir>/installer/uninstall.py --yes --purge
```

## Development

```bash
git clone https://github.com/rimaslogic/pii-guard
cd pii-guard
scripts/dev-link.sh                  # symlink skill/ into ~/.claude/skills/pii-guard
python3 -m venv .venv && .venv/bin/pip install pytest
.venv/bin/pytest -q                  # 14 tests
scripts/build-release.sh             # build both zips into dist/
```

## Security notes

- No network calls.
- Patterns live on disk in `~/.claude/plugins/cache/rimaslogic/pii-guard/<version>/skill/runtime/patterns/` (plugin) or `~/.claude/pii-guard/patterns/` (standalone).
- Audit log at `~/.claude/pii-guard/audit.log` records counts per event (no PII content).
- Transcript log is opt-in and contains raw PII — clear and disable after auditing.

## License

[MIT](./LICENSE) — Copyright (c) 2026 Rimas Lukaszewicz.
