# pii-guard

A Claude Code skill + hook that redacts or blocks **PII and credentials** before they reach the model.

Every prompt you send goes through a local `UserPromptSubmit` hook. The hook runs 100% on your machine; nothing is uploaded. If your prompt contains an AWS key, it's blocked. If it contains a credit card, the number is replaced with `[CARD_1]`. If it contains an email, you get a warning banner.

## What it catches (v0.1.0)

| Category | Default action | Examples |
|---|---|---|
| `credentials` | **block** | AWS keys, GitHub PATs, OpenAI/Anthropic keys, Stripe/Slack/Google API keys, JWTs, private key blocks |
| `financial` | redact | Credit card numbers (Luhn-validated), IBAN (mod-97 validated) |
| `national_id` | redact | US SSN, PL PESEL (checksum), PL NIP (checksum) |
| `crypto_wallet` | redact | BTC, ETH addresses |
| `contact` | warn | emails, international phone numbers, IPv4 |

You can change any category's action (`block` / `redact` / `warn` / `allow`) via the CLI.

## Install

### Option A — Claude Code plugin (recommended)

```
/plugin marketplace add rimaslogic/pii-guard
/plugin install pii-guard@rimaslogic
```

Then `/reload` and you're done.

### Option B — Standalone zip

```bash
curl -L -o pii-guard.zip \
  https://github.com/rimaslogic/pii-guard/releases/latest/download/pii-guard-0.1.0.zip
unzip pii-guard.zip
cd pii-guard
python3 installer/install.py --yes
```

Then `/reload` in Claude Code.

> ⚠️ If you already have a different `pii-guard` installed, uninstall it first — this package uses `~/.claude/pii-guard/` as its runtime directory.

## Usage

Once installed, it just works — every prompt is filtered. The CLI is for configuration:

```bash
python3 ~/.claude/pii-guard/cli.py status
python3 ~/.claude/pii-guard/cli.py test "my card is 4111 1111 1111 1111"
python3 ~/.claude/pii-guard/cli.py policy --set contact=redact
python3 ~/.claude/pii-guard/cli.py disable --duration 30m
python3 ~/.claude/pii-guard/cli.py disable --category contact
python3 ~/.claude/pii-guard/cli.py enable
```

### Inline bypass

Prefix a single prompt with `!pii-allow` to let contact/financial/national-id through. **Credentials are always blocked** — this bypass cannot disable them.

```
!pii-allow the test email is demo@example.com — no, really
```

## How it works

1. Installer writes the hook runtime to `~/.claude/pii-guard/` and adds a `UserPromptSubmit` entry to `~/.claude/settings.json` (after backing it up with a timestamped copy).
2. On every prompt, Claude Code pipes the hook payload (JSON with the `prompt` text) to `python3 ~/.claude/pii-guard/guard.py`.
3. `guard.py` scans the prompt with regex + checksum validators (Luhn for cards, mod-97 for IBAN, checksums for PESEL/NIP) to cut false positives.
4. Depending on policy, the hook either blocks (exit 2 → Claude Code surfaces the error) or rewrites the prompt (exit 0 with a JSON stdout payload).
5. A tiny `[🛡️ PII Guard: …]` banner is appended so you can see what got hit.

## Uninstall

```bash
python3 ~/.claude/pii-guard/../pii-guard-*/installer/uninstall.py --yes --purge
```

Or, if you still have the original skill dir:

```bash
python3 <skill-dir>/installer/uninstall.py --yes --purge
```

Plugin users:

```
/plugin uninstall pii-guard
```

## Development

```bash
git clone https://github.com/rimaslogic/pii-guard
cd pii-guard
scripts/dev-link.sh                  # symlink skill/ into ~/.claude/skills/pii-guard
pip install pytest && pytest -q      # run tests
scripts/build-release.sh             # build both zips into dist/
```

## Security notes

- No network calls, ever.
- Patterns live on disk in `~/.claude/pii-guard/patterns/`; you can edit `custom.json` to add your own.
- Audit log at `~/.claude/pii-guard/audit.log` records counts per category per event. It never contains the redacted content.
- `settings.json` is backed up on every install and every uninstall with a `settings.json.bak-YYYYMMDD-HHMMSS` file. Don't delete those until you're sure.

## License

[MIT](./LICENSE) — Copyright (c) 2026 Rimas Lukaszewicz.
