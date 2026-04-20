# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-04-20

### Changed — BREAKING
- **All detected PII now BLOCKS the prompt.** Previously, `redact` and `warn`
  policies pretended to rewrite the prompt — but Claude Code's
  `UserPromptSubmit` hook API cannot modify prompt text in flight. It can
  only block or pass through. Using `redact` therefore silently let the raw
  PII reach the model, with a misleading banner suggesting otherwise.
- New default policy: every category is `block`. The actions `redact` and
  `warn` still parse for backwards compatibility but are mapped to `block`
  (with a notice printed by the CLI).
- When a prompt is blocked, the user sees a clear reason containing a safe
  rewrite suggestion (with PII tokens like `[CARD_1]`) they can copy, edit,
  and resend. The original prompt never reaches the model.
- Block is now emitted via the documented `{"decision": "block", "reason":
  "..."}` JSON + exit 0 contract (previously we used exit 2 + stderr, which
  still worked but is less clean).

### Security
- Closes a correctness gap: the tool's previous "redact" behaviour was
  ineffective. Users should upgrade to v0.2.0 immediately. If you relied on
  `redact` to silently sanitize prompts, you will now see **block** decisions
  instead — your PII never left the machine; nothing leaked that wasn't
  already leaking in v0.1.x.

## [0.1.2] - 2026-04-20

### Added
- **Opt-in transcript log** — proves byte-for-byte what the hook sends to
  the model. Enable with `cli.py transcript on`; writes each invocation
  (input + output) to `~/.claude/pii-guard/transcript.log`. Off by default
  because the file contains the original unredacted prompts.
- CLI: `transcript on | off | show [-n N] | clear`.
- Tests: transcript off by default; when on, captures raw input and redacted
  output for a card prompt.

## [0.1.1] - 2026-04-20

### Fixed
- Plugin install now registers the `UserPromptSubmit` hook automatically via
  `hooks/hooks.json` using `${CLAUDE_PLUGIN_ROOT}`. Previously the plugin
  shipped the skill but not the hook, so prompts passed through unfiltered.
- `guard.py` now falls back to bundled `patterns/` next to itself when
  `~/.claude/pii-guard/patterns/` doesn't exist yet — makes the plugin work
  end-to-end without a separate installer run.

## [0.1.0] - 2026-04-20

### Added
- Initial release.
- `UserPromptSubmit` hook that redacts or blocks PII before it reaches the model.
- Detectors: credentials (AWS, GitHub PAT, OpenAI, Anthropic, Stripe, Slack, JWT, private keys),
  financial (card numbers with Luhn, IBAN with mod-97), contact (email, phone, IPv4),
  national IDs (US SSN, PL PESEL with checksum, PL NIP), crypto wallets (BTC, ETH).
- Per-category policy: `block` / `redact` / `warn` / `allow`.
- CLI: `status`, `enable`, `disable`, `test`, `policy`.
- Inline bypass prefix `!pii-allow` (credentials always blocked).
- Installer with timestamped `settings.json` backup + post-install verification.
- Two distribution formats: standalone zip and Claude Code plugin.
