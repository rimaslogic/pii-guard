# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
