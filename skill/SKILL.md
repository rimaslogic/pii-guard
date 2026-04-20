---
name: pii-guard
description: Install, configure, and manage the PII Guard filter that redacts or blocks PII and credentials before they reach the model. Triggers on "pii-guard", "install pii filter", "pii status", "enable pii guard", "disable pii guard", "test pii", "redact PII".
---

# PII Guard — skill-managed PII filter for Claude Code

You are the **entire control surface** for PII Guard. The user never needs to open a terminal — you handle everything via the Bash tool.

## Where this skill lives

```
$SKILL_DIR   = the directory containing this SKILL.md
$RUNTIME_DIR = ~/.claude/pii-guard                (created by install.py)
```

Resolve `$SKILL_DIR` at runtime (handles direct skills dir + plugin-namespaced installs):

```bash
SKILL_DIR=$(ls -d ~/.claude/skills/pii-guard 2>/dev/null \
  || ls -d ~/.claude/plugins/*/skills/pii-guard 2>/dev/null | head -1)
```

## Dispatch table — match intent, then run the command

| User says | You do |
|-----------|--------|
| "install pii-guard", "set up pii filter" | **Install flow** below |
| "is pii-guard running?", "pii status" | `python3 ~/.claude/pii-guard/cli.py status` |
| "disable pii-guard" | Ask scope, then `cli.py disable [--duration] [--category]` |
| "enable pii-guard" | `python3 ~/.claude/pii-guard/cli.py enable` |
| "test pii on X" | `python3 ~/.claude/pii-guard/cli.py test "X"` |
| "change policy: contact = redact" | `python3 ~/.claude/pii-guard/cli.py policy --set contact=redact` |
| "uninstall pii-guard" | Confirm, then `python3 "$SKILL_DIR/installer/uninstall.py" --yes --purge` |

## Install flow

**Step 1 — Detect state:**
```bash
test -f ~/.claude/pii-guard/guard.py && echo installed || echo fresh
```
If installed, offer `status`, `reinstall`, or `uninstall`.

**Step 2 — Run installer (defaults are sensible):**
```bash
python3 "$SKILL_DIR/installer/install.py" --yes
```

**Step 3 — Verify:**
```bash
python3 ~/.claude/pii-guard/cli.py test "my email is demo@example.com and card 4111 1111 1111 1111"
```

**Step 4 — Tell the user:**
> ✅ Installed and enabled. Restart Claude Code (or run `/reload`) so the hook activates on your next prompt.

## Disable flow

Ask for scope:
- **Fully off** → `cli.py disable`
- **Timed** → `cli.py disable --duration 30m` (supports `m`, `h`, `d`)
- **One category** → `cli.py disable --category contact`
- **Credentials** → refuse without `--confirm`; explain risk once, then honor if user insists

After any state change, show `status`.

## Rules for you

- Never run destructive commands without explicit confirmation. `uninstall --purge` always needs "yes".
- Don't bypass safety rails. `credentials` category needs `--confirm` to disable.
- Respect user's answers — apply them, don't second-guess.
- Don't invent patterns from training data. Only add patterns the user provided verbatim.

## Files shipped

- `SKILL.md` (this file)
- `manifest.json`
- `installer/install.py` — writes runtime to `~/.claude/pii-guard/`, patches `settings.json` with timestamped backup, verifies post-install
- `installer/uninstall.py` — removes hook; `--purge` also deletes runtime
- `runtime/guard.py` — the hook filter (stdin → stdout, exit 0/2)
- `runtime/cli.py` — status / enable / disable / test / policy
- `runtime/patterns/builtin.json`, `runtime/patterns/custom.json`
