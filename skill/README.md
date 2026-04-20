# pii-guard — skill package

The skill bundle that Claude Code loads. See the [repo README](../README.md) for the full story.

Layout:

```
SKILL.md               Dispatch instructions the agent reads
manifest.json          Skill metadata
installer/install.py   Writes runtime + patches settings.json
installer/uninstall.py Reverts hook, --purge removes runtime
runtime/guard.py       The UserPromptSubmit hook (stdin → stdout, exit 0/2)
runtime/cli.py         status / enable / disable / test / policy
runtime/patterns/      builtin.json (shipped) + custom.json (user-editable)
```
