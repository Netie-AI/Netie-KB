# Netie Knowledge Base

Private corpus of rules, workflows, findings, attacks, and skills for Claude Code and Cursor.

**One source, two renderings.** Edit `rules/`, `workflows/`, etc. - never hand-edit `generated/`, `~/.claude/CLAUDE.md`, or `~/.cursor/rules/netie-kb.mdc`.

## Quick start

```bash
cd D:\Netie-KB
pip install -r requirements.txt
python scripts/kb.py search "manifest escape"
python scripts/kb.py show R-0001
python scripts/kb.py new finding --title "..." --tags "..."
python scripts/kb.py index
python scripts/kb.py render
python scripts/sync_agents.py
```

## Session protocol

**Netie domain:** `kb.py search` / `kb.py new finding` when working Netie/KB/distill.
**Global OS:** `~/.cursor/rules/00-global-operating.mdc` (ADHD + Ponytail + findings).

## Promotion path

Finding (unverified) -> verified -> Rule / Workflow / Attack -> Skill

Only `status: active` rules render into agent globals. Unverified findings never
render. Default `kb.py search` omits them; pass `--include-unverified` to see them.

## Windows notes

- Corpus text is laptop-ASCII only (R-0012): no em dash, `>=` glyphs, arrows, or curly quotes. `kb.py validate` enforces this.
- PowerShell aliases `curl` to `Invoke-WebRequest`. Use `curl.exe` or `Invoke-RestMethod -Uri http://127.0.0.1:8010/healthz` for health checks.

## Global vs domain

- **Global Cursor OS:** `~/.cursor/rules/00-global-operating.mdc` (ADHD talk, Ponytail code, repo findings).
- **Paste for Settings -> User Rules:** `generated/GLOBAL_USER_RULES_PASTE.md`
- **Netie domain pack:** `generated/netie-kb.mdc` (`alwaysApply: false`) - KB invariants only.
- **Cortex engine laws:** stay in the Cortex repo. Do not promote them into Netie globals.

## CI

`validate` + Unicode `search` + `index` (no diff) + `render` (no diff on `generated/`)
+ unittest planted-render hop, plus `search-windows` on `windows-latest`.
