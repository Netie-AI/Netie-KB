# Netie Knowledge Base

Private corpus of rules, workflows, findings, attacks, and skills for Claude Code and Cursor.

**One source, two renderings.** Edit `rules/`, `workflows/`, etc. — never hand-edit `generated/`, `~/.claude/CLAUDE.md`, or `~/.cursor/rules/netie-kb.mdc`.

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

**START:** `kb.py search "<keywords>"` — report rules / workflow / attacks in three lines.  
**END:** `kb.py new finding` — at least one per session.

## Promotion path

Finding (unverified) → verified → Rule / Workflow / Attack → Skill

Only `status: active` rules render into agent globals. Unverified findings are searchable but never rendered.

## CI

`validate` + `index` (no diff) + `render` (no diff on `generated/`).
