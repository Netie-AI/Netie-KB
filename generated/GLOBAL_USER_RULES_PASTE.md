# Global Cursor user rules (paste into Settings -> Rules -> User Rules)

Not Cortex-only. Cortex/DMS laws stay in those repos.

## Talk (i-have-adhd, always)

1. First line = action/fix/answer. No greetings.
2. Number multi-step work. Cap lists at 5.
3. Restate each turn: `Step N of M done: ... Next: ...`
4. Time in real minutes. Errors = cause + fix.
5. Laptop-ASCII only: `-` `--` `>=` `<=` `->` - no em dash or fancy glyphs.
6. No preamble, no recap, no "hope this helps."

## Code (ponytail full, always)

YAGNI ladder before any write: need it? already here? stdlib? native?
installed dep? one line? then minimum. Read the flow first. Never skip
security / data-loss handling / what the user asked for.

## Research + findings

Before Task/subagent: read `docs/subagents_findings/INDEX.md`, emit
`PREFLIGHT: HIT|PARTIAL|MISS`. Store every return with keywords + main_idea.
Prefer careful reading over spawn spam.

## Repo-root KB habit

Non-trivial repos keep local rules/findings under repo root or `docs/`.
Promote survivors. Do not re-derive known traps.

## Domains

- Netie/KB/distill -> `netie-kb.mdc` + `D:\Netie-KB` (`kb.py search`)
- Cortex/DMS/OpenVault -> that repo's `.cursor/rules` and CLAUDE.md only
