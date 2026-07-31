#!/usr/bin/env python3
"""Netie Knowledge Base CLI — search, index, render, validate."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schema" / "frontmatter.json"
KIND_DIRS = {
    "rule": ROOT / "rules",
    "workflow": ROOT / "workflows",
    "finding": ROOT / "findings",
    "attack": ROOT / "attacks",
    "skill": ROOT / "skills",
}
KIND_PREFIX = {"rule": "R", "workflow": "W", "finding": "F", "attack": "A", "skill": "S"}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

SESSION_PROTOCOL = """\
## Session protocol

**START:** `python D:\\Netie-KB\\scripts\\kb.py search "<keywords>"` — report in three lines:
which rules apply, which workflow covers this shape, which attacks are proven here.
Follow an existing workflow rather than re-deriving. Use a small model for this step.

**END:** file ≥1 finding (`kb.py new finding`). "Nothing new — R-#### held" is valid.
Include: expected vs actual, repro steps, root cause CLASS, which invariant should have caught it.
"""


@dataclass
class Artifact:
    path: Path
    meta: dict[str, Any]
    body: str

    @property
    def id(self) -> str:
        return str(self.meta["id"])


def load_schema() -> dict[str, Any]:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def _normalize_meta(meta: dict[str, Any]) -> dict[str, Any]:
    origin = meta.get("origin")
    if isinstance(origin, dict) and "date" in origin:
        d = origin["date"]
        if hasattr(d, "isoformat"):
            origin["date"] = d.isoformat()
        else:
            origin["date"] = str(d)
    return meta


def split_frontmatter(text: str) -> tuple[dict[str, Any], str]:
    if not text.startswith("---"):
        raise ValueError("missing frontmatter")
    parts = text.split("---", 2)
    if len(parts) < 3:
        raise ValueError("malformed frontmatter")
    meta = yaml.safe_load(parts[1])
    if not isinstance(meta, dict):
        raise ValueError("frontmatter must be a mapping")
    meta = _normalize_meta(meta)
    body = parts[2].lstrip("\n")
    return meta, body


def load_artifact(path: Path) -> Artifact:
    text = path.read_text(encoding="utf-8")
    meta, body = split_frontmatter(text)
    return Artifact(path=path, meta=meta, body=body)


def iter_artifacts() -> list[Artifact]:
    items: list[Artifact] = []
    for kind, directory in KIND_DIRS.items():
        if not directory.exists():
            continue
        for path in sorted(directory.rglob("*.md")):
            if path.name == "SKILL.md":
                continue
            try:
                art = load_artifact(path)
            except ValueError as exc:
                raise ValueError(f"{path}: {exc}") from exc
            items.append(art)
    return items


def validate_meta(meta: dict[str, Any], schema: dict[str, Any]) -> list[str]:
    try:
        import jsonschema

        jsonschema.validate(meta, schema)
        return []
    except ImportError:
        errors: list[str] = []
        if not re.fullmatch(r"[RWFAS]-\d{4}", str(meta.get("id", ""))):
            errors.append("invalid id")
        if meta.get("status") not in {"active", "unverified", "superseded", "archived"}:
            errors.append("invalid status")
        return errors
    except Exception as exc:  # noqa: BLE001
        return [str(exc)]


def cmd_validate(_: argparse.Namespace) -> int:
    schema = load_schema()
    errors: list[str] = []
    for art in iter_artifacts():
        errors.extend(f"{art.path}: {e}" for e in validate_meta(art.meta, schema))
    if errors:
        for err in errors:
            print(err, file=sys.stderr)
        return 1
    print(f"validate: OK ({len(iter_artifacts())} artifacts)")
    return 0


def search_score(art: Artifact, query: str, tags: list[str]) -> int:
    q = query.lower().strip()
    score = 0
    title = str(art.meta.get("title", "")).lower()
    body = art.body.lower()
    tag_list = [t.lower() for t in art.meta.get("tags", [])]
    if q:
        for token in q.split():
            if token in title:
                score += 8
            if token in tag_list:
                score += 6
            if token in body:
                score += 2
    for tag in tags:
        if tag.lower() in tag_list:
            score += 10
    return score


def cmd_search(args: argparse.Namespace) -> int:
    query = args.query or ""
    tags = args.tag or []
    status = args.status
    severity = args.severity
    include_unverified = args.include_unverified

    results: list[tuple[int, Artifact]] = []
    for art in iter_artifacts():
        st = art.meta.get("status")
        if not include_unverified and st == "unverified":
            continue
        if status and st != status:
            continue
        if severity and art.meta.get("severity") != severity:
            continue
        score = search_score(art, query, tags)
        if query or tags:
            if score == 0:
                continue
        results.append((score, art))

    results.sort(
        key=lambda x: (
            -x[0],
            SEVERITY_ORDER.get(str(x[1].meta.get("severity")), 9),
            x[1].id,
        )
    )
    limit = args.limit
    for score, art in results[:limit]:
        print(
            f"{art.id} [{art.meta.get('status')}] "
            f"({art.meta.get('severity')}) score={score} — {art.meta.get('title')}"
        )
    if not results:
        print("no matches")
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    target = args.id.upper()
    for art in iter_artifacts():
        if art.id == target:
            print(art.path.read_text(encoding="utf-8"))
            return 0
    print(f"not found: {target}", file=sys.stderr)
    return 1


def next_id(kind: str) -> str:
    prefix = KIND_PREFIX[kind]
    existing: list[int] = []
    directory = KIND_DIRS[kind]
    if directory.exists():
        for path in directory.rglob("*.md"):
            m = re.search(rf"{prefix}-(\d{{4}})", path.name)
            if m:
                existing.append(int(m.group(1)))
    n = max(existing, default=0) + 1
    return f"{prefix}-{n:04d}"


def cmd_new(args: argparse.Namespace) -> int:
    kind = args.kind
    if kind not in KIND_DIRS:
        print(f"unknown kind: {kind}", file=sys.stderr)
        return 1
    new_id = next_id(kind)
    template_path = ROOT / "templates" / f"{kind}.md"
    if not template_path.exists():
        print(f"missing template: {template_path}", file=sys.stderr)
        return 1
    text = template_path.read_text(encoding="utf-8")
    text = text.replace("R-XXXX", new_id).replace("W-XXXX", new_id)
    text = text.replace("F-XXXX", new_id).replace("A-XXXX", new_id)
    text = text.replace("TITLE", args.title)
    if args.tags:
        tag_yaml = yaml.safe_dump(args.tags, default_flow_style=True).strip()
        text = re.sub(r"tags: \[.*\]", f"tags: {tag_yaml}", text, count=1)
    if args.severity:
        text = re.sub(r"severity: \w+", f"severity: {args.severity}", text, count=1)
    directory = KIND_DIRS[kind]
    directory.mkdir(parents=True, exist_ok=True)
    out = directory / f"{new_id}.md"
    out.write_text(text, encoding="utf-8")
    print(out)
    if args.edit:
        editor = args.editor or _default_editor()
        if editor:
            subprocess.run([editor, str(out)], check=False)
    return 0


def _default_editor() -> str | None:
    import os

    return os.environ.get("EDITOR") or os.environ.get("VISUAL")


def cmd_promote(args: argparse.Namespace) -> int:
    source_id = args.id.upper()
    target_kind = args.to
    if target_kind not in KIND_DIRS:
        print(f"unknown target kind: {target_kind}", file=sys.stderr)
        return 1
    source: Artifact | None = None
    for art in iter_artifacts():
        if art.id == source_id:
            source = art
            break
    if source is None:
        print(f"not found: {source_id}", file=sys.stderr)
        return 1
    new_id = next_id(target_kind)
    template_path = ROOT / "templates" / f"{target_kind}.md"
    text = template_path.read_text(encoding="utf-8")
    text = text.replace("R-XXXX", new_id).replace("W-XXXX", new_id)
    text = text.replace("F-XXXX", new_id).replace("A-XXXX", new_id)
    text = text.replace("TITLE", str(source.meta.get("title", "promoted")))
    meta, _ = split_frontmatter(text)
    meta["status"] = "active"
    meta["related"] = sorted(set(meta.get("related", []) + [source_id]))
    meta["origin"] = source.meta.get("origin", meta["origin"])
    meta["occurrences"] = int(source.meta.get("occurrences", 1))
    meta["tags"] = list(source.meta.get("tags", []))
    meta["severity"] = source.meta.get("severity", meta["severity"])
    promoted_body = f"Promoted from {source_id}.\n\n{source.body.strip()}\n"
    out_text = "---\n" + yaml.safe_dump(meta, sort_keys=False).strip() + "\n---\n\n" + promoted_body
    out_path = KIND_DIRS[target_kind] / f"{new_id}.md"
    out_path.write_text(out_text, encoding="utf-8")

    source.meta["status"] = "superseded"
    source.meta["related"] = sorted(set(source.meta.get("related", []) + [new_id]))
    updated = (
        "---\n"
        + yaml.safe_dump(source.meta, sort_keys=False).strip()
        + "\n---\n\n"
        + source.body
    )
    source.path.write_text(updated, encoding="utf-8")
    print(f"promoted {source_id} -> {new_id} ({out_path})")
    return 0


def cmd_index(_: argparse.Namespace) -> int:
    artifacts = iter_artifacts()
    by_kind: dict[str, list[Artifact]] = defaultdict(list)
    tag_counter: Counter[str] = Counter()
    for art in artifacts:
        by_kind[str(art.meta.get("kind"))].append(art)
        for tag in art.meta.get("tags", []):
            tag_counter[str(tag)] += 1

    lines = [
        "# Netie KB — INDEX",
        "",
        f"_Generated {date.today().isoformat()} by `kb.py index`. Do not hand-edit._",
        "",
    ]
    for kind in ("rule", "workflow", "attack", "finding", "skill"):
        group = by_kind.get(kind, [])
        if not group:
            continue
        group.sort(
            key=lambda a: (
                SEVERITY_ORDER.get(str(a.meta.get("severity")), 9),
                a.id,
            )
        )
        lines.append(f"## {kind.title()}s")
        lines.append("")
        for art in group:
            st = art.meta.get("status")
            sev = art.meta.get("severity")
            title = art.meta.get("title")
            tags = ", ".join(art.meta.get("tags", []))
            lines.append(f"- **{art.id}** `{st}` `{sev}` — {title} ({tags})")
        lines.append("")

    lines.append("## Tag cloud")
    lines.append("")
    for tag, count in tag_counter.most_common():
        lines.append(f"- `{tag}` ({count})")
    lines.append("")

    index_path = ROOT / "INDEX.md"
    index_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {index_path}")
    return 0


def render_claude_md(rules: list[Artifact]) -> str:
    lines = [
        "# Netie — global rules (Claude Code)",
        "",
        "_Generated by `kb.py render`. Do not hand-edit — edit `D:\\Netie-KB\\rules\\`._",
        "",
        "## Context",
        "Cortex `D:\\Cortex` = engine. DMS `D:\\DMS` = HTTP consumer (never imports CortexOS).",
        "OpenVault `D:\\OpenVault` = keys/gate/FreeRoute. KB: `D:\\Netie-KB`.",
        "Home: `C:\\Users\\OoiJianHong\\.claude\\`. Models: **Opus** (plan/judge) · **Fable** (execute).",
        "",
        SESSION_PROTOCOL,
        "",
        "## Invariants",
        "All `status: active` rules below are binding.",
        "",
    ]
    for art in rules:
        lines.append(f"### {art.id} — {art.meta.get('title')}")
        lines.append("")
        rule_body = art.body.strip()
        # Extract ## Rule section if present
        m = re.search(r"## Rule\s*\n+(.*?)(?=\n## |\Z)", rule_body, re.DOTALL)
        if m:
            lines.append(m.group(1).strip())
        else:
            lines.append(rule_body[:500])
        lines.append("")
    lines.extend(
        [
            "## Subagents",
            "Preflight KB search + `PREFLIGHT: HIT|PARTIAL|MISS` before Agent teams.",
            "Record shape + rationale in `~\\.claude\\workflows\\`. HIT → Fable + cited files only.",
            "",
            "## Style",
            "Do not weaken checks for green. Stop on cross-lane blockers. Verified ≠ assumed.",
            "",
        ]
    )
    return "\n".join(lines)


def render_mdc(rules: list[Artifact]) -> str:
    lines = [
        "---",
        "description: Netie KB active rules (generated). Do not hand-edit.",
        "alwaysApply: true",
        "---",
        "",
        "# Netie — global rules (Cursor)",
        "",
        "_Generated by `kb.py render`. Edit rules in `D:\\Netie-KB\\rules\\`._",
        "",
        SESSION_PROTOCOL,
        "",
        "## Invariants",
        "",
    ]
    for art in rules:
        m = re.search(r"## Rule\s*\n+(.*?)(?=\n## |\Z)", art.body, re.DOTALL)
        body = m.group(1).strip() if m else art.body.strip()[:300]
        lines.append(f"**{art.id}** — {body}")
        lines.append("")
    lines.extend(
        [
            "## Subagents",
            "Preflight KB + `PREFLIGHT: HIT|PARTIAL|MISS` before Task spawn.",
            "Composer = implement lane; Task = lens subagents. Not UI-only.",
            "",
            "## Style",
            "Do not weaken checks. Stop on blockers. Verified ≠ assumed.",
            "",
        ]
    )
    return "\n".join(lines)


def cmd_render(_: argparse.Namespace) -> int:
    rules = [
        art
        for art in iter_artifacts()
        if art.meta.get("kind") == "rule" and art.meta.get("status") == "active"
    ]
    rules.sort(key=lambda a: a.id)
    generated = ROOT / "generated"
    generated.mkdir(parents=True, exist_ok=True)
    claude_path = generated / "CLAUDE.md"
    mdc_path = generated / "netie-kb.mdc"
    claude_text = render_claude_md(rules)
    mdc_text = render_mdc(rules)
    claude_path.write_text(claude_text, encoding="utf-8")
    mdc_path.write_text(mdc_text, encoding="utf-8")
    # Plain markdown for Cursor Settings → User Rules (no YAML frontmatter)
    user_rules = mdc_text.split("---", 2)[-1].lstrip("\n") if mdc_text.startswith("---") else mdc_text
    user_rules_path = generated / "USER_RULES_PASTE.md"
    user_rules_path.write_text(user_rules, encoding="utf-8")
    line_count = len(claude_text.splitlines())
    print(f"wrote {claude_path} ({line_count} lines)")
    print(f"wrote {mdc_path}")
    print(f"wrote {user_rules_path}")
    if line_count > 200:
        print("WARNING: CLAUDE.md exceeds 200 lines — tighten rules", file=sys.stderr)
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Netie Knowledge Base")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("search", help="search corpus")
    s.add_argument("query", nargs="?", default="")
    s.add_argument("--tag", action="append", default=[])
    s.add_argument("--severity")
    s.add_argument("--status")
    s.add_argument("--include-unverified", action="store_true")
    s.add_argument("--limit", type=int, default=20)
    s.set_defaults(func=cmd_search)

    s = sub.add_parser("show", help="show artifact by ID")
    s.add_argument("id")
    s.set_defaults(func=cmd_show)

    s = sub.add_parser("new", help="create artifact from template")
    s.add_argument("kind", choices=sorted(KIND_DIRS))
    s.add_argument("--title", required=True)
    s.add_argument("--tags", nargs="+", default=[])
    s.add_argument("--severity", choices=["critical", "high", "medium", "low"])
    s.add_argument("--edit", action="store_true")
    s.add_argument("--editor")
    s.set_defaults(func=cmd_new)

    s = sub.add_parser("promote", help="promote finding to rule/workflow/attack")
    s.add_argument("id")
    s.add_argument("--to", required=True, choices=["rule", "workflow", "attack"])
    s.set_defaults(func=cmd_promote)

    s = sub.add_parser("index", help="regenerate INDEX.md")
    s.set_defaults(func=cmd_index)

    s = sub.add_parser("render", help="regenerate CLAUDE.md + netie-kb.mdc")
    s.set_defaults(func=cmd_render)

    s = sub.add_parser("validate", help="validate all frontmatter")
    s.set_defaults(func=cmd_validate)

    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
