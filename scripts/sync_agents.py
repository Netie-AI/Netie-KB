#!/usr/bin/env python3
"""Sync generated KB outputs to ~/.claude and ~/.cursor with divergence guard."""

from __future__ import annotations

import argparse
import filecmp
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GENERATED = ROOT / "generated"
CLAUDE_SRC = GENERATED / "CLAUDE.md"
MDC_SRC = GENERATED / "netie-kb.mdc"
SKILLS_SRC = ROOT / "skills"

CLAUDE_HOME = Path.home() / ".claude"
CURSOR_HOME = Path.home() / ".cursor"
CLAUDE_DST = CLAUDE_HOME / "CLAUDE.md"
MDC_DST = CURSOR_HOME / "rules" / "netie-kb.mdc"
SKILLS_DST = CLAUDE_HOME / "skills"


def _run_kb_render() -> None:
    subprocess.run([sys.executable, str(ROOT / "scripts" / "kb.py"), "render"], check=True)


def _has_local_drift(dst: Path, src: Path) -> bool:
    if not dst.exists():
        return False
    if not src.exists():
        return False
    return not filecmp.cmp(dst, src, shallow=False)


def _copy_if_ok(src: Path, dst: Path, label: str, force: bool) -> None:
    if not src.exists():
        raise FileNotFoundError(f"missing generated file: {src}")
    if _has_local_drift(dst, src) and not force:
        print(f"REFUSE: {label} has local modifications not in KB generated output.", file=sys.stderr)
        print(f"  destination: {dst}", file=sys.stderr)
        print(f"  source:      {src}", file=sys.stderr)
        print("  Run with --force to overwrite, or edit D:\\Netie-KB and re-render.", file=sys.stderr)
        raise SystemExit(2)
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    print(f"synced {label} -> {dst}")


def _sync_skills(force: bool) -> None:
    if not SKILLS_SRC.exists():
        return
    SKILLS_DST.mkdir(parents=True, exist_ok=True)
    for skill_dir in SKILLS_SRC.iterdir():
        if not skill_dir.is_dir():
            continue
        dst_dir = SKILLS_DST / skill_dir.name
        if dst_dir.exists() and not force:
            # Compare SKILL.md only for drift signal
            src_skill = skill_dir / "SKILL.md"
            dst_skill = dst_dir / "SKILL.md"
            if src_skill.exists() and dst_skill.exists() and not filecmp.cmp(src_skill, dst_skill, shallow=False):
                print(f"REFUSE: skill {skill_dir.name} drift at {dst_skill}", file=sys.stderr)
                raise SystemExit(2)
        if dst_dir.exists():
            shutil.rmtree(dst_dir)
        shutil.copytree(skill_dir, dst_dir)
        print(f"synced skill {skill_dir.name}")


def _ensure_junction(link: Path, target: Path) -> None:
    if link.exists():
        return
    link.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(link), str(target)],
        check=True,
        capture_output=True,
        text=True,
    )
    print(f"junction {link} -> {target}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--force", action="store_true", help="overwrite local drift")
    parser.add_argument("--no-junction", action="store_true")
    args = parser.parse_args()

    _run_kb_render()
    _copy_if_ok(CLAUDE_SRC, CLAUDE_DST, "CLAUDE.md", args.force)
    _copy_if_ok(MDC_SRC, MDC_DST, "netie-kb.mdc", args.force)
    _sync_skills(args.force)

    if not args.no_junction:
        _ensure_junction(CLAUDE_HOME / "kb", ROOT)
        _ensure_junction(CURSOR_HOME / "kb", ROOT)

    print("sync complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
