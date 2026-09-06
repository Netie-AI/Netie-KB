"""Planted lesson reaches a fresh agent via kb.py render (the hop that exists).

Phase 3 of the ecosystem plan wants feedback -> PRD table -> finding ->
verified -> rendered rules -> registry. That full pipeline is not this test.
This asserts the last hop that already ships: an active rule in the corpus
appears in generated packs that a new process can read off disk.

Unverified findings never render. Default search omits them unless
--include-unverified (README used to say they were searchable by default).
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

KB_ROOT = Path(__file__).resolve().parents[1]
KB_PY = KB_ROOT / "scripts" / "kb.py"
RULE_NONCE = "planted-rule-nonce-c0ffee12"
FINDING_NONCE = "planted-finding-nonce-bada5511"

RULE_MD = f"""\
---
id: R-9999
kind: rule
title: Planted render hop {RULE_NONCE}
status: active
severity: high
tags: [planted, render]
origin:
  date: 2026-08-27
  repo: netie-kb
  incident: "isolated render-hop test"
occurrences: 1
enforced_by: null
related: []
supersedes: []
---

## Rule

A planted lesson {RULE_NONCE} must reach a fresh agent via render.

## Why

1. Isolated corpus
2. Render hop

## Check

generated/CLAUDE.md contains the nonce.
"""

FINDING_MD = f"""\
---
id: F-9999
kind: finding
title: Planted search hop {FINDING_NONCE}
status: unverified
severity: medium
tags: [planted, search]
origin:
  date: 2026-08-27
  repo: netie-kb
  incident: "isolated search-hop test"
occurrences: 1
enforced_by: null
related: []
supersedes: []
---

## Expected vs actual

Expected: a fresh agent can find {FINDING_NONCE} after it is planted.
Actual: default search omits unverified; render omits findings.
"""


def _run_kb(tmp: Path, *args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["NETIE_KB_ROOT"] = str(tmp)
    env["PYTHONUTF8"] = "1"
    return subprocess.run(
        [sys.executable, str(KB_PY), *args],
        cwd=str(KB_ROOT),
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )


def _plant(tmp: Path) -> None:
    (tmp / "rules").mkdir()
    (tmp / "findings").mkdir()
    (tmp / "rules" / "R-9999.md").write_text(RULE_MD, encoding="utf-8")
    (tmp / "findings" / "F-9999.md").write_text(FINDING_MD, encoding="utf-8")


class PlantedFindingReachesFreshAgent(unittest.TestCase):
    def test_planted_active_rule_appears_in_render_for_a_fresh_reader(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            _plant(tmp)
            rendered = _run_kb(tmp, "render")
            self.assertEqual(rendered.returncode, 0, rendered.stderr)
            claude = tmp / "generated" / "CLAUDE.md"
            mdc = tmp / "generated" / "netie-kb.mdc"
            self.assertTrue(claude.is_file(), "render did not write CLAUDE.md")
            env = os.environ.copy()
            env["PYTHONUTF8"] = "1"
            reader = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    (
                        "from pathlib import Path\n"
                        f"claude = Path(r'{claude}').read_text(encoding='utf-8')\n"
                        f"mdc = Path(r'{mdc}').read_text(encoding='utf-8')\n"
                        f"assert {RULE_NONCE!r} in claude\n"
                        f"assert {RULE_NONCE!r} in mdc\n"
                        f"assert {FINDING_NONCE!r} not in claude\n"
                        f"assert {FINDING_NONCE!r} not in mdc\n"
                    ),
                ],
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                check=False,
            )
            self.assertEqual(reader.returncode, 0, reader.stderr)

    def test_planted_unverified_finding_needs_the_flag_and_never_renders(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            _plant(tmp)
            default = _run_kb(tmp, "search", FINDING_NONCE)
            self.assertEqual(default.returncode, 0, default.stderr)
            self.assertNotIn("F-9999", default.stdout)
            flagged = _run_kb(tmp, "search", FINDING_NONCE, "--include-unverified")
            self.assertEqual(flagged.returncode, 0, flagged.stderr)
            self.assertIn("F-9999", flagged.stdout)
            rendered = _run_kb(tmp, "render")
            self.assertEqual(rendered.returncode, 0, rendered.stderr)
            claude = (tmp / "generated" / "CLAUDE.md").read_text(encoding="utf-8")
            self.assertNotIn(FINDING_NONCE, claude)
            self.assertIn(RULE_NONCE, claude)


if __name__ == "__main__":
    unittest.main()
