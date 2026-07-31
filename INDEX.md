# Netie KB — INDEX

_Generated 2026-07-31 by `kb.py index`. Do not hand-edit._

## Rules

- **R-0001** `active` `critical` — Gates assert the artifact the customer receives (testing, ci, verification, envelope, invariant)
- **R-0002** `active` `critical` — A skipped test is a failing test (testing, ci, adversarial, duckdb)
- **R-0003** `active` `critical` — Adversary is never the verifier (red-team, verification, adversarial)
- **R-0007** `active` `critical` — Verify the gate can fail before trusting it green (ci, testing, importlinter, verification)
- **R-0009** `active` `critical` — Never hand-author generated artifacts (contract, openapi, generation, drift)
- **R-0011** `active` `critical` — A silent fallback is a lie (demo, fallback, envelope, visibility)
- **R-0004** `active` `high` — Fix the root cause class, not the symptom (security, manifest, sql, name-binding)
- **R-0005** `active` `high` — A control that refuses legitimate work is a failure (security, manifest, enforcement, false-positive)
- **R-0006** `active` `high` — Check git log before amend; never git add -A (git, multi-lane, workflow)
- **R-0008** `active` `high` — Push before session end — uncommitted work does not exist (git, workflow, data-loss)
- **R-0010** `active` `high` — Zero errors in n trials bounds error at 3/n — claim <1% only at n≥300 (eval, statistics, trust, corpus)

## Workflows

- **W-0001** `active` `critical` — Adversarial review — N adversaries → separate verifier → judge (red-team, adversarial, security, orchestration)
- **W-0002** `active` `high` — Contract change — bump, freeze spec, compat-check, test vectors, vendor downstream (contract, openapi, release, coordination)
- **W-0003** `active` `high` — Boundary violation repair — invert dependency behind Protocol (architecture, import-boundary, protocol, packs)
- **W-0004** `active` `high` — Corpus-first hardening — write corpus, run, fix, re-run for false positives (security, corpus, manifest, testing)

## Attacks

- **A-0001** `active` `critical` — Unknown FROM-position table functions (manifest, duckdb, table-functions, escape)
- **A-0002** `active` `critical` — Name shadowing via local binding (manifest, sql, name-binding, unnest)
- **A-0003** `active` `critical` — Value encoding mismatch — filter matches nothing, green badge (routing, vocabulary, envelope, value-encoding)
- **A-0004** `active` `high` — Stale process serving old config (ops, demo, stale-process, verification)

## Tag cloud

- `manifest` (5)
- `testing` (4)
- `verification` (4)
- `security` (4)
- `ci` (3)
- `envelope` (3)
- `adversarial` (3)
- `duckdb` (2)
- `red-team` (2)
- `sql` (2)
- `name-binding` (2)
- `git` (2)
- `workflow` (2)
- `contract` (2)
- `openapi` (2)
- `corpus` (2)
- `demo` (2)
- `invariant` (1)
- `enforcement` (1)
- `false-positive` (1)
- `multi-lane` (1)
- `importlinter` (1)
- `data-loss` (1)
- `generation` (1)
- `drift` (1)
- `eval` (1)
- `statistics` (1)
- `trust` (1)
- `fallback` (1)
- `visibility` (1)
- `orchestration` (1)
- `release` (1)
- `coordination` (1)
- `architecture` (1)
- `import-boundary` (1)
- `protocol` (1)
- `packs` (1)
- `table-functions` (1)
- `escape` (1)
- `unnest` (1)
- `routing` (1)
- `vocabulary` (1)
- `value-encoding` (1)
- `ops` (1)
- `stale-process` (1)

