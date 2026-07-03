# Changelog

## [0.2.0] - 2025-09-14
Renamed the project to **overstep** and reworked it around a declarative
authorization matrix. This is a breaking change — the `authscope` CLI, the
invariants DSL and the old config format are gone.

### Added
- **Authorization matrix** format: `subjects` × `resources` × `policy`, with
  object-level (`type: object` + `owner_param`) and function-level resources.
- Positive **and** negative test generation, with self/other expansion for
  object resources (`overstep plan`).
- Finding classification: **BOLA**, **BFLA**, **privilege escalation**, plus
  `unexpected-deny` for over-restrictions.
- **Authorization drift**: `overstep snapshot` records a baseline and
  `overstep run --baseline` fails CI when decisions change.
- Reporters: JSON, HTML, **SARIF** (GitHub code scanning) and **JUnit** XML.
- `overstep validate` (lint a matrix) and `overstep scaffold` (starter
  `resources:` block from OpenAPI or HAR).
- `--fail-on {vuln,drift,any,never}` to control the exit code, plus bounded
  concurrency for faster runs.
- Optional safe `condition` expressions on allow rules (e.g. tenant isolation).

### Changed
- Package renamed `authscope` → `overstep`; console script is now `overstep`.
- Executor runs requests concurrently and treats transport errors as denials.

### Security
- Expression evaluator hardened: comparison operators added, unknown names and
  any callable now rejected.

## [0.1.0] - 2025-08-22
Initial release as `authscope`: OpenAPI-driven SELF/OTHER scenarios, an
invariants DSL, an async httpx runner, HTML/JSON reports, a mock vulnerable API
and a safe expression evaluator.
