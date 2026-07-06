# Changelog

## [Unreleased]

### Added
- **Dynamic authentication.** Subjects can obtain a token by logging in before
  the run via an auth provider (`type: http`, `oauth2_client_credentials`,
  `oauth2_password`) instead of carrying a static token, with the token pulled
  from the JSON response at a configurable `token_path`.
- **`${ENV}` interpolation** for matrix files (`${VAR}` / `${VAR:-default}`), so
  secrets stay out of the committed matrix; `--env-file` loads a dotenv.
- **Custom headers** on resources and subjects, merged as
  resource → subject → bearer, never clobbering an explicit `Authorization`.
- **Configurable response matcher** (`access:`) to decide allow/deny by status
  (codes, ranges, classes), body regex, and redirect handling — instead of a
  bare 2xx check.

## [0.1.0] - 2025-09-14
First release of **overstep** — matrix-driven authorization testing for HTTP APIs.

### Added
- **Authorization matrix** format: `subjects` × `resources` × `policy`, with
  object-level (`type: object` + `owner_param`) and function-level resources.
- Positive **and** negative test generation, with self/other expansion for
  object resources (`overstep plan`).
- Finding classification: **BOLA**, **BFLA**, **privilege escalation**, plus
  `unexpected-deny` for over-restrictions.
- **Authorization drift**: `overstep snapshot` records a baseline and
  `overstep run --baseline` fails CI when decisions change.
- A `run_pipeline` orchestration seam with an injectable executor, and a
  pluggable reporter registry.
- Reporters: JSON, HTML, **SARIF** (GitHub code scanning) and **JUnit** XML.
- `overstep validate` (lint a matrix) and `overstep scaffold` (starter
  `resources:` block from OpenAPI or HAR).
- `--fail-on {vuln,drift,any,never}` to control the exit code, plus bounded
  concurrency for faster runs.
- Optional safe `condition` expressions on allow rules (e.g. tenant isolation),
  evaluated through a restricted AST evaluator.
- A bundled intentionally-vulnerable demo API and an OWASP crAPI example.
