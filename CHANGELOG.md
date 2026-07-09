# Changelog

## [0.5.0] - 2026-07-09

### Added
- **Waivers / accepted-risk suppression.** `overstep run --waivers waivers.yaml`
  moves reviewed, consciously-accepted findings out of the gating set without
  silencing the tool. Each waiver names a finding by its stable `test_id` (optionally
  narrowed to a `vuln_class`), a mandatory `reason`, and an optional `expires`
  date. Waived findings are recorded separately (in the JSON report and the
  summary) so accepted risk stays visible. **Expired waivers stop suppressing and
  print a warning**, forcing re-review — keeping this distinct from a drift
  baseline. A sample `examples/mock_api/waivers.yaml` is included.

## [0.4.0] - 2026-07-09

### Added
- **Reproduction evidence on every finding.** Each finding now carries a
  copy-pasteable `curl` command and a structured `request` record (method, URL,
  headers, body) so a developer can re-run the exact request that triggered it.
  Credentials (`Authorization`, `Cookie`, `X-Api-Key`, …) are masked in both, so
  reports are safe to paste into tickets and dashboards. The HTML report shows the
  repro line alongside the response body under **evidence & repro**.

## [0.3.0] - 2026-07-09

### Added
- **Content-aware BOLA oracle.** A subject can declare a `marker` — a string that
  uniquely identifies *its* data (an email, a per-user secret). When a BOLA probe
  slips through, overstep scans the response body for the victim's marker and
  grades the finding's `confidence`: `confirmed` when the victim's data actually
  leaked, `suspected` when access was granted but the owner data never appeared
  (downgraded to `medium` severity — likely an empty result, verify manually), and
  `unverified` when no marker was configured (status-only, as before). This turns
  "the status was 200" into "the response really contained someone else's data",
  cutting the biggest source of BOLA false positives. `confidence` is surfaced in
  the JSON, HTML and SARIF reports.

## [0.2.0] - 2026-07-06

### Added
- **Setup steps & object seeding.** `setup:` requests run once before the suite
  (as a chosen subject) and `extract` values from their responses into a capture
  context. A resource `objects:` map assigns each subject the real id of the
  object it owns — filled from `{{captures}}` — so SELF/OTHER probes target
  genuine objects instead of relying on `user_id`. Captures also fill request
  bodies, queries and headers.
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
