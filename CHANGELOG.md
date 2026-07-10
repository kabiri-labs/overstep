# Changelog

## [0.11.0] - 2026-07-10

### Added
- **Transport abstraction.** Execution is now pluggable behind a transport
  registry (`overstep.transports`), mirroring the reporter registry. A resource
  declares a `transport:` (default `http`), the planner carries it onto every test
  case, and a dispatcher routes each case to the matching transport's executor —
  so a single run can mix transports. HTTP is registered as the built-in `http`
  transport with no behaviour change. `validate` now flags a resource that
  references an unknown transport. This is the seam that lets non-HTTP targets
  (e.g. MCP tool-calls) be added without touching the matrix, planner, classifier
  or reports.

## [0.10.0] - 2026-07-09

### Added
- **Policy inference from OpenAPI security schemes.** `overstep scaffold spec.yaml
  --with-policy` now emits a *full* starter matrix — roles, subjects, resources
  **and a policy** — by reading the spec's `securitySchemes` scopes and each
  operation's `security` requirement. Declared scopes become roles ordered
  least→most privileged; an endpoint requiring a scope gets an allow rule per scope
  (object resources default to owner-scope for non-admin roles); an endpoint with
  no security becomes public (`anonymous`). This removes most of the manual policy
  authoring that was the main adoption cost.

## [0.9.0] - 2026-07-09

### Added
- **CWE / OWASP API Top 10 tagging.** A new taxonomy maps every finding class to
  its CWE (BOLA→CWE-639, BFLA→CWE-285, BOPLA→CWE-213, privilege-escalation→CWE-269)
  and OWASP API Security Top 10 entry. SARIF rules now carry `helpUri`, a
  `security-severity` score (so GitHub code scanning ranks them correctly),
  and `external/cwe/...` + `APIx:2023` tags; each result and every JSON finding is
  annotated with its `cwe` and `owasp_api`. Findings are now first-class in
  vulnerability dashboards and compliance reports.

## [0.8.0] - 2026-07-09

### Added
- **429/503 retry with backoff.** The executor now retries rate-limited and
  transiently-unavailable responses, honouring a `Retry-After` header and
  otherwise using exponential backoff with full jitter (`--max-retries`, default 2).
  A large matrix no longer trips a WAF into flaky failures.
- **Read-only mode (`--read-only`).** Skips every mutating verb (POST/PUT/PATCH/
  DELETE) so the suite can be pointed at a sensitive environment without changing
  state. Skipped requests are recorded but never produce findings.
- **Teardown steps (`teardown:`).** Best-effort cleanup requests that run once
  after the suite and can reference `{{captures}}` from setup, so fixtures created
  for BOLA testing are removed. A teardown failure is reported as a warning, never
  a run failure.

## [0.7.0] - 2026-07-09

### Added
- **BOPLA (object property-level) checks.** A resource can declare
  `forbidden_fields:` — JSON keys that must never appear in a response, even for an
  allowed caller (`password_hash`, `is_admin`, …). When one shows up in a granted
  response overstep reports a `BOPLA` finding. Detection is key-based (the body is
  parsed as JSON), so a forbidden name appearing as free text does not false-positive.
- **Cross-method probing.** A resource can declare `probe_methods: [PUT, DELETE]`;
  overstep fires each verb at *another* subject's object as a negative test. A
  probe that succeeds means the endpoint is missing method-level authorization and
  is reported as BOLA/BFLA — catching a whole class of write-side bugs without
  hand-writing a resource per verb.

### Changed
- `BOPLA` is treated as a gating vulnerability and carries a SARIF rule.

## [0.6.0] - 2026-07-09

### Added
- **CI-native distribution.** overstep now ships the artifacts a DevSecOps team
  needs to adopt it in minutes:
  - a **`Dockerfile`** (+ `.dockerignore`) that installs the package and exposes
    the CLI as the entrypoint, so a pipeline can `docker run … overstep run …`;
  - a composite **GitHub Action** (`action.yml`) with `matrix`, `base-url`, `out`,
    `fail-on`, `waivers` and `baseline` inputs and a `sarif` output for
    `upload-sarif`;
  - a **pre-commit hook** (`.pre-commit-hooks.yaml`, `overstep-validate`) that
    lints the matrix before every commit;
  - copy-paste **GitHub Actions and GitLab CI** examples under `examples/ci/`.

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
