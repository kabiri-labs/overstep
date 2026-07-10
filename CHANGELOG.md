# Changelog

## [0.17.0] - 2026-07-10

### Changed
- **`--fail-on drift` now gates on drift only.** Previously `--fail-on drift`
  also exited non-zero on any active vulnerability, so a baseline full of
  already-triaged findings could never go green — contradicting the documented
  "fail only when authorization *changes*" contract. `drift` now fails solely on
  authorization drift versus the baseline. A new **`vuln-or-drift`** value keeps
  the old combined behaviour for anyone who wants it. The accepted values are now
  `vuln | drift | vuln-or-drift | any | never`, and an unrecognized `--fail-on`
  value now fails fast with exit code 2 (with a clear message) instead of being
  silently treated as `vuln`.

### Fixed
- **`snapshot` now uses the same orchestration as `run`.** The `snapshot` command
  used to call the HTTP executor directly, bypassing the transport dispatcher and
  never running `teardown:` steps — so baselines for MCP, stdio-MCP and mixed
  HTTP/MCP matrices were wrong or empty, and setup fixtures leaked. Both commands
  now share one pipeline (authenticate → setup → plan → dispatch → teardown), so
  every transport snapshots correctly. `snapshot` also gains `--read-only` and
  `--max-retries` for parity with `run`.
- **Teardown runs even when a run fails.** Fixture cleanup now executes in a
  `finally`, so a crash or interrupt during planning or dispatch no longer leaks
  the objects that setup steps created. A teardown failure is still only a
  warning and never masks the original error.

## [0.16.0] - 2026-07-10

### Added
- **MCP OAuth 2.1 discovery.** An auth provider can now `discover_from` an MCP
  server (by name or URL) instead of hardcoding a `token_url`: overstep fetches the
  server's **Protected Resource Metadata** (RFC 9728,
  `/.well-known/oauth-protected-resource`) to find its authorization server, then
  the **Authorization Server Metadata** (RFC 8414 / OIDC discovery) to find the
  `token_endpoint`. It obtains a token with the machine grants
  (`oauth2_client_credentials` / `oauth2_password`) and includes the **resource
  indicator** (RFC 8707) so the token is audience-bound to the MCP server. The
  discovered token flows into the subject's headers, so remote MCP servers behind
  OAuth work with no manual endpoint wiring. `validate` flags an OAuth provider
  with neither `token_url` nor `discover_from`, and a `discover_from` that names an
  unknown server. (The interactive authorization-code flow is out of scope for an
  automated tool.)

## [0.15.0] - 2026-07-10

### Added
- **MCP setup & teardown.** `setup:` and `teardown:` steps can now be MCP
  tool-calls (`call: { server, tool, arguments }`) instead of HTTP requests, so
  fixtures for MCP BOLA testing are created and cleaned up over the same
  transport. A setup step's `extract` reads dotted paths out of the tool result's
  JSON content (e.g. capture a new document id from `create_document`), and those
  captures fill `{{...}}` in resource `objects`/arguments and later teardown calls.
  Works for both HTTP and stdio MCP servers via a synchronous MCP client; teardown
  is best-effort (failures become warnings). `validate` checks that each step sets
  a `request` or a `call` and references a known server. The demo MCP server gains
  `create_document`/`delete_document`, with a `matrix_setup.yaml` example.

## [0.14.0] - 2026-07-10

### Added
- **stdio MCP transport.** overstep can now test **local MCP servers** launched as
  a subprocess, speaking newline-delimited JSON-RPC over stdin/stdout (initialize
  → `notifications/initialized` → `tools/call`). A server declares `command:`
  (argv) instead of `url:`; identity — which has no HTTP header on stdio — is
  injected into the child's environment via `token_env` (the subject's token) plus
  a static `env`, so each subject runs its own process. Findings carry a stdio
  repro (masked env + command + the JSON-RPC call), `--read-only` still skips
  `mutating` tools, and `validate` requires each server to set a `url` or a
  `command`. A bundled vulnerable stdio demo server and matrix are included
  (`examples/mcp_api/stdio_server.py`, `matrix_stdio.yaml`).

## [0.13.0] - 2026-07-10

### Added
- **Scaffold a matrix from an MCP server.** `overstep scaffold <url> --fmt mcp`
  connects to a live MCP server (`initialize` + `tools/list`) — or reads a saved
  `tools.json` — and drafts a full starter matrix: servers, roles, placeholder
  subjects, resources and a starter policy. Each tool is classified **object vs
  function** (an id-like argument becomes the `owner_arg` BOLA surface) and
  **mutating tools are detected automatically** from `annotations`
  (`destructiveHint` / `readOnlyHint`), falling back to a verb heuristic on the
  name, so `--read-only` skips them. `--server-name`, `--server-url` and `--token`
  tune the output. The bundled demo MCP server now advertises input schemas and
  annotations so live scaffolding works out of the box.

## [0.12.0] - 2026-07-10

### Added
- **MCP tool-call transport.** overstep can now test authorization on **MCP /
  agent tool-calls**, not just HTTP APIs. A resource sets `transport: mcp` and a
  `call: { server, tool, arguments }`; `servers:` declares the MCP endpoints. The
  same matrix, planner, classifier, markers/confidence, waivers, drift and reports
  apply — BOLA on a tool argument (`owner_arg`), BFLA/privilege-escalation on a
  tool a role shouldn't invoke, all mapped to the existing CWE/OWASP taxonomy.
  - Speaks **MCP over Streamable HTTP (JSON-RPC 2.0)** using the existing httpx
    client — no new dependency. Best-effort `initialize` handshake with session-id
    capture, then `tools/call`.
  - A dedicated **MCP oracle** (`McpMatcher`): since MCP has no `403`, allow/deny
    is decided from a JSON-RPC `error`, an `isError: true` result, and content
    regexes. The content-aware marker oracle scans the tool result, so a
    cross-owner read is a *confirmed* leak.
  - Identity reuses the subject's token/headers/auth providers; `--read-only`
    skips tools flagged `mutating`; findings carry an **MCP `tools/call` repro**.
  - `validate` checks MCP resources (`call`, known `server`, `owner_arg`).
  - A bundled intentionally-vulnerable demo MCP server and matrix under
    `examples/mcp_api/`.
- An all-MCP matrix no longer needs a `base_url` (it lives on `servers:`).

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
