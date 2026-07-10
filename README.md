# overstep

**Matrix-driven authorization testing for HTTP APIs and MCP tool-calls.**

![CI](https://img.shields.io/badge/CI-GitHub%20Actions-blue)
![License](https://img.shields.io/badge/license-Apache--2.0-green)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)

overstep takes a declarative **authorization matrix** — who is allowed to do what
— and turns it into concrete HTTP tests. It generates **positive** tests (access
that *should* succeed) and **negative** tests (access that *should* be denied),
runs them against a live target, and reports every negative test that slipped
through as an authorization vulnerability: **BOLA**, **BFLA**, **BOPLA** or
**privilege escalation**. Snapshot the results and CI fails the moment your
authorization surface **drifts**.

```
   authorization matrix  ──►  positive + negative tests  ──►  run  ──►  findings
   (subjects × resources)     (self/other, per role,          (BOLA/BFLA/BOPLA/
                               cross-method)                    privesc/drift)
```

Every finding is classified, mapped to its **CWE / OWASP API Top 10** entry,
graded by **confidence**, and shipped with a copy-pasteable **`curl` repro** —
so it lands in a dashboard or a ticket ready to act on.

The matrix, planning and classification are **transport-agnostic**: the same
matrix tests **HTTP APIs** and **MCP / agent tool-calls** behind a pluggable
transport registry (see [Testing MCP tool-calls](#testing-mcp--agent-tool-calls)
and [Transports & extensibility](#transports--extensibility)).

---

## Why a matrix?

Most authorization bugs aren't a missing `if` in one handler — they're a *cell*
in a table nobody wrote down. "Can a plain user delete another user's order?"
is a question about the intersection of a **role**, a **resource** and an
**ownership scope**. overstep makes that table explicit and tests every cell:

- **BOLA** (Broken Object Level Authorization) — a subject reaches *another
  subject's* object (`GET /orders/{id}` for an id they don't own).
- **BFLA** (Broken Function Level Authorization) — a subject invokes a function
  their role shouldn't have (`GET /admin/users` as a normal user).
- **BOPLA** (Broken Object Property Level Authorization) — an allowed response
  exposes a *field* the caller shouldn't see (`is_admin`, `password_hash`).
- **Privilege escalation** — a lower-privileged role reaches something reserved
  for a higher one.
- **Authorization drift** — a decision that changed since your last release,
  caught by comparing against a saved baseline.

## Install

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e .            # or: pip install -e ".[dev]" for tests + demo server
```

Or run it without installing anything, straight from the container image:

```bash
docker run --rm -v "$PWD:/work" -w /work ghcr.io/kabiri-labs/overstep \
    run matrix.yaml --out out
```

## Quickstart (bundled vulnerable demo)

```bash
# 1. Start the intentionally-vulnerable demo API
python -m uvicorn examples.mock_api.server:app --port 8000

# 2. In another shell, run the matrix against it
overstep run examples/mock_api/matrix.yaml --out out
```

You'll get a summary like:

```
         overstep summary
 Tests run              18
 Positive / negative    7 / 11
 Vulnerabilities        8
   BOLA                 2
   privilege-escalation 6
```

and reports in `out/`:

| File | For |
|---|---|
| `report.html` | humans — findings with evidence and repro |
| `findings.json` | scripts / dashboards (CWE + OWASP tagged) |
| `overstep.sarif` | GitHub code scanning |
| `junit.xml` | CI test reporters |

`overstep run` exits non-zero when it finds a vulnerability, so it fails a
pipeline out of the box.

## The authorization matrix

A matrix has three parts — **subjects** (who), **resources** (what) and
**policy** (the allow-list). Everything not explicitly allowed is denied.

```yaml
base_url: http://127.0.0.1:8000
roles: [anonymous, user, admin]        # least -> most privileged

subjects:
  - { name: alice, role: user,  token: alice-token, attributes: { user_id: u1 } }
  - { name: bob,   role: user,  token: bob-token,   attributes: { user_id: u2 } }
  - { name: root,  role: admin, token: admin-token, attributes: { user_id: u9 } }
  - { name: anon,  role: anonymous, token: null }

resources:
  - name: get_user
    request: { method: GET, path: "/users/{id}" }
    type: object            # object-level -> BOLA surface
    owner_param: id          # {id} must match the caller's user_id
    owner_attr: user_id
  - name: admin_list_users
    request: { method: GET, path: "/admin/users" }
    type: function          # function-level -> BFLA surface

policy:
  get_user:
    allow:
      - { role: user, scope: own }    # a user may read only their own object
      - { role: admin, scope: any }   # admins may read anyone's
  admin_list_users:
    allow:
      - { role: admin }               # admin-only
```

From this, overstep generates (`overstep plan examples/mock_api/matrix.yaml`):

| Expected | Request | Subject | Variant |
|---|---|---|---|
| allow | `GET /users/u1` | alice | self |
| **deny** | `GET /users/u2` | alice | other  ← BOLA probe |
| allow | `GET /users/u9` | root | self |
| allow | `GET /users/u1` | root | other |
| **deny** | `GET /admin/users` | alice | na  ← BFLA / privesc probe |
| allow | `GET /admin/users` | root | na |

## Sharper findings

### Confidence: proving a leak, not guessing from status

A `200` on a BOLA probe is not proof that data leaked — the endpoint might have
returned an empty list. Give each subject a **`marker`** (a string that uniquely
identifies *its* data), and overstep looks for the victim's marker in the
response before it trusts the status:

```yaml
subjects:
  - { name: alice, role: user, token: a, marker: "alice@example.com", attributes: { user_id: u1 } }
  - { name: bob,   role: user, token: b, marker: "bob@example.com",   attributes: { user_id: u2 } }
```

Findings are then graded:

- **confirmed** — the victim's data actually appeared in the response (a proven leak);
- **suspected** — access was granted but the owner data never showed up (downgraded
  to *medium* severity — likely an empty result, verify by hand);
- **unverified** — decided on status alone because no marker was configured.

### Reproduction on every finding

Each finding carries a copy-pasteable **`curl`** command and a structured request
record, with credentials masked so reports are safe to share:

```
curl -sS -X GET -H 'Authorization: Bearer ***' http://127.0.0.1:8000/users/u2
```

### BOPLA: forbidden response fields

Even an *allowed* read can over-share. List the JSON keys a response must never
contain and overstep reports a BOPLA when one appears (matching is key-based, so
a name in free text won't false-positive):

```yaml
resources:
  - name: get_user
    request: { method: GET, path: "/users/{id}" }
    type: object
    owner_param: id
    forbidden_fields: [password_hash, is_admin]
```

### Cross-method probing

A GET-only resource can hide a missing check on other verbs. `probe_methods`
fires each verb at *another* subject's object as a negative test — a success is a
missing method-level authorization:

```yaml
resources:
  - name: get_order
    request: { method: GET, path: "/orders/{id}" }
    type: object
    owner_param: id
    probe_methods: [PUT, DELETE]   # can a non-owner modify/delete it?
```

## Writing the policy

### Custom conditions

For finer rules (tenant isolation, attribute matching) an allow rule can carry a
safe boolean `condition` evaluated over `subject` and `target` attributes:

```yaml
policy:
  get_order:
    allow:
      - role: user
        condition: "subject.tenant == target.tenant"
```

Conditions run through a restricted AST evaluator — comparisons, boolean logic
and attribute/index access only. No function calls, no arbitrary names.

### Custom headers

By default each subject authenticates with `Authorization: Bearer <token>`. When
an endpoint needs more — a non-bearer auth scheme, an API key, a tenant header —
set headers on the **resource** (sent for every subject) and/or on the
**subject** (per identity). Subject headers override resource headers, and an
explicit `Authorization` header is never overwritten by the token:

```yaml
resources:
  - name: get_order
    request:
      method: GET
      path: "/orders/{id}"
      headers: { Accept: application/json, X-Api-Version: "2" }  # every request
    type: object
    owner_param: id

subjects:
  - name: alice
    role: user
    token: alice-token                 # -> Authorization: Bearer alice-token
    headers: { X-Tenant: t1 }          # extra per-subject header
    attributes: { user_id: u1 }
  - name: svc
    role: admin
    headers: { X-API-Key: "abc123" }   # custom auth, no bearer token
    attributes: { user_id: u9 }
```

### Deciding allow vs. deny (response matcher)

By default a `2xx` status means access was granted and anything else means it was
denied. That's wrong for APIs that redirect on success, return `200` with an
error body, or mask a `403` as a `404`. A **response matcher** makes the real
signal explicit. Set it matrix-wide under `access:` and/or override it per
resource:

```yaml
# matrix-wide default
access:
  allow_status: ["2xx"]             # exact codes, ranges ("200-299") or classes ("2xx")
  deny_body_regex: "access denied|not authorized"   # a 200 with this body -> deny
  treat_redirect_as: deny           # how to read a 3xx: deny | allow | status

resources:
  - name: start_export
    request: { method: POST, path: "/exports" }
    type: function
    access:
      allow_status: [200, 202]      # async accept counts as success
```

Evaluation order: `deny_body_regex` (wins, fails safe) → `allow_body_regex` →
redirect handling → `allow_status`. Body patterns are case-insensitive.

## Authentication (dynamic tokens & secrets)

Static tokens don't survive CI — they expire and shouldn't be committed. Two
features handle this:

**`${ENV}` interpolation.** Any `${VAR}` in the matrix is replaced from the
environment at load time (`${VAR:-default}` for a fallback); a missing variable
fails the run loudly instead of sending the literal string. Pass a dotenv file
with `--env-file`.

**Auth providers.** A subject can obtain its token by logging in before the run,
instead of carrying a static one. `type: http` posts an arbitrary login request
and reads the token out of the JSON response; `oauth2_client_credentials` and
`oauth2_password` build the standard token-endpoint form. Values may contain
`{{var}}` placeholders filled from each subject's `auth.vars`, so one provider
serves many identities:

```yaml
auth:
  providers:
    - name: login
      type: http                      # or oauth2_password / oauth2_client_credentials
      request:
        method: POST
        path: /auth/login
        body: { username: "{{U}}", password: "{{P}}" }
      token_path: "$.access_token"    # dotted path into the JSON response

subjects:
  - name: alice
    role: user
    auth: { provider: login, vars: { U: alice, P: "${ALICE_PASS}" } }  # secret from env
    attributes: { user_id: u1 }
```

`${...}` is resolved once from the environment; `{{...}}` is resolved per subject
at login time — so secrets come from the environment and never touch the file.

## Real objects: setup, captured ids & teardown

Meaningful BOLA testing needs a *real owned object* — the order that belongs to
alice, not her user id.

**`objects`** on a resource maps each subject to the id of the object it owns.
**`setup`** steps run once before the suite, as a chosen subject, and `extract`
values from their responses into a capture context that fills `{{name}}`
placeholders — including in `objects`. **`teardown`** steps run best-effort after
the suite (reusing those captures) to clean the fixtures up:

```yaml
setup:
  - name: alice creates an order
    as: alice                        # runs with alice's (dynamic) token
    request: { method: POST, path: /orders, body: { item: book } }
    extract: { ALICE_ORDER: "$.id" } # capture the new id
  - name: bob creates an order
    as: bob
    request: { method: POST, path: /orders, body: { item: pen } }
    extract: { BOB_ORDER: "$.id" }

resources:
  - name: get_order
    request: { method: GET, path: "/orders/{id}" }
    type: object
    owner_param: id
    objects: { alice: "{{ALICE_ORDER}}", bob: "{{BOB_ORDER}}" }

teardown:
  - { as: alice, request: { method: DELETE, path: "/orders/{{ALICE_ORDER}}" } }
  - { as: bob,   request: { method: DELETE, path: "/orders/{{BOB_ORDER}}" } }
```

Now `get_order::bob::other` fetches **alice's real order id**, so a `200` is a
genuine BOLA finding. A teardown failure is reported as a warning, never a run
failure.

Setup and teardown steps work over **MCP** too — give a step a `call:` (a
tool-call) instead of a `request:`, and `extract` reads the captured id out of the
tool result's JSON content:

```yaml
setup:
  - name: alice creates a document
    as: alice
    call: { server: docs, tool: create_document, arguments: { body: "notes" } }
    extract: { ALICE_DOC: "$.id" }     # capture the new id from the tool result
teardown:
  - { as: alice, call: { server: docs, tool: delete_document, arguments: { doc_id: "{{ALICE_DOC}}" } } }
```

## Running safely against live targets

- `--read-only` skips every mutating verb (POST/PUT/PATCH/DELETE) so the suite can
  be pointed at a sensitive environment without changing state.
- `--max-retries N` (default 2) retries `429`/`503` responses, honouring
  `Retry-After` and otherwise backing off with full jitter — so a large matrix
  doesn't trip a rate limiter into flaky failures.
- `--concurrency` bounds in-flight requests.

## Waivers: accepted risk without turning off gating

A reviewed, consciously-accepted finding shouldn't fail the pipeline forever nor
silence the tool. A waivers file names findings by their stable `test_id`, with a
mandatory reason and an optional expiry:

```yaml
# waivers.yaml
waivers:
  - id: get_order::alice::other
    vuln_class: BOLA
    reason: "Tracked in SEC-1234; fix scheduled next release."
    expires: 2026-12-31
```

```bash
overstep run matrix.yaml --waivers waivers.yaml
```

Waived findings move out of the gating set but stay visible in the reports. An
**expired** waiver stops suppressing and prints a warning, forcing re-review —
which keeps waivers distinct from a drift baseline.

## Commands

| Command | What it does |
|---|---|
| `overstep run MATRIX` | generate, execute and report; non-zero exit on findings |
| `overstep snapshot MATRIX` | record current decisions as a drift baseline |
| `overstep plan MATRIX` | print the generated test cases (no network) |
| `overstep validate MATRIX` | lint a matrix for structural problems |
| `overstep scaffold SPEC` | draft a `resources:` block (or a full matrix) from OpenAPI/HAR |

`run` flags: `--base`, `--out`, `--baseline`, `--waivers`, `--concurrency`,
`--read-only`, `--max-retries`, `--insecure`, `--env-file`, and
`--fail-on {vuln,drift,any,never}`.

## Bootstrapping a matrix from a spec

Don't write the resource list — or the policy — by hand:

```bash
# just the resources
overstep scaffold openapi.yaml --fmt openapi > resources.snippet.yaml
overstep scaffold traffic.har  --fmt har     > resources.snippet.yaml

# a full starter matrix (roles + subjects + policy) inferred from
# the spec's securitySchemes scopes and per-operation security
overstep scaffold openapi.yaml --with-policy > matrix.yaml
```

`--with-policy` turns each declared scope into a privilege-ordered role, gives
every secured endpoint an allow rule per required scope (object resources default
to owner-scope for non-admin roles), and marks unsecured endpoints public. Review
and tighten the result — it's a starting point, not a source of truth.

For MCP, scaffold straight from a live server's `tools/list`:

```bash
overstep scaffold http://host/mcp --fmt mcp > matrix.yaml
```

See [Testing MCP tool-calls](#testing-mcp--agent-tool-calls) for what it infers.

## CI / CD

overstep ships the artifacts a pipeline needs:

- **GitHub Action** — see [`examples/ci/github-actions.yml`](examples/ci/github-actions.yml);
  it runs the matrix and uploads SARIF to code scanning.
- **GitLab CI** — see [`examples/ci/gitlab-ci.yml`](examples/ci/gitlab-ci.yml).
- **Docker image** — `ghcr.io/kabiri-labs/overstep`.
- **pre-commit hook** — `overstep-validate` lints the matrix on every commit
  (see [`.pre-commit-hooks.yaml`](.pre-commit-hooks.yaml)).

### Catching authorization drift

Bake the known-good state into a baseline, then fail only when authorization
*changes*:

```bash
# once, after triaging findings
overstep snapshot examples/mock_api/matrix.yaml --out baseline.json

# on every pull request
overstep run examples/mock_api/matrix.yaml --baseline baseline.json --fail-on drift
```

A cell that flips from **deny → allow** is a newly opened hole; **allow → deny**
is a new restriction. Keep `matrix.yaml` and `baseline.json` in version control
and authorization gets reviewed like any other code.

## Finding taxonomy

Every class maps to its CWE and OWASP API Security Top 10 entry, carried in the
SARIF rules (with a `security-severity` score) and on every JSON finding:

| Class | CWE | OWASP API Top 10 |
|---|---|---|
| BOLA | CWE-639 | API1:2023 |
| BOPLA | CWE-213 | API3:2023 |
| BFLA | CWE-285 | API5:2023 |
| privilege-escalation | CWE-269 | API5:2023 |

## Testing MCP / agent tool-calls

The same matrix tests **MCP servers** (and the tool-calls an agent makes through
them), not just HTTP APIs. Authorization bugs map one-to-one: a subject reading
another subject's object via a tool argument is **BOLA**; invoking a tool its role
shouldn't is **BFLA / privilege escalation**. A resource sets `transport: mcp` and
a `call` instead of an HTTP `request`, and `servers:` declares the endpoints. Two
server kinds are supported — **Streamable HTTP** (`url:`) and **stdio** (`command:`,
a local process). Below is HTTP; for stdio see [Local (stdio) MCP servers](#local-stdio-mcp-servers).

```yaml
servers:
  - name: docs
    url: http://127.0.0.1:9000/mcp        # MCP over Streamable HTTP (JSON-RPC)

# MCP has no 403 — decide allow/deny from the tool result:
mcp_access:
  is_error_is_deny: true                  # a result with isError: true -> denied
  jsonrpc_error_is_deny: true             # a JSON-RPC error -> denied
  # deny_content_regex: "permission denied"

subjects:
  - { name: alice, role: user, token: alice-token, marker: "alice@corp", attributes: { doc_id: d-alice } }
  - { name: bob,   role: user, token: bob-token,   marker: "bob@corp",   attributes: { doc_id: d-bob } }

resources:
  - name: read_document
    transport: mcp
    call: { server: docs, tool: read_document }
    type: object            # BOLA surface on the tool argument
    owner_arg: doc_id        # overstep fills this with the caller's / a victim's object id
    owner_attr: doc_id
  - name: reset_tenant
    transport: mcp
    call: { server: docs, tool: reset_tenant, mutating: true }   # skipped under --read-only
    type: function          # BFLA / privesc surface
```

overstep performs a best-effort `initialize` handshake and then `tools/call` per
subject, using that subject's token/headers for identity. Because there is no
status code, the **marker** oracle matters more than in HTTP: when a cross-owner
tool-call returns the victim's marker, the BOLA is graded **confirmed**. Findings
carry an MCP `tools/call` repro, and `--read-only` skips `mutating` tools.

**Don't write the resources by hand** — scaffold them from the server's own
`tools/list`, with object/function type and mutating tools inferred automatically:

```bash
overstep scaffold http://127.0.0.1:9000/mcp --fmt mcp --server-name docs > matrix.yaml
# or from a saved tools/list response:  overstep scaffold tools.json --fmt mcp --server-url ...
```

An id-like tool argument becomes the `owner_arg` (the BOLA surface); a tool whose
`annotations` say `destructiveHint` (or whose name reads like a write) is marked
`mutating`. Review the starter policy, then run.

Try it against the bundled vulnerable MCP demo:

```bash
python -m uvicorn examples.mcp_api.server:app --port 9000
overstep run examples/mcp_api/matrix.yaml --out out
```

### OAuth-protected MCP servers

For a remote MCP server behind OAuth 2.1, an auth provider can **discover** where
to authenticate instead of hardcoding a token endpoint. overstep reads the
server's Protected Resource Metadata (RFC 9728) to find its authorization server,
then the Authorization Server Metadata (RFC 8414) to find the token endpoint,
obtains a token with a machine grant, and sends the resource indicator (RFC 8707)
so the token is bound to that server:

```yaml
auth:
  providers:
    - name: mcp_oauth
      type: oauth2_client_credentials
      discover_from: docs            # the MCP server name (or a URL)
      client_id: "{{client_id}}"     # per-subject via auth.vars
      client_secret: "${CLIENT_SECRET}"

subjects:
  - name: svc-a
    role: user
    auth: { provider: mcp_oauth, vars: { client_id: svc-a } }
```

The discovered, audience-bound token is set on the subject and used for its
tool-calls. (The interactive authorization-code flow needs a browser and is out
of scope for an automated tool.)

### Local (stdio) MCP servers

For a server that runs as a local process, declare a `command` instead of a
`url`. overstep launches the process itself — one per subject — and speaks
JSON-RPC over stdin/stdout. There is no HTTP header for identity on stdio, so the
subject's token is injected into the process **environment** via `token_env`:

```yaml
servers:
  - name: docs
    command: ["python", "server.py"]   # a local MCP server
    token_env: MCP_TOKEN                # each subject's token -> this env var
```

Everything else is identical — object/function resources, `owner_arg`, markers,
`--read-only` (skips `mutating` tools), reports. Findings carry a stdio repro
(masked env + command + the JSON-RPC call). Try the bundled stdio demo:

```bash
overstep run examples/mcp_api/matrix_stdio.yaml --out out
```

> This tests the **server's** enforcement directly and deterministically.
> Driving the *agent* with natural-language prompts (confused-deputy /
> prompt-injection) is a separate, non-deterministic concern and out of scope.

## Transports & extensibility

overstep separates *what* it tests (the matrix, the planned self/other and
cross-method probes, the BOLA/BFLA/BOPLA/privesc classification, the reports) from
*how* a request is delivered. Delivery lives behind a **transport registry**
(`overstep.transports`) — the same pluggable pattern as the reporters. A resource
picks its transport; everything downstream is unchanged:

```yaml
resources:
  - name: get_user
    transport: http            # the default; may be omitted
    request: { method: GET, path: "/users/{id}" }
    type: object
    owner_param: id
```

A single run can mix transports: the dispatcher groups the planned cases by their
`transport` and routes each group to the matching executor. `overstep validate`
flags a resource whose `transport` is not registered. The built-in transports are
`http` and `mcp` (see [Testing MCP tool-calls](#testing-mcp--agent-tool-calls));
the registry is the seam any further target plugs into without changing the core.

## Comparison

| Capability | overstep | Burp Autorize / AuthMatrix | Schemathesis |
|---|---|---|---|
| Authorization matrix as code | ✅ | ⚠️ (per-request, manual) | ❌ |
| Positive **and** negative tests | ✅ | ⚠️ | ⚠️ |
| BOLA / BFLA / BOPLA / privesc classification | ✅ | ⚠️ | ❌ |
| HTTP **and** MCP tool-call authorization | ✅ | ❌ | ❌ |
| Content-verified findings + repro | ✅ | ⚠️ | ❌ |
| Drift baselines & waivers for CI | ✅ | ❌ | ❌ |
| SARIF (CWE/OWASP) + JUnit output | ✅ | ❌ | ⚠️ |

> ⚠️ means possible only with significant manual effort.

## crAPI demo

See [`examples/crapi`](examples/crapi/README.md) to run overstep against OWASP
crAPI for a realistic BOLA/BFLA showcase.

## License

Apache-2.0.
