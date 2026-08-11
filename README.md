# overstep

**Matrix-driven authorization testing for HTTP APIs and MCP tool-calls.**

![Version](https://img.shields.io/badge/version-0.27.1-blue)
![CI](https://img.shields.io/badge/CI-GitHub%20Actions-blue)
![License](https://img.shields.io/badge/license-Apache--2.0-green)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)

You write down who is allowed to do what. overstep turns that table into concrete
requests — **positive** tests for access that should succeed and **negative**
tests for access that should be denied — fires them at a running target, and
reports every negative test that got through as an authorization vulnerability.

```
   authorization matrix  ──►  positive + negative tests  ──►  run  ──►  findings
   (subjects × resources)     (self/other, per role,          (BOLA/BFLA/BOPLA/
                               cross-method)                    privesc/drift)
```

Findings are classified, mapped to **CWE / OWASP API Top 10**, graded by
**confidence** (did the victim's data actually come back?), and shipped with a
`curl` command that reproduces them. Snapshot the results and CI fails the moment
your authorization surface **drifts**.

The matrix, the planning and the classification are **transport-agnostic**: the
same file tests an HTTP API and an [MCP server](#testing-mcp--agent-tool-calls).

---

**Contents**

[What overstep finds](#what-overstep-finds) ·
[What it doesn't do](#what-it-doesnt-do) ·
[Install](#install) ·
[Quickstart](#quickstart-the-bundled-demo) ·
[**Point it at your own API**](#point-it-at-your-own-api) ·
[The matrix](#the-authorization-matrix) ·
[Trustworthy findings](#making-findings-trustworthy) ·
[Modelling a real API](#modelling-a-real-api) ·
[MCP tool-calls](#testing-mcp--agent-tool-calls) ·
[Running in CI](#running-in-ci) ·
[Command reference](#command-reference) ·
[Taxonomy](#finding-taxonomy) ·
[Transports](#transports--extensibility) ·
[Comparison](#comparison)

---

## What overstep finds

Most authorization bugs aren't a missing `if` in one handler — they're a *cell*
in a table nobody wrote down. "Can a plain user delete another user's order?" is
a question about the intersection of a **role**, a **resource** and an **ownership
scope**. overstep makes that table explicit and tests every cell.

| Class | What it means | Example probe |
|---|---|---|
| **BOLA** | a subject reaches *another subject's* object | `GET /orders/{id}` for an id they don't own |
| **BFLA** | a subject invokes a function their role shouldn't have | `GET /admin/users` as a normal user |
| **BOPLA** | an allowed response exposes a *field* the caller shouldn't see | `password_hash` in a user record |
| **Privilege escalation** | a lower-privileged role reaches something reserved for a higher one | a `member` deleting a project |
| **Authorization drift** | a decision that changed since your last release | a cell that flipped deny → allow |

## What it doesn't do

Knowing the edges is part of deciding whether this fits:

- **It doesn't discover your API.** You declare the surface; `scaffold` drafts it
  from an OpenAPI spec, a HAR capture or a live MCP server, but you review it.
- **It doesn't invent your policy.** The matrix *is* the specification. A wrong
  matrix produces wrong results — `validate`, the plan table and the
  [inconclusive-run check](#inconclusive-runs-the-gate-refuses-to-fail-open)
  exist to catch the common mistakes, not to guess your intent.
- **It doesn't test authentication.** Login strength, token forgery and session
  fixation are out of scope; overstep tests what an *already authenticated*
  identity is permitted to do.
- **It doesn't fuzz.** Every request is one the matrix asked for, which is what
  makes results deterministic and diffable.
- **It doesn't drive an agent with natural-language prompts.** For MCP it tests
  the **server's** enforcement directly. Confused-deputy and prompt-injection
  attacks against the agent are a separate, non-deterministic concern.
- **It sends real requests.** Use [`--read-only`](#running-safely-against-live-targets)
  against anything you care about.

## Install

```bash
pip install overstep
overstep version
```

Or run it without installing anything:

```bash
docker run --rm -v "$PWD:/work" -w /work ghcr.io/kabiri-labs/overstep \
    run matrix.yaml --out out
```

To work on overstep itself, or to run the bundled demo below, clone the repo and
install it editable — see [CONTRIBUTING.md](CONTRIBUTING.md):

```bash
git clone https://github.com/kabiri-labs/overstep && cd overstep
pip install -e ".[dev]"
```

## Quickstart: the bundled demo

Two minutes, against an intentionally-vulnerable API that ships with the repo.

```bash
# 1. start the demo API
python -m uvicorn examples.mock_api.server:app --port 8000

# 2. in another shell, run the matrix against it
overstep run examples/mock_api/matrix.yaml --out out
```

```
             overstep summary
 Tests run                            18
 Positive / negative               7 / 11
 Vulnerabilities            8 (3 defects)
   BOLA                                2
   privilege-escalation                6
 Object resources probed             2/2
```

Eight probes got through, and they trace back to **three** distinct bugs — one
row per thing to fix, with the subjects that reached it as evidence. Reports land
in `out/`:

| File | For |
|---|---|
| `report.html` | humans — findings with evidence and repro |
| `findings.json` | scripts / dashboards (CWE + OWASP tagged) |
| `overstep.sarif` | GitHub code scanning |
| `junit.xml` | CI test reporters |

`overstep run` exits non-zero when it finds a vulnerability, so it fails a
pipeline out of the box.

## Point it at your own API

The demo proves the tool runs. This is the part that matters — six steps from a
spec to a result you can trust.

Each command ends by naming the next one on `stderr`, so the sequence does not
have to be memorised:

```
next: overstep validate matrix.yaml --live — check the target answers and every
credential still works
```

Set `OVERSTEP_NO_HINTS=1` to switch them off; a pipeline knows its own next step.

### 1. Draft the matrix

```bash
overstep scaffold openapi.yaml --with-policy > matrix.yaml   # OpenAPI
overstep scaffold traffic.har  --fmt har     > resources.yaml # or a HAR capture
overstep scaffold http://host/mcp --fmt mcp  > matrix.yaml   # or a live MCP server
```

`--with-policy` reads the spec's own `security` declarations to draft the policy,
not just the endpoint list:

| What the spec says about an operation | What you get |
|---|---|
| requires named scopes | an allow rule per scope; object resources default to owner-scope for non-admin roles |
| requires a credential but **no** scope (plain bearer, api key) | allowed to any authenticated role — anonymous is what the spec rules out |
| deliberately unprotected, in a spec that secures other operations | public (allow `anonymous`) |
| **nothing at all** — no `security`, no `securitySchemes` | a **deny-by-default guess**, behind a warning header and a warning on stderr |

That last row matters. Reading an authorization-silent spec as "everything is
public" would produce a matrix with **zero negative tests**, which reports a clean
run against a broken API. Guessing tight instead means an unmodified scaffold
*over*-reports — expect `unexpected-deny` findings for access that is genuinely
allowed, and loosen the rules as you confirm them.

### 2. Fill in the placeholders

The scaffold leaves `PASTE_..._TOKEN` and `REPLACE_ME_1` / `REPLACE_ME_2` where it
cannot know the answer. Two things to get right:

- **Give the two peer subjects genuinely different objects.** A cross-owner probe
  only exists when two subjects own *different* things; filling both placeholders
  with the same id silently removes every BOLA test.
- **Keep secrets out of the file** — write `${ALICE_TOKEN}` and pass the value
  through the environment or `--env-file`. See
  [Authentication](#authentication-dynamic-tokens--secrets).

### 3. Lint it

```bash
overstep validate matrix.yaml
```

This catches the mistakes that would otherwise produce a confidently wrong run,
and separates the two kinds:

- **`error:`** — the matrix cannot produce a trustworthy result. A policy naming
  an unknown role, an injection pointing at a path parameter that doesn't exist,
  or a `PASTE_..._TOKEN` / `REPLACE_ME` placeholder left over from `scaffold`.
  Each one is reported with the line number to edit and what to put there.
  Exits `1`.
- **`warning:`** — the run will happen and its findings will be real, but it
  tests less than its size suggests: a resource with no policy entry (denied by
  default), or subjects that all resolve to the same object so no BOLA probe can
  be generated. Exits `0`; pass `--strict` to fail on these too.

Placeholders are worth the loudest of those, because leaving one in does not
half-configure a run — it kills it. Every credential is rejected, so every
expected-allow test fails and every expected-deny test "passes" for the wrong
reason. `run` prints the same lines before it sends its first request.

Two things the file cannot tell you — whether the target answers, and whether
each credential is still accepted — need the target itself:

```bash
overstep validate matrix.yaml --live
```

```
error: subject 'alice' was denied GET /users/u1 (HTTP 401), which the matrix
expects to be allowed — its credential is rejected or expired, or the policy is
wrong; every negative result for it would be meaningless
```

`--live` sends **one** request per subject: an expected-*allow* case, which is by
definition a request the matrix says that subject may make, so seeing it allowed
is the cheapest proof the identity works. This is the same judgement the
[inconclusive-run check](#inconclusive-runs-the-gate-refuses-to-fail-open) makes
afterwards, asked first and answered per subject — an expired token becomes
"alice is rejected" before the run instead of "the credentials or the matrix are
wrong" after it.

It is side-effect free: probes go out `--read-only`, and non-mutating verbs are
preferred, so a subject whose only positive control is a `DELETE` is reported as
unverifiable rather than verified destructively. Setup steps are not run either,
for the same reason. Anonymous subjects are not flagged — carrying no credential,
having nothing to verify is their normal shape.

### 4. Read the plan before sending anything

```bash
overstep plan matrix.yaml
```

`plan` prints every request it *would* send, with the decision the matrix expects,
and touches the network zero times. If a row looks wrong here, the matrix is
wrong — fix it before you point this at a real system.

### 5. Run it

```bash
overstep run matrix.yaml --out out --read-only     # drop --read-only once you trust it
```

### 6. Tighten the loop

An `unexpected-deny` finding means the matrix claims access that the API refuses:
usually your policy is stricter than reality, occasionally the API is broken.
Either way, resolve it — a matrix that matches reality is what makes the *next*
run's silence meaningful. Then take a [baseline](#catching-authorization-drift)
and let CI gate on change.

## The authorization matrix

Three parts — **subjects** (who), **resources** (what) and **policy** (the
allow-list). Everything not explicitly allowed is denied.

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
    owner_param: id         # {id} must match the caller's user_id
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

`overstep plan` expands that into eleven cases — every subject against every
resource:

| Expected | Request | Subject | Variant | |
|---|---|---|---|---|
| allow | `GET /users/u1` | alice | self | |
| **deny** | `GET /users/u2` | alice | other | ← BOLA probe |
| allow | `GET /users/u2` | bob | self | |
| **deny** | `GET /users/u1` | bob | other | ← BOLA probe |
| allow | `GET /users/u9` | root | self | |
| allow | `GET /users/u1` | root | other | admins may read anyone's |
| **deny** | `GET /users/u1` | anon | other | ← unauthenticated probe |
| **deny** | `GET /admin/users` | alice | na | ← BFLA / privesc probe |
| **deny** | `GET /admin/users` | bob | na | |
| allow | `GET /admin/users` | root | na | |
| **deny** | `GET /admin/users` | anon | na | |

Every **deny** row is a probe: if the API answers it successfully, that's a
finding. Every **allow** row is a control: if the API refuses it, either your
matrix or your API is wrong, and overstep reports it as `unexpected-deny`.

## Making findings trustworthy

A tool that cries wolf gets switched off. These are the features that decide
whether a finding is real.

### Confidence: proving a leak, not guessing from status

A `200` on a BOLA probe is not proof that data leaked — the endpoint might have
returned an empty list. Give each subject a **`marker`** (a string that uniquely
identifies *its* data) and overstep looks for the victim's marker in the response
before it trusts the status:

```yaml
subjects:
  - { name: alice, role: user, token: a, marker: "alice@example.com", attributes: { user_id: u1 } }
  - { name: bob,   role: user, token: b, marker: "bob@example.com",   attributes: { user_id: u2 } }
```

- **confirmed** — the victim's data actually appeared in the response (a proven leak);
- **suspected** — access was granted but the owner's data never showed up
  (downgraded to *medium* — likely an empty result, verify by hand);
- **unverified** — decided on status alone, because no marker was configured.

### One defect, not one finding per user

A missing check is reported once per identity that reaches it, so one bug can
arrive as a dozen findings — triage cost that scales with the size of your matrix
instead of the number of bugs. Every report therefore carries a **defect**
roll-up: one row per thing to fix, with the subjects as evidence of blast radius.

```
Vulnerabilities   11 (3 defects)
```

`findings.json` gains a `defects` array (worst first, each with its `subjects`,
`findings` count and an `example_test_id`), the HTML report leads with a
**Defects** table, and every finding carries its `group` key so a dashboard can
collapse them the same way. Nothing is filtered — the full finding list is still
there, and gating still counts findings.

### A repro that actually runs

Each finding carries a `curl` command and a structured request record. The
credential is replaced by a shell variable named after the subject it belongs to,
so the line is safe to paste into a ticket **and** still works:

```bash
export OVERSTEP_TOKEN_ALICE=...     # the only thing that's missing
curl -sS -X GET -H "Authorization: Bearer $OVERSTEP_TOKEN_ALICE" \
    http://127.0.0.1:8000/users/u2
```

A bare `***` would be safe too, but it turns the repro into a command that
answers `401`. Each subject gets its own variable (`OVERSTEP_TOKEN_<SUBJECT>`, or
`OVERSTEP_<HEADER>_<SUBJECT>` for a non-bearer secret) so a repro can never
authenticate as the wrong identity. stdio MCP repros do the same with the
server's token environment variable.

### BOPLA: forbidden response fields

Even an *allowed* read can over-share. List the JSON keys a response must never
contain; matching is key-based, so a name appearing in free text won't
false-positive:

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
    probe_methods: [PUT, DELETE]   # can a non-owner modify or delete it?
```

### How many victims each subject probes

By default every subject sends **one** cross-owner probe. That catches a check
that is missing outright, cheaply. It does not catch a check that holds for *some*
owners and not others — a tenant whose ACL rows were never backfilled, a legacy
record with no owner column — because the one object a subject happens to reach
for may be the one that *is* protected.

```yaml
probe_victims: all          # matrix-wide

resources:
  - name: get_report
    probe_victims: all      # or per resource
```

`all` sends one probe per **distinct** object instead. Victims holding the same
object still count once, so this is not a blind N²: it costs nothing extra on a
matrix where subjects share objects, and grows only where there are genuinely
distinct objects to reach. Test ids are unchanged wherever a subject still probes
a single object, so existing drift baselines stay comparable; only the ids that
genuinely multiply gain a `@victim` suffix.

The **other** variant always targets a subject whose object genuinely differs.
Subjects can legitimately share one — two members of a tenant, a service account
and the user it acts for — and pairing a subject with such a peer would re-send
its own request under a different name: a probe that proves nothing while counting
as BOLA coverage. When no subject owns a different object the probe is dropped
rather than faked, and `validate` says so:

```
• object resource 'get_project' has no two subjects with different objects
  (all resolve to p-1), so no cross-owner BOLA probe can be generated;
  give at least two subjects distinct objects
```

## Modelling a real API

Everything above assumes a tidy API. This section covers what real ones do.

### Custom conditions

For finer rules — tenant isolation, attribute matching — an allow rule can carry
a boolean `condition` evaluated over `subject` and `target` attributes:

```yaml
policy:
  get_order:
    allow:
      - role: user
        condition: "subject.tenant == target.tenant"
```

Conditions run through a restricted AST evaluator: comparisons, boolean logic and
attribute/index access only. No function calls, no arbitrary names.

### Custom headers

By default each subject authenticates with `Authorization: Bearer <token>`. When
an endpoint needs more — a non-bearer scheme, an API key, a tenant header — set
headers on the **resource** (sent for every subject) and/or on the **subject**
(per identity). Subject headers override resource headers, and an explicit
`Authorization` header is never overwritten by the token:

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

By default `2xx` means access was granted and anything else means it was denied.
That's wrong for APIs that redirect on success, return `200` with an error body,
or mask a `403` as a `404`. A **response matcher** makes the real signal explicit,
matrix-wide under `access:` and/or per resource:

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
      allow_status: [200, 202]      # an async accept counts as success
```

Evaluation order: `deny_body_regex` (wins, fails safe) → `allow_body_regex` →
redirect handling → `allow_status`. Body patterns are case-insensitive.

### Authentication: dynamic tokens & secrets

Static tokens don't survive CI — they expire and shouldn't be committed.

**`${ENV}` interpolation.** Any `${VAR}` in the matrix is replaced from the
environment at load time (`${VAR:-default}` for a fallback); a missing variable
fails the run loudly instead of sending the literal string. Pass a dotenv file
with `--env-file`.

**Auth providers.** A subject can obtain its token by logging in before the run.
`type: http` posts an arbitrary login request and reads the token out of the JSON
response; `oauth2_client_credentials` and `oauth2_password` build the standard
token-endpoint form. Values may contain `{{var}}` placeholders filled from each
subject's `auth.vars`, so one provider serves many identities:

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

`${...}` resolves once from the environment; `{{...}}` resolves per subject at
login time — so secrets come from the environment and never touch the file.

### Real objects: setup, captured ids & teardown

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

Setup and teardown work over **MCP** too — give a step a `call:` instead of a
`request:`, and `extract` reads the captured id out of the tool result's JSON:

```yaml
setup:
  - name: alice creates a document
    as: alice
    call: { server: docs, tool: create_document, arguments: { body: "notes" } }
    extract: { ALICE_DOC: "$.id" }     # capture the new id from the tool result
teardown:
  - { as: alice, call: { server: docs, tool: delete_document, arguments: { doc_id: "{{ALICE_DOC}}" } } }
```

### Where the object id lives: injections

The identifier of the object a subject reaches for is the BOLA surface — but it
isn't always a path parameter. Real APIs carry it in a query string, a header, a
cookie, a form field, a JSON body, GraphQL variables, or an MCP tool argument.
`ownership.injections` says where to write it; overstep fills each location with
the caller's own object (SELF) or a victim's (OTHER), so the same probe works
wherever the id travels.

```yaml
resources:
  - name: get_order
    request: { method: GET, path: /orders }   # the id is NOT in the path
    type: object
    objects: { alice: order-a1, bob: order-b1 }
    ownership:
      injections:
        - location: query                     # -> GET /orders?order_id=order-b1
          selector: order_id
```

`location` is one of `path`, `query`, `header`, `cookie`, `form`, `json`,
`graphql_variables` or `mcp_argument`. `selector` is read per location: a path
parameter name, a query/header/cookie/form key, a JSONPath into the JSON body
(`$.order.id`, nested objects and arrays supported), a variable name (or
`$.path`) for GraphQL, or a tool-argument key. A `form` injection sends an
`application/x-www-form-urlencoded` body.

List several injections to exercise an object addressed in more than one place at
once, and set `owner_attr` on an injection to source it from a different subject
attribute (the tenant, say) than the object id:

```yaml
    ownership:
      injections:
        - { location: header, selector: X-Account-ID }                 # the object id
        - { location: header, selector: X-Tenant, owner_attr: tenant } # the caller's tenant
```

The shortcuts still work unchanged: `owner_param: id` is exactly a single `path`
injection, and `owner_arg: doc_id` (MCP) a single `mcp_argument` injection. An
object resource must declare at least one locator; `validate` flags an injection
whose location doesn't match the transport, a `path` selector that isn't a
parameter of the path, and an object no subject can resolve — so overstep never
falls back to a placeholder id. A full example lives in
[`examples/injections/matrix.yaml`](examples/injections/matrix.yaml).

## Testing MCP / agent tool-calls

The same matrix tests **MCP servers** and the tool-calls an agent makes through
them. The bugs map one-to-one: a subject reading another subject's object via a
tool argument is **BOLA**; invoking a tool its role shouldn't is **BFLA /
privilege escalation**.

A resource sets `transport: mcp` and a `call` instead of an HTTP `request`, and
`servers:` declares the endpoints. Two server kinds are supported — **Streamable
HTTP** (`url:`) and **stdio** (`command:`, a local process). Below is HTTP; for
stdio see [Local (stdio) MCP servers](#local-stdio-mcp-servers).

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
    owner_arg: doc_id       # filled with the caller's / a victim's object id
    owner_attr: doc_id
  - name: reset_tenant
    transport: mcp
    call: { server: docs, tool: reset_tenant, mutating: true }   # skipped under --read-only
    type: function          # BFLA / privesc surface
```

overstep performs a best-effort `initialize` handshake and then `tools/call` per
subject, using that subject's token and headers for identity. Because there is no
status code, the **marker** oracle matters more than in HTTP: when a cross-owner
tool-call returns the victim's marker, the BOLA is graded **confirmed**. Findings
carry an MCP `tools/call` repro, and `--read-only` skips `mutating` tools.

**Don't write the resources by hand** — scaffold them from the server's own
`tools/list`, with object/function type and mutating tools inferred:

```bash
overstep scaffold http://127.0.0.1:9000/mcp --fmt mcp --server-name docs > matrix.yaml
# or from a saved tools/list response:
overstep scaffold tools.json --fmt mcp --server-url http://127.0.0.1:9000/mcp
```

An id-like tool argument becomes the `owner_arg` (the BOLA surface); a tool whose
`annotations` say `destructiveHint` — or whose name reads like a write — is marked
`mutating`. Review the starter policy, then run.

Try it against the bundled vulnerable MCP demo:

```bash
python -m uvicorn examples.mcp_api.server:app --port 9000
overstep run examples/mcp_api/matrix.yaml --out out
```

### OAuth-protected MCP servers

For a remote MCP server behind OAuth 2.1, a provider can **discover** where to
authenticate instead of hardcoding a token endpoint. overstep reads the server's
Protected Resource Metadata (RFC 9728) to find its authorization server, then the
Authorization Server Metadata (RFC 8414) to find the token endpoint, obtains a
token with a machine grant, and sends the resource indicator (RFC 8707) so the
token is bound to that server:

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
tool-calls. The interactive authorization-code flow needs a browser and is out of
scope for an automated tool.

### Local (stdio) MCP servers

For a server that runs as a local process, declare a `command` instead of a
`url`. overstep launches the process itself — one per subject — and speaks
JSON-RPC over stdin/stdout. There is no HTTP header for identity on stdio, so the
subject's token is injected into the process **environment** via `token_env`:

```yaml
servers:
  - name: docs
    command: ["python", "server.py"]   # a local MCP server
    token_env: MCP_TOKEN               # each subject's token -> this env var
```

Everything else is identical — object/function resources, `owner_arg`, markers,
`--read-only`, reports. Findings carry a stdio repro (masked env + command + the
JSON-RPC call). Try the bundled stdio demo:

```bash
overstep run examples/mcp_api/matrix_stdio.yaml --out out
```

## Running in CI

### Running safely against live targets

- `--read-only` skips every mutating verb (POST/PUT/PATCH/DELETE) so the suite can
  be pointed at a sensitive environment without changing state.
- `--max-retries N` (default 2) retries `429`/`503`, honouring `Retry-After` and
  otherwise backing off with full jitter — so a large matrix doesn't trip a rate
  limiter into flaky failures.
- `--concurrency N` bounds in-flight requests.

### Gating with `--fail-on`

| Value | Exits non-zero when… |
|---|---|
| `vuln` (default) | there is an active, non-waived vulnerability (BOLA/BFLA/BOPLA/privilege escalation) |
| `drift` | a decision changed versus the `--baseline` — **only** drift, ignoring pre-existing findings |
| `vuln-or-drift` | either a vulnerability **or** drift is present |
| `any` | any active finding exists (including functional `unexpected-deny` regressions) |
| `never` | always exits zero (report-only) |

An unrecognized value fails immediately with exit code 2. Use `vuln` on a fresh
target to block new holes, and `drift` once you have a triaged baseline so CI
gates on *change* rather than on a backlog of accepted risk.

### Inconclusive runs: the gate refuses to fail open

A run only means something if the requests reached the target and the credentials
were accepted. When they didn't, every negative test "passes" for the wrong
reason — nothing was allowed because nothing got through — and a naive summary
reads `Vulnerabilities 0`. A security gate that goes green because the API never
started is worse than no gate at all, so overstep calls that run **inconclusive**
and exits **3**:

```
inconclusive run — a clean result here would be meaningless:
  • 55 of 55 requests never reached the target (first failure: All connection
    attempts failed) — it is unreachable, so these results say nothing about
    authorization
```

A run is inconclusive when, **for any one target**, either

- **unreachable** — at least half its requests failed at the transport layer
  (target down, wrong `--base`, a dead stdio server, DNS or TLS failure);
- **unverified** — nothing proves the credentials work: every expected-*allow*
  test was skipped (`--read-only` on an all-mutating surface), or none of the ones
  that ran was allowed — which is what expired tokens, a bad `--env-file` or a
  scaffolded matrix still holding its `PASTE_..._TOKEN` placeholders look like.

The judgement is **per target**, not over the run as a whole. A matrix can span an
HTTP API and several MCP servers, and aggregating them would let a busy healthy
target outvote a small one that answered nothing, so the verdict names the target
that failed:

```
inconclusive run — a clean result here would be meaningless:
  • MCP server http://127.0.0.1:9999/mcp: 4 of 4 requests never reached the
    target (first failure: All connection attempts failed) — it is unreachable
```

A target with no expected-allow tests at all is not condemned: an intentionally
all-negative matrix has no positive control to lose.

Exit code 3 is distinct from 1 (findings) and 2 (bad input), so CI can tell "your
API has an authorization hole" apart from "the scan never ran". The verdict does
**not** depend on `--fail-on` — that flag governs findings and cannot vouch for a
run that never happened — and it travels in `findings.json` under
`summary.inconclusive` so a dashboard doesn't read an empty run as a clean one.
Pass `--allow-inconclusive` to report anyway and keep the old exit code.

`snapshot` applies the same check and **refuses to write the baseline**: one
recorded against a dead target says "everything is denied", which would report the
next healthy run as wholesale authorization drift.

### Coverage: what a clean result is allowed to mean

Two different absences make `Vulnerabilities 0` mean less than it looks like, and
neither shows up in a finding count. `overstep coverage` reports both, and sends
nothing:

```bash
overstep coverage matrix.yaml --spec openapi.yaml
```

```
              API surface
 Operations in the spec              140
 Declared in the matrix       92/140 (66%)

note: 48 operation(s) are in the spec but not in the matrix, so no run says
anything about them:
  • POST /orders
  • DELETE /orders/{id}
  ...

            Object surface
 Object resources                     31
 Probed across owners        28/31 (90%)
```

The **API surface** is the outer gap. The matrix *is* the specification, so an
operation nobody declared is invisible by construction — no run sends it, and
nothing in the findings mentions it. The only way to see it is to compare the
matrix against an independent description of the API: `--spec` takes OpenAPI
(default), a HAR capture (`--fmt har`), or an MCP server or `tools.json`
(`--fmt mcp`).

Parameter *names* are the matrix author's choice, not the API's, so a spec
writing `/users/{user_id}` and a matrix writing `/users/{id}` match. Resources
the spec doesn't mention are listed too — usually an undocumented endpoint or a
stale spec, occasionally a mistyped path, which shows up as one gap and one
stray.

`--fail-under N` exits `1` when either percentage falls below `N`, so coverage
can gate a pipeline instead of only describing one.

### Probe coverage: what a clean result is allowed to mean

The inconclusive check answers "did this run happen at all". Coverage answers the
question after it: **of the object surface you declared, how much could this run
actually ask about?**

A cross-owner probe — one subject reaching for another subject's object — is the
only thing that tests BOLA. The planner generates one only when two subjects
resolve to genuinely *different* objects; when they don't, it drops the probe
rather than replaying the subject's own request under a different label, which
would manufacture a pass. That is the right call, but it used to leave no trace:
a resource nobody probed and a resource probed and found clean both contributed
`0` to the finding count.

So the run says so, in the summary, on the plan, and in `findings.json`:

```
 Object resources probed             2/3

note: no cross-owner probe was generated for 1 object resource(s), so this run
says nothing about BOLA on them:
  • get_invoice
  give at least two subjects different objects (an 'objects:' entry, or the
  owner attribute)
```

`overstep plan` prints the same note without touching the network, which is where
it is cheapest to act on. `validate` warns about the matrix-level cause.

Only a probe with a real victim counts. When *nobody* can resolve an object for a
resource, the planner still emits a request so the endpoint is exercised — but it
reaches for a default id belonging to no subject, and coverage does not count it.

This is the same principle as the inconclusive check, one level up: reporting the
absence of a finding is worth something only if you can show the run could have
seen it.

### Catching authorization drift

Bake the known-good state into a baseline, then fail only when authorization
*changes*:

```bash
# once, after triaging findings
overstep snapshot matrix.yaml --out baseline.json

# on every pull request
overstep run matrix.yaml --baseline baseline.json --fail-on drift
```

A cell that flips **deny → allow** is a newly opened hole; **allow → deny** is a
new restriction. Findings that were already present when you took the baseline
don't fail the build — that's what lets a legacy target adopt overstep without an
impossible green-from-day-one requirement. Use `--fail-on vuln-or-drift` when you
also want any vulnerability to fail regardless of the baseline. Keep `matrix.yaml`
and `baseline.json` in version control and authorization gets reviewed like any
other code.

Because `snapshot` runs through the same pipeline as `run`, baselines are accurate
for MCP and mixed matrices too, and `teardown:` fixtures are cleaned up after the
snapshot is taken.

### Waivers: accepted risk without turning off gating

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
which is what keeps waivers distinct from a drift baseline.

### Pipeline artifacts

- **GitHub Action** — [`examples/ci/github-actions.yml`](examples/ci/github-actions.yml)
  runs the matrix and uploads SARIF to code scanning.
- **GitLab CI** — [`examples/ci/gitlab-ci.yml`](examples/ci/gitlab-ci.yml).
- **Docker image** — `ghcr.io/kabiri-labs/overstep`.
- **pre-commit hook** — `overstep-validate` lints the matrix on every commit
  (see [`.pre-commit-hooks.yaml`](.pre-commit-hooks.yaml)).

## Command reference

| Command | What it does |
|---|---|
| `overstep run MATRIX` | generate, execute and report; non-zero exit on findings |
| `overstep snapshot MATRIX` | record current decisions as a drift baseline |
| `overstep plan MATRIX` | print the generated test cases (no network) |
| `overstep coverage MATRIX` | report what the matrix covers, vs. `--spec` and vs. its own object surface (no network) |
| `overstep validate MATRIX` | lint a matrix for structural problems and unfilled placeholders (`--live` also probes the target; `--strict` fails on warnings) |
| `overstep scaffold SPEC` | draft a `resources:` block, or a full matrix, from OpenAPI/HAR/MCP |
| `overstep version` | print the installed version |

| Flag | `run` | `snapshot` | Meaning |
|---|:--:|:--:|---|
| `--base URL` | ✅ | ✅ | override the matrix `base_url` |
| `--out PATH` | ✅ | ✅ | report directory / baseline file |
| `--fail-on VALUE` | ✅ | — | [gating](#gating-with---fail-on) |
| `--baseline FILE` | ✅ | — | compare against a snapshot for drift |
| `--waivers FILE` | ✅ | — | accepted findings |
| `--read-only` | ✅ | ✅ | skip mutating verbs and tools |
| `--concurrency N` | ✅ | ✅ | bound in-flight requests |
| `--max-retries N` | ✅ | ✅ | retry `429`/`503` with backoff |
| `--env-file FILE` | ✅ | ✅ | dotenv for `${VAR}` values |
| `--allow-inconclusive` | ✅ | ✅ | report/write anyway, keeping the old exit code |
| `--insecure` | ✅ | ✅ | disable TLS verification |

Exit codes: **0** clean · **1** findings (per `--fail-on`) · **2** bad input or
setup failure · **3** [inconclusive run](#inconclusive-runs-the-gate-refuses-to-fail-open).

`run` and `snapshot` share one pipeline — authenticate → setup → plan → dispatch →
teardown — so every transport (HTTP, MCP, stdio-MCP, mixed) behaves identically
and setup fixtures are always cleaned up, even if a run is interrupted.

## Finding taxonomy

Every class maps to its CWE and OWASP API Security Top 10 entry, carried in the
SARIF rules (with a `security-severity` score) and on every JSON finding:

| Class | CWE | OWASP API Top 10 |
|---|---|---|
| BOLA | CWE-639 | API1:2023 |
| BOPLA | CWE-213 | API3:2023 |
| BFLA | CWE-285 | API5:2023 |
| privilege-escalation | CWE-269 | API5:2023 |

## Transports & extensibility

overstep separates *what* it tests (the matrix, the planned probes, the
classification, the reports) from *how* a request is delivered. Delivery lives
behind a **transport registry** (`overstep.transports`) — the same pluggable
pattern as the reporters. A resource picks its transport; everything downstream is
unchanged:

```yaml
resources:
  - name: get_user
    transport: http            # the default; may be omitted
    request: { method: GET, path: "/users/{id}" }
    type: object
    owner_param: id
```

A single run can mix transports: the dispatcher groups planned cases by their
`transport` and routes each group to the matching executor. `validate` flags a
resource whose transport is not registered. The built-ins are `http` and `mcp`;
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
