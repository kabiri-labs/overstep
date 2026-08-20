# overstep

**Authorization testing for REST APIs and MCP servers — one problem class, two surfaces.**

![Version](https://img.shields.io/badge/version-1.5.0-blue)
![CI](https://img.shields.io/badge/CI-GitHub%20Actions-blue)
![License](https://img.shields.io/badge/license-Apache--2.0-green)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)

Authorization is the check a callee makes before it acts: *may this caller perform
this action on this object?* When that check is missing, weak or inconsistent, the
request is still well-formed and the response is still a `200` — the system simply
hands one tenant's data to another. overstep makes the intended answer explicit as
a file, turns it into positive and negative requests against a running target, and
reports every request that should have been refused and wasn't.

```
   authorization matrix  ──►  positive + negative tests  ──►  run  ──►  findings
   (subjects × resources)     (self / other, per role)       (REST + MCP)
```

---

**Contents**

[Why it is hard to automate](#why-authorization-is-hard-to-automate) ·
[Scope](#scope-one-problem-class-two-modules) ·
[Install](#install) ·
[Usage](#usage) ·
[Non-goals](#what-overstep-does-not-do) ·
[Roadmap](#roadmap) ·
[Contributing](#contributing)

---

## Why authorization is hard to automate

Most vulnerability classes have a syntactic tell. An injection payload, a
traversal sequence, a missing security header: a scanner recognises the *shape* of
the problem without knowing anything about the application. Authorization has no
such shape.

- **It is a logic flaw, not a syntax flaw.** `GET /invoices/8842` is a valid
  request whether or not invoice 8842 belongs to the caller. Nothing in the
  request, the response, or the specification distinguishes the legitimate read
  from the cross-tenant one. The two are byte-identical apart from a number.
- **Detection requires the intended policy, and the intended policy is not in the
  code.** To call a `200` a finding you must already know that this subject was
  not supposed to reach this object. That knowledge lives in a product decision,
  not in an OpenAPI document, a type signature or a route table — which is why a
  scanner with no policy input can only report what crashed, never what leaked.
- **Ownership is invisible to a spec.** An OpenAPI document describes
  `/invoices/{id}` as taking a string. It does not say which ids belong to whom,
  so nothing tells a generic scanner which id to substitute in order to make the
  request *wrong*. Without at least two identities holding genuinely different
  objects, there is no cross-owner probe to send.
- **The failure is silent by construction.** A missing check produces no error,
  no log line and no anomaly. It looks exactly like a feature working.

The consequence is that authorization testing cannot be discovery-driven. It has
to be **declarative**: someone writes down the intended policy, and the tool holds
the target to it. That is what the [authorization
matrix](#the-authorization-matrix) is, and it is why overstep asks for one before
it sends anything.

## Scope: one problem class, two modules

Authorization is the problem class. **REST** and **MCP** are two surfaces on which
it shows up — transports and layers, not two separate tools sharing a repository.
The detection logic is the same on both: resolve who the caller is, resolve which
object the request names, ask whether the callee refused, and compare that against
the declared policy.

The vocabulary is the standard one, and it is transport-independent:

| Term | The question | Where it applies |
|---|---|---|
| **Object-level authorization** (BOLA) | may this subject reach *this object*? | REST, MCP |
| **Function-level authorization** (BFLA) | may this subject invoke *this operation*? | REST, MCP |
| **Property-level authorization** (BOPLA) | may this subject see *this field* of an allowed response? | REST, MCP |
| **Privilege escalation** | does a lower-privileged role reach what a higher one is reserved for? | REST, MCP |
| **Multi-tenancy isolation** | does the tenant boundary hold when the caller is authenticated but foreign? | REST, MCP |
| **Credential audience binding** | does the callee check who the credential was issued *for*? | MCP |
| **Session binding** | can a connection identifier stand in for a credential? | MCP |
| **Authorization drift** | did any of the above answers change since the last release? | REST, MCP |

### The shared core

Everything except delivery is common to both modules and lives in one place: the
matrix model, the planner that expands it into cases, the ownership resolution,
the classifier, the confidence grading, the drift baseline, the waivers and every
report format. **The architecture is module-based**: each surface is a package
under `overstep/modules/`, and reaches the core only through registries — how a
case is delivered, how a finding is rendered, how a setup step runs, where a
credential is discovered, and which finding classes it can report. Neither module
sits at the package root, neither may import the other, and the core may not
import either; an import-graph test measures all three.

A resource does not name its module — it is read off the body the resource
declares — so adding a third surface means a package, an executor and a body
shape, not a string in a config file.

The matrix file has the same shape. Its top level is the shared core — subjects,
resources, policy, credentials, fixtures — and each module's own configuration
sits under its name in [`modules:`](#the-authorization-matrix). Neither surface is
the unmarked default, so adding a third would add a block rather than rearrange
the two that exist.

A single matrix can span both. The dispatcher groups planned cases by the module
each resource belongs to and routes each group to its executor, so a REST API and
the MCP server in front of it are one run, one baseline and one report.

### MCP: the newest and hardest instance of the class

MCP belongs under the same umbrella as REST, not above it — but it is where the
class is currently hardest to reason about, for four reasons:

- **The caller is an agent, not a person.** The identity that reaches the server
  is acting **on behalf of** a user. Authorization therefore depends on a
  **delegation chain** (user → agent → server → downstream service) rather than on
  a single authenticated principal, and every hop is somewhere the caller's
  authority can fail to be **attenuated** — that is, fail to shrink to the subset
  of privileges the delegation was meant to convey. This is multi-hop delegation,
  and it is the structural difference from a REST endpoint that answers one
  authenticated user directly.
- **There is no `403`.** A refusal arrives in-band, as a JSON-RPC error or an
  `isError` result, or on the HTTP leg as a `401` whose body is not JSON-RPC at
  all. A checker that reads only one of those calls a secure server wide open, or
  a broken one clean.
- **The surface is wider than the tool list.** The same objects are reachable
  through `resources/read` by URI. A server can enforce ownership perfectly on
  every tool and hand the data out through the other door.
- **The protocol carries authorization requirements of its own.** A server must
  refuse a credential that was not issued for it, and — on the revisions that have
  sessions — must not let a session identifier stand in for one. Neither is a
  question about your policy, and neither surfaces in any test of your tools.

overstep tests the **server's own enforcement** on this surface. It does not drive
the agent, and it does not evaluate what the agent was persuaded to ask for; see
[non-goals](#what-overstep-does-not-do).

### Module maturity

Conservative markers: **implemented** means exercised by the test suite;
**partial** means it works within a stated limit; **planned** means not built.

The bundled demos are a *subset* of that — they cover object- and function-level
probes, resource reads, session binding and tool enumeration, and are what the
numbers further down are measured from. Property-level checks, policy conditions,
cross-method probing, credential audience and OAuth discovery are covered by tests
rather than by a demo matrix, so read those rows as "there is a test for it", not
as "you can watch it run in two minutes".

| Capability | REST | MCP |
|---|---|---|
| Object-level (BOLA) probes across owners | **implemented** | **implemented** (tool arguments and resource URIs) |
| Function-level (BFLA) and privilege-escalation probes | **implemented** | **implemented** |
| Property-level (BOPLA) forbidden response fields | **implemented** | **implemented** |
| Multi-tenancy isolation via policy conditions | **implemented** | **implemented** |
| Ownership injection points | **implemented** (path, query, header, cookie, form, JSON body, GraphQL variables) | **implemented** (tool argument, resource URI placeholder) |
| Cross-method probing (`PUT`/`DELETE` against another owner's object) | **implemented** | n/a — MCP has no verb |
| Credential audience probe | n/a | **implemented** (Streamable HTTP only) |
| Session-binding probe | n/a | **implemented** (Streamable HTTP, stateful revisions; not applicable on `2026-07-28`) |
| Tool-enumeration probe | n/a | **implemented**, opt-in |
| Transport | **implemented** (HTTP/HTTPS) | **implemented** (Streamable HTTP and stdio) |
| Matrix scaffolding | **partial** — OpenAPI drafts a full matrix with `--with-policy`; a HAR capture drafts resources only, with no policy | **implemented** — a live server or a saved listing drafts a full matrix |
| Credential acquisition | **implemented** (arbitrary login request, OAuth 2.1 password and client-credentials grants) | **partial** — the same, plus RFC 9728/8414/8707 discovery; the interactive authorization-code flow is not supported |
| Delegation-chain and scope-attenuation testing | **planned** | **planned** |

## Install

```bash
pip install overstep
overstep version
```

Python 3.10+. Or run it without installing anything:

```bash
docker run --rm -v "$PWD:/work" -w /work ghcr.io/kabiri-labs/overstep \
    run matrix.yaml --out out
```

To work on overstep itself, or to run the bundled demos, clone the repository and
install it editable — see [CONTRIBUTING.md](CONTRIBUTING.md):

```bash
git clone https://github.com/kabiri-labs/overstep && cd overstep
pip install -e ".[dev]"
```

## Usage

The path from nothing to a result you can trust is the same for both modules:

| | |
|---|---|
| `overstep scaffold` | draft a matrix from a live MCP server, an OpenAPI document or a HAR capture |
| `overstep validate` | lint it — and with `--live`, check every credential still works |
| `overstep plan` | print what it *would* send, touching the network zero times |
| `overstep run` | send it and report |
| `overstep snapshot` | record today's decisions as a drift baseline |
| `overstep coverage` | report what the matrix does and does not reach |

Each command names the next on `stderr`; set `OVERSTEP_NO_HINTS=1` to switch that
off.

### The authorization matrix

Three parts — **subjects** (who), **resources** (what) and **policy** (the
allow-list). Everything not explicitly allowed is denied. `roles:` is ordered
least- to most-privileged, which is what separates BFLA from vertical privilege
escalation.

The file has **two levels**. Everything a run needs regardless of how a request is
delivered — subjects, resources, policy, credentials, fixtures — is declared once
at the top. Everything that only means something to one surface lives under that
surface's name in `modules:`.

A resource never names its module. It declares an HTTP `request`, or an MCP
`call` (a tool) or `read` (a resource URI), and that body is what places it — so
a resource cannot contradict itself about what it sends.

```yaml
roles: [anonymous, user, admin]

modules:
  rest:
    base_url: http://127.0.0.1:8000

subjects:
  - { name: alice, role: user,  token: "${ALICE_TOKEN}", marker: "alice@corp", attributes: { user_id: u1 } }
  - { name: bob,   role: user,  token: "${BOB_TOKEN}",   marker: "bob@corp",   attributes: { user_id: u2 } }
  - { name: root,  role: admin, token: "${ADMIN_TOKEN}", attributes: { user_id: u9 } }
  - { name: anon,  role: anonymous, token: null }

resources:
  - name: get_user
    request: { method: GET, path: "/users/{id}" }
    type: object            # object-level -> BOLA surface
    owner: id               # {id} must match the caller's user_id
    owner_attr: user_id
  - name: admin_list_users
    request: { method: GET, path: "/admin/users" }
    type: function          # function-level -> BFLA surface

policy:
  get_user:
    allow:
      - { role: user, scope: own }    # a user may read only their own profile
      - { role: admin, scope: any }   # admins may read anyone's
  admin_list_users:
    allow:
      - { role: admin }               # admin-only
```

Every **deny** case the planner derives is a probe: if the target answers it
successfully, that is a finding. Every **allow** case is a control: if the target
refuses it, either the matrix or the target is wrong, and overstep reports
`unexpected-deny`.

### Worked example: the REST module

A deliberately broken HTTP API ships with the repository.

```bash
python -m uvicorn examples.rest_api.server:app --port 8000
overstep plan examples/rest_api/matrix.yaml
```

`plan` sends nothing. It prints the eighteen cases the matrix above (plus a
`delete_user` resource) expands into — every subject against every resource:

```
┏━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━┳━━━━━━━━━┓
┃ Expected ┃ Class    ┃ Request          ┃ Subject          ┃ Variant ┃
┡━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━╇━━━━━━━━━┩
│ allow    │ object   │ GET /users/u1    │ alice (user)     │ self    │
│ deny     │ object   │ GET /users/u2    │ alice (user)     │ other   │
│ allow    │ object   │ GET /users/u2    │ bob (user)       │ self    │
│ deny     │ object   │ GET /users/u1    │ bob (user)       │ other   │
│ allow    │ object   │ GET /users/u9    │ root (admin)     │ self    │
│ allow    │ object   │ GET /users/u1    │ root (admin)     │ other   │
│ deny     │ object   │ GET /users/u1    │ anon (anonymous) │ other   │
│ deny     │ object   │ DELETE /users/u2 │ alice (user)     │ other   │
│ …        │          │                  │                  │         │
│ deny     │ function │ GET /admin/users │ alice (user)     │ na      │
│ allow    │ function │ GET /admin/users │ root (admin)     │ na      │
└──────────┴──────────┴──────────────────┴──────────────────┴─────────┘
```

The `other` rows are the object-level probes. They exist only because alice and
bob hold genuinely *different* objects; give two subjects the same id and the
cross-owner probe disappears, which is why `validate` warns about it.

```bash
overstep run examples/rest_api/matrix.yaml --out out
```

```
 Tests run                            18
 Positive / negative               7 / 11
 Vulnerabilities            8 (3 defects)
   BOLA                                2
   privilege-escalation                6
 Object resources probed             2/2
```

Eight probes got through, tracing back to **three** distinct defects — one row per
thing to fix, with the subjects that reached it as evidence of blast radius.

### Worked example: the MCP module

The MCP demo is a deliberately broken Streamable HTTP server.

```bash
python -m uvicorn examples.mcp_api.server:app --port 9000
overstep run examples/mcp_api/matrix.yaml --out out
```

```
 Tests run                            27
 Positive / negative   8 / 15 (+4 listing)
 Vulnerabilities           16 (7 defects)
   BOLA                                4
   privilege-escalation                5
   session-hijack                      3
   tool-enumeration                    4
 Object resources probed             2/2
```

Its matrix has the same shape — the same core at the top, a different module
block, and resources whose bodies place them:

```yaml
modules:
  mcp:
    servers:
      - name: docs
        url: http://127.0.0.1:9000/mcp     # Streamable HTTP (JSON-RPC)

resources:
  - name: read_document
    call: { server: docs, tool: read_document }
    type: object            # object-level -> BOLA surface on the tool argument
    owner: doc_id
    owner_attr: doc_id
  - name: read_doc_resource
    read: { server: docs, uri: "doc://acme/{doc_id}" }
    type: object            # object-level -> BOLA surface on the resource URI
    owner: doc_id           # the {placeholder} carrying the object id
    owner_attr: doc_id
  - name: reset_tenant
    call: { server: docs, tool: reset_tenant, mutating: true }   # skipped under --read-only
    type: function
```

Two of the four BOLA findings come through `tools/call` and two through
`resources/read`, against the same two documents, because the server has the same
missing ownership check on both doors — the case a tools-only checker reports
clean.

The other two classes are about the connection rather than a declared operation,
and have no equivalent in a REST scanner. The server hands out an `Mcp-Session-Id`
at `initialize` and then accepts it *in place of* a credential, and it advertises
`list_all_users` and `reset_tenant` to plain users who cannot invoke them. Those
rows appear in `plan` alongside the declared ones:

```
│ deny  │ function │ tools/list docs │ alice (user) │ session   │
│ allow │ function │ tools/list docs │ alice (user) │ enumerate │
```

Reports land in `out/`:

| File | For |
|---|---|
| `report.html` | humans — findings with evidence and repro |
| `findings.json` | scripts and dashboards (CWE + OWASP tagged) |
| `overstep.sarif` | GitHub code scanning |
| `junit.xml` | CI test reporters |

`overstep run` exits non-zero on findings, so it fails a pipeline out of the box.
A stdio variant of the same demo lives at `examples/mcp_api/matrix_stdio.yaml`.

### Pointing it at your own target

```bash
overstep scaffold http://127.0.0.1:9000/mcp --fmt mcp --server-name docs \
    --token "$TOKEN" > matrix.yaml        # MCP: a full matrix
overstep scaffold openapi.yaml --with-policy > matrix.yaml   # REST: a full matrix
overstep scaffold traffic.har --fmt har > resources.yaml     # REST: resources only
```

For MCP, overstep reads **both** `tools/list` and `resources/templates/list`, so
the second door is in the draft from the start, and it records which
[protocol revision](#mcp-protocol-revisions) the server speaks. For OpenAPI,
`--with-policy` reads the document's own `security` declarations; a document that
describes no authorization at all yields a deny-by-default guess behind an
explicit warning, because reading silence as "everything is public" would produce
a matrix with zero negative tests.

The scaffold leaves `PASTE_..._TOKEN` and `REPLACE_ME_1` / `REPLACE_ME_2` where it
cannot know the answer. Two things to get right: give the two peer subjects
genuinely **different** objects, and keep secrets out of the file (`${ALICE_TOKEN}`
from the environment or `--env-file`). Then review the starter policy — it is a
guess, and it is the one part of the file only you can write.

```bash
overstep validate matrix.yaml          # structural errors and leftover placeholders
overstep validate matrix.yaml --live   # one expected-allow request per subject
overstep plan matrix.yaml              # read every request before sending one
overstep run matrix.yaml --out out --read-only
```

`--live` proves each credential is still accepted, which matters because an
expired token turns every negative test into a pass for the wrong reason. It is
side-effect free: probes go out read-only and non-mutating operations are
preferred.

### Reading allow and deny

The allow/deny signal is the one thing a tool cannot infer, so it is declared.

Each module declares it under the same key — `access:` — and the schema is the
module's own. A resource may override it with the same key; which matcher parses
it follows from the resource's body, so a REST resource cannot be handed an MCP
matcher by accident.

**REST.** By default `2xx` means granted and anything else means denied. For APIs
that redirect on success, return `200` with an error body, or mask `403` as `404`:

```yaml
modules:
  rest:
    access:
      allow_status: ["2xx"]         # exact codes, ranges ("200-299") or classes ("2xx")
      deny_body_regex: "access denied|not authorized"   # a 200 with this body -> deny
      treat_redirect_as: deny       # deny | allow | status
```

Evaluation order: `deny_body_regex` (wins, fails safe) → `allow_body_regex` →
redirect handling → `allow_status`.

**MCP.** There is no `403`, so the deny signal is spelled out on both legs:

```yaml
modules:
  mcp:
    access:
      is_error_is_deny: true              # a result with isError: true -> denied
      jsonrpc_error_is_deny: true         # a JSON-RPC error -> denied
      deny_status: ["4xx", "5xx"]         # an HTTP-leg refusal (401/403) -> denied
      # deny_content_regex: "permission denied"
```

`deny_status` is the half that is easy to miss. The MCP authorization spec has an
unauthorized request answered with `401` and a `WWW-Authenticate` header, and
nothing requires the body to be a JSON-RPC message — an empty body, or a
framework's own `{"detail": "Not authenticated"}`, is what many servers send. Such
a response carries no in-band deny signal at all, so without reading the status,
the servers that reject *before* dispatching — the ones doing it right — are
exactly the ones a run would report wide open. It does not apply to stdio, which
has no HTTP leg.

### Where the object id lives: injections

The identifier of the object a subject reaches for is the object-level surface,
and it does not always sit in a path parameter or a tool argument.
`ownership.injections` says where to write it; overstep fills each location with
the caller's own object (SELF) or a victim's (OTHER).

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
`graphql_variables`, `mcp_argument` or `mcp_resource_uri`. `selector` is read per
location: a path parameter, a query/header/cookie/form key, a JSONPath into the
body, a GraphQL variable name, a tool-argument key, or a `{placeholder}` in an MCP
resource URI template. `owner:` is the shorthand for exactly one of these, in
whichever place the resource naturally carries an id — a path parameter for a
`request`, a tool argument for a `call`, the URI placeholder for a `read` — so it
never has to restate what the body already says. Set `owner_attr` on an individual
injection to source it from a different subject attribute — the tenant, say,
rather than the object id.

A full example lives in
[`examples/injections/matrix.yaml`](examples/injections/matrix.yaml).

**Cross-method probing (REST only).** A GET-only resource can hide a missing check
on other verbs. `probe_methods: [PUT, DELETE]` fires each verb at another
subject's object as a negative test.

### Making findings trustworthy

A tool that cries wolf gets switched off. These decide whether a finding is real.

**Confidence.** A successful result on an object-level probe is not proof that
data leaked — the call may have returned an empty list. Give each subject a
`marker` (a string that uniquely identifies *its* data) and overstep looks for the
victim's marker before it trusts the outcome: **confirmed** (the victim's data
appeared), **suspected** (access granted, no victim data — downgraded to medium),
**unverified** (no marker configured). This matters more on MCP, where there is
often no status code to lean on.

**One defect, not one finding per identity.** A missing check is reported once per
identity that reaches it, so one bug can arrive as a dozen findings. Every report
therefore carries a defect roll-up — one row per thing to fix, with the subjects
as evidence — in the summary, in `findings.json` under `defects`, and as the
leading table of the HTML report. Nothing is filtered; gating still counts
findings.

**A repro that runs.** Each finding carries a runnable command and a structured
request record, with the credential replaced by a shell variable named after the
subject it belongs to (`OVERSTEP_TOKEN_<SUBJECT>`), so the line is safe to paste
into a ticket and still works once the variable is set. stdio findings get an
stdio repro; a session-binding finding gets the two-step form its defect requires.

**Property-level checks.** List the JSON keys an allowed response must never
contain. Matching is key-based, so a name appearing in free text does not
false-positive:

```yaml
    forbidden_fields: [password_hash, is_admin]
```

**How many victims each subject probes.** By default every subject sends one
cross-owner probe, which catches a check that is missing outright. Set
`probe_victims: all` (matrix-wide or per resource) to send one probe per *distinct*
object instead — for a check that holds for some owners and not others, such as a
tenant whose ACL rows were never backfilled.

### Modelling a real target

**Custom conditions.** For tenant isolation and attribute matching, an allow rule
can carry a boolean condition over `subject` and `target` attributes:

```yaml
policy:
  read_document:
    allow:
      - role: user
        condition: "subject.tenant == target.tenant"
```

Conditions run through a restricted AST evaluator — comparisons, boolean logic and
attribute/index access only. No function calls, no arbitrary names.

**Custom headers.** By default each subject authenticates with `Authorization:
Bearer <token>`. Headers can be set on the resource (or, for MCP, the server) and
on the subject; subject headers override what they inherit. An `Authorization`
header set on the *subject* is a deliberate choice of scheme and is never
overwritten by the token; one set on the resource or server belongs to no identity
in particular, so a subject's own token replaces it — otherwise a matrix written to
tell callers apart would be testing a single caller under several names.

**Credentials.** Any `${VAR}` in the matrix is replaced from the environment at
load time (`${VAR:-default}` for a fallback); a missing variable fails the run
loudly. Pass a dotenv file with `--env-file`. A subject can instead obtain its
token by logging in before the run — `type: http` posts an arbitrary login request
and reads the token out of the response, `oauth2_password` and
`oauth2_client_credentials` build the standard token-endpoint form. `{{var}}`
placeholders are filled per subject from `auth.vars`, so one provider serves many
identities and secrets never touch the file.

**Real objects.** Meaningful object-level testing needs a real owned object.
`objects:` maps each subject to the id it owns; `setup:` steps run once before the
suite as a chosen subject and `extract` values into a capture context that fills
`{{name}}` placeholders, including in `objects:`; `teardown:` steps clean the
fixtures up best-effort afterwards.

```yaml
setup:
  - { as: alice, call: { server: docs, tool: create_document, arguments: { body: "notes" } }, extract: { ALICE_DOC: "$.id" } }
  - { as: bob,   call: { server: docs, tool: create_document, arguments: { body: "plans" } }, extract: { BOB_DOC: "$.id" } }

resources:
  - name: read_document
    # …
    objects: { alice: "{{ALICE_DOC}}", bob: "{{BOB_DOC}}" }
```

### The MCP protocol probes

Three checks run against every Streamable HTTP server beyond what the matrix
declares, because they ask about the **credential** and the **connection** rather
than about any one operation. None is available on stdio, where identity is an
environment variable the server itself named rather than anything travelling on a
connection.

| Probe | Default | Asks |
|---|---|---|
| Credential audience | on | does the server check who the credential was issued *for*? |
| Session binding | on | can a session id stand in for a credential? |
| Tool enumeration | off | is the privileged half of the catalogue advertised to everyone? |

**Credential audience.** The MCP authorization spec is unambiguous: a server must
not accept a token that was not issued for it. A server that skips the check is a
confused deputy, and the blast radius is not one object but every service trusting
the same issuer. Declare what a subject's token is bound to and overstep replays
that credential at every server the audience does not identify:

```yaml
subjects:
  - { name: alice, role: user, token: "${ALICE_DOCS_TOKEN}", token_audience: docs }
```

The audience is inferred when a subject authenticates through a provider that
discovers its token endpoint from a server or sends an explicit `resource` — such a
token *is* audience-bound. With no audience known, no probe is generated: overstep
does not guess which credential belongs where. The probe is `tools/list`, which
requires authorization, takes no arguments and changes nothing, so it isolates the
single question. The policy is deliberately not consulted — an admin's token bound
to server A must still be refused by server B. Set
`modules.mcp.probes.token_audience: false` if one credential is legitimately
valid at several of your declared servers.

**Session binding.** Streamable HTTP hands out an `Mcp-Session-Id` at `initialize`,
and the spec is explicit that it must not authenticate. The probe opens a session
as the subject, then sends the same **anonymous** request twice — once carrying the
session id, once without. The second request is the control: a server whose listing
is simply public answers both, and calling that a hijack would be a finding about
nothing. Only the difference counts. A server that issues no session id has
nothing to hijack, and the probe is recorded as skipped rather than passed.

**Tool enumeration.** Opt-in via `modules.mcp.probes.tool_enumeration: true`, because listing
everything and enforcing at call time is a common and defensible design. It calls
`tools/list` as each subject and compares the result against the policy already
written; a paginated listing is followed to the end. A tool the matrix does not
declare is *undescribed* rather than disallowed — that is
[coverage](#what-a-clean-result-is-allowed-to-mean)'s gap to report — and a subject
that cannot list at all has nothing to disclose. Enumeration probes are never
counted as positive controls, since a public listing answers with no credential at
all.

#### MCP protocol revisions

Through `2025-11-25` a connection opens with an `initialize` handshake and may
carry an `Mcp-Session-Id`. From **`2026-07-28`** the core is stateless: the
handshake and the session header are gone, and every request carries its own
protocol version and client capabilities in `params._meta`, plus `Mcp-Method` and
`Mcp-Name` headers.

overstep drives both. The default stays on the stateful wire, because which
revision to speak is a fact about the target, not a preference:

```yaml
modules:
  mcp:
    servers:
      - name: docs
        url: https://mcp.example.com/mcp
        protocol_version: "2026-07-28"     # default: 2025-06-18
```

You do not have to know which one to write — `scaffold` asks the server
(`server/discover` first, then a negotiated `initialize`) and records the answer.
Two consequences: session binding is reported as **skipped, not applicable** on
`2026-07-28`, because the defect was removed from the protocol rather than fixed in
your server; and a version mismatch ends the run as
[inconclusive](#what-a-clean-result-is-allowed-to-mean) rather than scoring it,
because a refusal to speak is not a denial.

#### OAuth-protected MCP servers

For a remote server behind OAuth 2.1, a provider can discover where to
authenticate rather than hardcoding a token endpoint: overstep reads the server's
Protected Resource Metadata (RFC 9728), then the Authorization Server Metadata
(RFC 8414), obtains a token with a machine grant, and sends the resource indicator
(RFC 8707) so the token is audience-bound.

```yaml
auth:
  providers:
    - name: mcp_oauth
      type: oauth2_client_credentials
      discover_from: docs                  # the MCP server name (or a URL)
      issuer: https://login.example.com    # where these credentials are registered
      client_id: "{{client_id}}"
      client_secret: "${CLIENT_SECRET}"
```

Discovery starts at the server under test, which means the least trusted host in
the picture names where your `client_secret` is posted. Four checks are automatic:
the authorization server and token endpoint must be HTTPS (loopback and
`--insecure` excepted); the metadata's `issuer` must be identical to the identifier
the well-known URL was built from (RFC 8414 §3.3); the resource metadata's
`resource` must be identical to the server URL your matrix declared (RFC 9728
§3.3); and a metadata request must not be redirected to another origin. None of
those catches a target that names an authorization server it simply owns and
describes honestly — `issuer:` is what refuses that, and `validate` warns when a
provider sends a secret without one.

The interactive authorization-code flow needs a browser and is not supported.

#### Local MCP servers over stdio

For a server that runs as a local process, declare a `command` instead of a `url`.
overstep launches one process per subject and speaks JSON-RPC over stdin/stdout.
There is no HTTP header for identity, so the subject's token goes into the process
environment:

```yaml
modules:
  mcp:
    servers:
      - name: docs
        command: ["python", "server.py"]
        token_env: MCP_TOKEN           # each subject's token -> this env var
```

Everything else is identical — object and function resources, ownership, markers,
`--read-only`, reports. The three protocol probes do not apply.

### Gating on change: baselines and waivers

Finding today's holes is the first run. What compounds is the run after it, because
an authorization surface usually breaks by *changing*: a refactor drops a scope
check, a new operation ships without an owner check, a role gains a permission in a
config nobody reviewed as security. None of that looks anomalous on its own. It is
only wrong relative to what was agreed last month.

```bash
overstep snapshot matrix.yaml --out baseline.json                            # once, after triage
overstep run matrix.yaml --baseline baseline.json --fail-on vuln-or-drift    # every PR
```

A cell that flipped **deny → allow** is a newly opened hole; **allow → deny** is a
new restriction, often intended and occasionally an outage.

**Gate on `vuln-or-drift`, not `drift`.** A diff can only speak about cells that
existed on both sides, so a newly added operation has nothing to differ from: the
new tool shipped without an owner check is reported as a vulnerability, not as
drift, and a drift-only gate goes green on exactly the case that motivates the
baseline.

| `--fail-on` | Exits non-zero when… |
|---|---|
| `vuln` (default) | there is an active, non-waived vulnerability |
| `drift` | a decision changed versus `--baseline`, ignoring pre-existing findings |
| `vuln-or-drift` | either is present |
| `any` | any active finding exists, including `unexpected-deny` |
| `never` | always exits zero (report-only) |

The cost of `vuln-or-drift` is that pre-existing findings fail the build too.
**Waivers** are the mechanism for that — each accepted finding named by its stable
`test_id`, with a mandatory reason and an optional expiry, reviewed like any other
code. Waived findings leave the gating set but stay visible in the reports, and an
expired waiver stops suppressing and prints a warning.

```yaml
# waivers.yaml
waivers:
  - id: read_document::alice::other
    vuln_class: BOLA
    reason: "Tracked in SEC-1234; fix scheduled next release."
    expires: 2026-12-31
```

Keep `matrix.yaml`, `baseline.json` and `waivers.yaml` in version control and
authorization gets reviewed like any other code.

**Safety and pipeline flags.** `--read-only` skips every mutating operation
(POST/PUT/PATCH/DELETE over HTTP, any tool marked `mutating` over MCP).
`--max-retries N` (default 2) retries `429`/`503`, honouring `Retry-After`.
`--concurrency N` bounds in-flight requests. Ready-made artifacts:
[`examples/ci/github-actions.yml`](examples/ci/github-actions.yml),
[`examples/ci/gitlab-ci.yml`](examples/ci/gitlab-ci.yml), the
`ghcr.io/kabiri-labs/overstep` image, and an `overstep-validate` pre-commit hook.

### What a clean result is allowed to mean

An absence of findings is worth something only if the run could have seen them.
Two checks enforce that.

**Inconclusive runs.** If the requests never arrived or the credentials were never
accepted, every negative test "passes" for the wrong reason and a naive summary
reads `Vulnerabilities 0`. overstep calls that run **inconclusive** and exits `3`.
A run is inconclusive when, for any one target, at least half its requests failed
at the transport layer, or nothing proves its credentials work — every
expected-allow test skipped, or none of the ones that ran allowed. The judgement is
per target, so a busy healthy one cannot outvote a small one that answered nothing.
Exit code 3 is distinct from 1 (findings) and 2 (bad input), so CI can tell "your
server has a hole" from "the scan never ran", and `snapshot` refuses to write a
baseline against a dead target. `--allow-inconclusive` reports anyway.

**The credential half of that check needs expected-allow tests to work, on the
target you want it to speak for.** An allowed request is the only thing that
proves a credential is still accepted, so a target with no expected-allow case has
no such proof to lose — and overstep does not condemn it for that, because an
intentionally all-negative suite is a legitimate thing to write.

The consequence is worth stating plainly, and it is sharper than it first looks
because the judgement is **per target**. A matrix spanning a REST API and an MCP
server, with its only positive control on the REST side, says nothing about the
MCP server's credentials: if that server rejects every one of them, its every
expected-deny case is denied, and the run is reported as conclusive and clean.
The healthy target does not vouch for the silent one — the same isolation that
stops a busy target outvoting a small one also stops it covering for one.

**Give every target at least one expected-allow case if you want expired
credentials to fail the build.** Unreachability is still caught either way; it is
only the credential check that has nothing to stand on.

**Coverage.** `overstep coverage` measures two gaps and sends nothing:

```bash
overstep coverage matrix.yaml --spec http://127.0.0.1:9000/mcp --fmt mcp --token "$TOKEN"
```

The *outer* gap is what the matrix never declared — measured against an
independent description of the surface (`--spec` takes an MCP server or
`tools.json` with `--fmt mcp`, an OpenAPI document, or a HAR capture). The *inner*
gap is what the run could not ask about: a cross-owner probe is the only thing that
tests object-level authorization, and the planner generates one only when two
subjects resolve to genuinely different objects. Where they do not, it drops the
probe rather than replaying a subject's own request under another label — so the
run reports a resource nobody probed instead of counting it as clean.
`--fail-under N` gates on either percentage.

### Command reference

| Command | What it does |
|---|---|
| `overstep scaffold SPEC` | draft a matrix from a live MCP server, `tools.json`, OpenAPI or HAR |
| `overstep validate MATRIX` | lint for structural problems and unfilled placeholders (`--live` probes the target; `--strict` fails on warnings) |
| `overstep plan MATRIX` | print the generated test cases (no network) |
| `overstep coverage MATRIX` | report what the matrix covers, vs. `--spec` and vs. its own object surface (no network) |
| `overstep run MATRIX` | generate, execute and report; non-zero exit on findings |
| `overstep snapshot MATRIX` | record current decisions as a drift baseline |
| `overstep version` | print the installed version |

| Flag | `run` | `snapshot` | Meaning |
|---|:--:|:--:|---|
| `--base URL` | ✅ | ✅ | override the matrix `base_url` |
| `--out PATH` | ✅ | ✅ | report directory / baseline file |
| `--fail-on VALUE` | ✅ | — | gating |
| `--baseline FILE` | ✅ | — | compare against a snapshot for drift |
| `--waivers FILE` | ✅ | — | accepted findings |
| `--read-only` | ✅ | ✅ | skip mutating verbs and tools |
| `--concurrency N` | ✅ | ✅ | bound in-flight requests |
| `--max-retries N` | ✅ | ✅ | retry `429`/`503` with backoff |
| `--env-file FILE` | ✅ | ✅ | dotenv for `${VAR}` values |
| `--allow-inconclusive` | ✅ | ✅ | report/write anyway, keeping the old exit code |
| `--insecure` | ✅ | ✅ | disable TLS verification |

Exit codes: **0** clean · **1** findings (per `--fail-on`) · **2** bad input or
setup failure · **3** inconclusive run.

`run` and `snapshot` share one pipeline — authenticate → setup → plan → dispatch →
teardown — so every transport behaves identically and setup fixtures are cleaned up
even if a run is interrupted.

### Finding taxonomy

Every class maps to its CWE and OWASP API Security Top 10 entry, carried in the
SARIF rules (with a `security-severity` score) and on every JSON finding.

| Class | CWE | OWASP API Top 10 | Surface |
|---|---|---|---|
| BOLA | CWE-639 | API1:2023 | REST, MCP |
| BOPLA | CWE-213 | API3:2023 | REST, MCP |
| BFLA | CWE-285 | API5:2023 | REST, MCP |
| privilege-escalation | CWE-269 | API5:2023 | REST, MCP |
| token-audience | CWE-863 | API2:2023 | MCP |
| session-hijack | CWE-287 | API2:2023 | MCP |
| tool-enumeration | CWE-200 | API5:2023 | MCP |

## What overstep does not do

Knowing the edges is part of deciding whether this fits.

- **It does not discover your surface.** You declare it. `scaffold` drafts a matrix
  from a live MCP server, an OpenAPI document or a HAR capture, but you review it.
- **It does not invent your policy.** The matrix *is* the specification. A wrong
  matrix produces wrong results; `validate`, the plan table and the coverage and
  inconclusive checks exist to catch the common mistakes, not to guess intent.
- **It does not test authentication.** Login strength, token forgery and session
  fixation are out of scope: overstep tests what an *already authenticated*
  identity is permitted to do. Two deliberate exceptions, both because the MCP spec
  makes them requirements of the server: credential audience validation and session
  binding.
- **It does not test the delegation chain.** overstep authenticates as a subject
  and tests the enforcement of the callee it talks to. It does not verify that
  authority was correctly **attenuated** across hops, that an on-behalf-of token
  carries the right actor claims, or that a downstream service re-checks what an
  upstream one already allowed. Those are real parts of the problem class and they
  are [roadmap](#roadmap), not features.
- **It is not an AI or LLM security tool.** It does not drive an agent with
  natural-language prompts, and it has no opinion about tool descriptions. Prompt
  injection, tool poisoning and confused-deputy attacks *against the agent* are a
  separate, non-deterministic concern. overstep tests the server's enforcement, and
  the two are complements: a description scanner will not tell you the server hands
  `doc://acme/anyone` to whoever asks, and overstep will not tell you a tool
  description is lying to your agent.
- **It does not fuzz.** Every request is one the matrix asked for, which is what
  makes results deterministic and diffable.
- **It is a test, not a control.** It runs in CI against a target you nominate; it
  enforces nothing at runtime.
- **It sends real requests.** Use `--read-only` against anything you care about.

## Roadmap

Short and honest. Nothing here is scheduled.

| | Status |
|---|---|
| REST and MCP modules as described above | **implemented** |
| Policy inference when scaffolding from a HAR capture (today: resources only) | **planned** |
| Interactive OAuth authorization-code flow for subjects that cannot use a machine grant | **planned** |
| Delegation-chain testing: on-behalf-of token shape, actor claims, re-checking at each hop | **planned** |
| Scope-attenuation checks: proving a delegated credential carries strictly fewer privileges than the one it was derived from | **planned** |
| Further surfaces | **planned**, unscheduled — `rest` and `mcp` are the two modules that exist. A third is a package under `overstep/modules/`, an executor, a body shape and a config block; the registries carry the rest |

### What 1.0.0 means

The matrix format, the `test_id` shape, the finding classes and their wire values,
the exit codes and the report documents are the surface this version freezes.
They are pinned by golden files that fail on any change, so a release that moves
one has to say so.

It does not mean the roadmap above is finished, or that the tool covers every
authorization question — the non-goals are as true at 1.0.0 as they were before
it. It means the parts you would build a pipeline against have stopped moving
underneath you, and that breaking one is now a decision with a version number
rather than an ordinary release.

## Contributing

Issues and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for
the development setup, and [SECURITY.md](SECURITY.md) for reporting a
vulnerability in overstep itself. The test suite runs with `pytest -q`.

Only test targets you are authorized to test.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
