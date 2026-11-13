# overstep

**Authorization testing for MCP servers. Declare who may invoke which tool and reach which object, and overstep proves whether the server enforces it — including the REST API behind the server, in the same run.**

![Version](https://img.shields.io/badge/version-1.11.0-blue)
[![CI](https://github.com/kabiri-labs/overstep/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/kabiri-labs/overstep/actions/workflows/ci.yml)
![License](https://img.shields.io/badge/license-Apache--2.0-green)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)

An MCP server decides, on every call, whether this caller may invoke this tool
and reach this object. When that check is missing, weak or inconsistent nothing
looks wrong: the call is well-formed, the result is an ordinary tool result, and
the server hands one tenant's documents to another. overstep makes the intended
answer explicit as a file, turns it into positive and negative calls against a
running server, and reports every one that should have been refused and wasn't.

It does the same for the API behind that server, in the same run, because an MCP
server is almost never the system of record. A façade that enforces ownership
perfectly says nothing about whether the object underneath it is protected — and
that is the gap an MCP-only check cannot see. See [when testing an MCP server
means testing the API behind
it](#when-testing-an-mcp-server-means-testing-the-api-behind-it).

```
   authorization matrix  ──►  positive + negative tests  ──►  run  ──►  findings
   (subjects × resources)     (self / other, per role)      (MCP + the API behind it)
```

---

**Contents**

[Why it is hard to automate](#why-authorization-is-hard-to-automate) ·
[The API behind the server](#when-testing-an-mcp-server-means-testing-the-api-behind-it) ·
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

- **It is a logic flaw, not a syntax flaw.** `read_document(doc_id: "d-8842")`
  is a valid call whether or not document `d-8842` belongs to the caller.
  Nothing in the request, the result, or the tool's schema distinguishes the
  legitimate read from the cross-tenant one. The two are byte-identical apart
  from an identifier.
- **Detection requires the intended policy, and the policy is not in the
  schema.** To call a successful result a finding you must already know that
  this subject was not supposed to reach this object. That knowledge lives in a
  product decision, not in a tool description, an input schema or an OpenAPI
  document — which is why a scanner with no policy input can only report what
  crashed, never what leaked.
- **Ownership is invisible to a description.** `tools/list` tells you
  `read_document` takes a `doc_id` string. It does not say which ids belong to
  whom, so nothing tells a generic scanner which id to substitute in order to
  make the call *wrong*. Without at least two identities holding genuinely
  different objects, there is no cross-owner probe to send.
- **The failure is silent by construction.** A missing check produces no error,
  no log line and no anomaly. It looks exactly like a feature working.

So one half of the problem is discoverable and the other half is not. An MCP
server describes its own surface — `tools/list` and
`resources/templates/list` return the inventory with its schemas, which is why
`scaffold` can draft a whole matrix from a live server and is marked
**implemented** for MCP while it is only **partial** for REST. What no server
returns is who may reach what, and which ids belong to whom. That part is
**declarative**: somebody writes it down, and the tool holds the server to it.
That is what the [authorization matrix](#the-authorization-matrix) is, and
scaffolding is how most of it gets written for you before you fill in the one
part only you can know.

### MCP: the newest and hardest instance of the class

This is one problem class, and MCP is where it is currently hardest to reason
about — which is the whole reason overstep leads with it. Four reasons:

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
  sessions — must not let a session identifier stand in for one. The OAuth
  machinery around it carries more: metadata documents that name the server
  rather than somebody else, and a client registry that does not hand a client
  id to an anonymous caller. None of these is a question about your policy, and
  none surfaces in any test of your tools.

overstep tests the **server's own enforcement** on this surface. It does not drive
the agent, and it does not evaluate what the agent was persuaded to ask for; see
[non-goals](#what-overstep-does-not-do).

### When testing an MCP server means testing the API behind it

An MCP server is almost never the system of record. It is a façade over an API, a
database or a SaaS product, and authorization either holds at the object or it
does not. That is why overstep covers plain HTTP as well — not to serve REST
users, but because MCP engagements run into it. Ranked by whether they produce a
defect:

**1. The check lives in the façade, not at the resource.** The most common case
and the most serious. The MCP server enforces ownership correctly on every tool;
the API behind it does not. Testing only the MCP surface proves the wrapper
enforces — not that the object is protected. Anyone reaching the API directly
goes around the wrapper: a second MCP server pointed at the same backend, a
mobile client, an internal service, a developer holding a token. One matrix
across both surfaces answers where the check actually sits, and it is the reason
the two [worked examples](#worked-example-the-mcp-module) below are keyed to the
same objects.

**2. Blast radius of a compromised MCP server.** What can the MCP server's own
service credential reach? Point the REST module at the backing API with that
credential and the answer is a list rather than a guess: this is what an
attacker who owns the MCP server gets, and it is the question a reviewer asks
before approving a deployment. The companion question — whether the server
forwards *your* credential to an upstream API rather than using a token of its
own — is what the [token-passthrough probe](#the-mcp-protocol-probes) answers,
and it needs a canary you run, because nothing in the protocol reports what a
server sent onward.

**3. Drift between two doors to the same object.** The same object is exposed as
an MCP tool and as a REST endpoint. A policy fix lands on one and not the other.
The [drift baseline](#gating-on-change-baselines-and-waivers) spans both surfaces
in one run, so the regression arrives as a diff instead of as an incident.

**4. The MCP server's own HTTP surface.** A deployment ships more than the
JSON-RPC endpoint: health and admin routes, the OAuth metadata documents the
[conformance probes](#the-mcp-protocol-probes) already read, sometimes a
registration endpoint or a management console. That is plain HTTP and needs the
same matrix.

**5. Where the matrix comes from.** MCP tools usually mirror API operations, and
the OpenAPI document for the backing API carries the resource inventory and often
the ownership parameter names. Scaffold from OpenAPI, then re-point the resources
at the tools. Not a defect class — a workflow answer to the question every
declarative tool is asked, which is where the policy file is supposed to come
from.

The one-sentence version: the MCP server is not the system of record, so an MCP
authorization tool that cannot test the API behind the server is testing a
wrapper.

## Scope: one problem class, two modules

Authorization is the problem class. **MCP** is the surface overstep leads with
and **REST** is the one underneath it — transports and layers, not two separate
tools sharing a repository. The detection logic is identical on both: resolve who
the caller is, resolve which object the request names, ask whether the callee
refused, and compare that against the declared policy. That the same code finds
the same defect on either door is the evidence that none of this is MCP-specific
hand-waving, and it is what makes the case above possible at all.

The vocabulary is the standard one, and it is transport-independent:

| Term | The question | Where it applies |
|---|---|---|
| **Object-level authorization** (BOLA) | may this subject reach *this object*? | MCP, REST |
| **Function-level authorization** (BFLA) | may this subject invoke *this operation*? | MCP, REST |
| **Property-level authorization** (BOPLA) | may this subject see *this field* of an allowed response? | MCP, REST |
| **Privilege escalation** | does a lower-privileged role reach what a higher one is reserved for? | MCP, REST |
| **Multi-tenancy isolation** | does the tenant boundary hold when the caller is authenticated but foreign? | MCP, REST |
| **Credential audience binding** | does the callee check who the credential was issued *for*? | MCP |
| **Session binding** | can a connection identifier stand in for a credential? | MCP |
| **Server metadata identity** | do the OAuth documents a server serves name that server? | MCP |
| **Authorization drift** | did any of the above answers change since the last release? | MCP, REST |

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

### Module maturity

Conservative markers: **implemented** means exercised by the test suite;
**partial** means it works within a stated limit; **planned** means not built.

The bundled demos are a *subset* of that — they cover object- and function-level
probes, resource reads, session binding and tool enumeration, and are what the
numbers further down are measured from. Property-level checks, policy conditions,
cross-method probing, credential audience, OAuth discovery and the two server
conformance probes are covered by tests rather than by a demo matrix, so read
those rows as "there is a test for it", not as "you can watch it run in two
minutes". The conformance probes in particular need an authorization server that
misbehaves, which is not something a demo you are invited to run should ship.

| Capability | MCP | REST |
|---|---|---|
| Object-level (BOLA) probes across owners | **implemented** (tool arguments and resource URIs) | **implemented** |
| Function-level (BFLA) and privilege-escalation probes | **implemented** | **implemented** |
| Property-level (BOPLA) forbidden response fields | **implemented** | **implemented** |
| Multi-tenancy isolation via policy conditions | **implemented** | **implemented** |
| Ownership injection points | **implemented** (tool argument, resource URI placeholder) | **implemented** (path, query, header, cookie, form, JSON body, GraphQL variables) |
| Cross-method probing (`PUT`/`DELETE` against another owner's object) | n/a — MCP has no verb | **implemented** |
| Credential audience probe | **implemented** (Streamable HTTP only) | n/a |
| Session-binding probe | **implemented** (Streamable HTTP, stateful revisions; not applicable on `2026-07-28`) | n/a |
| Tool-enumeration probe | **implemented**, opt-in | n/a |
| Metadata-identity conformance probe | **implemented** (Streamable HTTP, where a provider discovers its token endpoint) | n/a |
| Open-registration conformance probe | **implemented**, opt-in — writes to the target's authorization server, and reports without gating | n/a |
| Token-passthrough conformance probe | **implemented**, opt-in — needs a canary endpoint you run | n/a |
| Transport | **implemented** (Streamable HTTP and stdio) | **implemented** (HTTP/HTTPS) |
| Matrix scaffolding | **implemented** — a live server or a saved listing drafts a full matrix | **partial** — OpenAPI drafts a full matrix with `--with-policy`; a HAR capture drafts resources only, with no policy |
| Credential acquisition | **partial** — everything REST does, plus RFC 9728/8414/8707 discovery; the interactive authorization-code flow is not supported | **implemented** (arbitrary login request, OAuth 2.1 password and client-credentials grants) |
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
  mcp:
    servers:
      - name: docs
        url: http://127.0.0.1:9000/mcp     # Streamable HTTP (JSON-RPC)

subjects:
  - { name: alice, role: user,  token: "${ALICE_TOKEN}", marker: "alice@corp", attributes: { doc_id: d-a1 } }
  - { name: bob,   role: user,  token: "${BOB_TOKEN}",   marker: "bob@corp",   attributes: { doc_id: d-b1 } }
  - { name: root,  role: admin, token: "${ADMIN_TOKEN}", attributes: { doc_id: d-a9 } }
  - { name: anon,  role: anonymous, token: null }

resources:
  - name: read_document
    call: { server: docs, tool: read_document }
    type: object            # object-level -> BOLA surface on the tool argument
    owner: doc_id           # the argument that must match the caller's own
    owner_attr: doc_id
  - name: list_all_users
    call: { server: docs, tool: list_all_users }
    type: function          # function-level -> BFLA surface

policy:
  read_document:
    allow:
      - { role: user, scope: own }    # a user may read only their own document
      - { role: admin, scope: any }   # admins may read anyone's
  list_all_users:
    allow:
      - { role: admin }               # admin-only
```

The same file reaches a REST API by giving a resource a `request:` instead of a
`call:`, and a `modules.rest.base_url` to send it to — the [REST worked
example](#worked-example-the-rest-module) is that file. Nothing above the
`modules:` block changes, which is what lets one matrix span both doors to the
same object.

Every **deny** case the planner derives is a probe: if the target answers it
successfully, that is a finding. Every **allow** case is a control: if the target
refuses it, either the matrix or the target is wrong, and overstep reports
`unexpected-deny`.

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
Defects (7) — one line per thing to fix:
  privilege-escalation  tools/call list_all_users  as alice, anon, bob  (high, confirmed)
  session-hijack  tools/list docs  as alice, bob, root  (high, confirmed)
  BOLA  resources/read doc://acme/{doc_id}  as alice, bob  (high, confirmed)
  BOLA  tools/call read_document  as alice, bob  (high, confirmed)
  privilege-escalation  resources/read doc://acme/{doc_id}  as anon  (high, confirmed)
  privilege-escalation  tools/call read_document  as anon  (high, confirmed)
  tool-enumeration  tools/list docs  as alice, bob  (medium, confirmed)
```

Its matrix is the one above with a second door added — the resource URI — so the
same two documents are reached two ways:

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
| `report.html` | humans — findings with evidence and repro, every case, filters by class, resource and subject |
| `findings.json` | scripts and dashboards (CWE + OWASP tagged), with every case and its outcome |
| `overstep.sarif` | GitHub code scanning |
| `junit.xml` | CI test reporters |

Both documents open by saying which run they describe — the targets, when it
started and how long it took, the overstep version, the matrix file, and whether
the run was read-only or narrowed to part of the matrix — and both list every
case the run planned, not only the ones that went wrong: `cases` in
`findings.json`, a collapsed table in the page. A case is recorded by its method,
path, status and outcome (`passed`, `finding`, `waived`, `skipped` or
`undelivered`); no header and no body, so no credential. The page is one file
with nothing loaded from anywhere.

`overstep run` exits non-zero on findings, so it fails a pipeline out of the box.
A stdio variant of the same demo lives at `examples/mcp_api/matrix_stdio.yaml`,
and the server that *enforces* this matrix at
[`examples/secure_mcp/`](examples/secure_mcp/):

```bash
python -m uvicorn examples.secure_mcp.server:app --port 9010
overstep run examples/secure_mcp/matrix.yaml --out out
```

The same 27 tests, zero vulnerabilities, exit 0 — with both object doors probed
across owners, all 8 expected-allow tests allowed, and the session and
enumeration probes *run and passed* rather than skipped. On this
surface especially, a clean result needs that second half: there is no status
code to lean on, so a server that answered nothing looks much like one that
refused correctly.

### Worked example: the REST module

The other door. A deliberately broken HTTP API ships with the repository, and it
is the same three parts over a different transport — which is how you point
overstep at the API behind an MCP server, and the reason
[§ the API behind the server](#when-testing-an-mcp-server-means-testing-the-api-behind-it)
is not a hypothetical.

```bash
python -m uvicorn examples.rest_api.server:app --port 8000
overstep plan examples/rest_api/matrix.yaml
```

`plan` sends nothing. It prints the eighteen cases that demo's matrix — the same
three parts over HTTP, plus a `delete_user` resource — expands into, every
subject against every resource:

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
cross-owner probe disappears, which is why `validate` warns about it — both when
every subject shares one object, and when only some do and are quietly probed
against a third subject instead of each other.

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
Defects (3) — one line per thing to fix:
  privilege-escalation  DELETE /users/{id}  as alice, bob  (high, confirmed)
  privilege-escalation  GET /admin/users  as alice, bob  (high, confirmed)
  BOLA  GET /users/{id}  as alice, bob  (high, unverified)
```

Eight probes got through, tracing back to **three** distinct defects — one line per
thing to fix, with the subjects that reached it as evidence of blast radius. The
terminal names them, so a CI log is enough to act on: up to 20 defects, then a
pointer to `report.html`. Requests the matrix allows and the target refused are
listed separately as *unexpected denials*, because they usually mean the matrix
is wrong rather than the target.

The same matrix against a target that *does* enforce it ships alongside, at
[`examples/secure_api/`](examples/secure_api/):

```bash
python -m uvicorn examples.secure_api.server:app --port 8010
overstep run examples/secure_api/matrix.yaml --out out
```

Zero vulnerabilities and exit 0 — and, the part worth checking, a conclusive run
with all 7 expected-allow tests allowed and both object resources probed across
owners. An unreachable target reports zero too, so the second half is
what makes the first mean anything; see
[what a clean result is allowed to mean](#what-a-clean-result-is-allowed-to-mean).

### Pointing it at your own target

```bash
overstep scaffold http://127.0.0.1:9000/mcp --fmt mcp --server-name docs \
    --token "$TOKEN" > matrix.yaml        # MCP: a full matrix
overstep scaffold openapi.yaml --with-policy > matrix.yaml   # REST: a full matrix
overstep scaffold traffic.har --fmt har > resources.yaml     # REST: resources only
```

**The endpoint's spelling.** A Streamable HTTP server mounted at `/mcp/` commonly
answers `/mcp` with a `307`, so overstep follows a redirect once — and only a
`307` or `308`, and only while it stays on the scheme, host and port the matrix
declared. The status matters: `303` means "GET the other URI" and `301`/`302` are
rewritten to GET by convention, so replaying a JSON-RPC POST to any of them is
not what the server asked for, and would run a mutating `tools/call` twice if the
first endpoint had already dispatched it. The origin matters because a credential
must not be replayed at a host you did not name. A cross-origin redirect is
refused and recorded as a request that never arrived — so the run is
inconclusive and the message names both ends, rather than the body-less `3xx`
being scored as the server's answer.

For MCP, overstep reads **both** `tools/list` and `resources/templates/list`, so
the second door is in the draft from the start, and it records which
[protocol revision](#mcp-protocol-revisions) the server speaks. For OpenAPI,
`--with-policy` reads the document's own `security` declarations; a document that
describes no authorization at all yields a deny-by-default guess behind an
explicit warning, because reading silence as "everything is public" would produce
a matrix with zero negative tests.

The scaffold leaves `PASTE_..._TOKEN` and `REPLACE_ME_1` / `REPLACE_ME_2` where it
cannot know the answer — and `REPLACE_ME_BASE_URL` when the document names no
`servers`, or `REPLACE_ME_MCP_URL` when an MCP matrix is drafted from a saved
listing without `--server-url`, rather than guessing an address something else
may be listening on.
`validate` reports each one as an error with its line, and `run` and `snapshot`
send nothing while any remain. An explicit `--base` stands in for the base URL
placeholder, and for nothing else. Two things to get right: give the two peer
subjects genuinely **different** objects, and keep secrets out of the file
(`${ALICE_TOKEN}` from the environment or `--env-file`). Then review the starter policy — it is a
guess, and it is the one part of the file only you can write.

```bash
overstep validate matrix.yaml          # structural errors and leftover placeholders
overstep validate matrix.yaml --live   # one expected-allow request per subject
overstep plan matrix.yaml              # read every request before sending one
overstep run matrix.yaml --out out --read-only
```

A key the matrix format does not have is reported where you are, not where the
validator is: `line 10: resource 'get_order' has an unknown key
'forbiden_fields' — did you mean 'forbidden_fields'?`.

`--live` proves each credential is still accepted, which matters because an
expired token turns every negative test into a pass for the wrong reason. It is
side-effect free: probes go out read-only and non-mutating operations are
preferred. It sends nothing while the file itself has an error — a placeholder
token proves nothing about a credential.

**A worked example against a target nobody here wrote.**
[`examples/crapi/`](examples/crapi/) points overstep at a live
[OWASP crAPI](https://github.com/OWASP/crAPI), with real accounts, real tokens
and real object ids obtained through crAPI's own signup flow. It ships a matrix per
surface — the REST gateway, and the MCP server the same instance exposes — both
keyed to the same vehicles, so a finding on one and a finding on the other are
the same defect reached two ways. Its README has the steps, including the two
things that are easy to get wrong: giving two identities genuinely different
objects, and keying a vehicle by its uuid rather than by its owner's numeric id.

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
stdio repro; a session-binding finding gets the two-step form its defect
requires; a [conformance](#the-mcp-protocol-probes) finding has no credential in
it at all, because neither of those probes presents one — which makes it the one
repro you can forward to the server's owner exactly as the report prints it.

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

```yaml
auth:
  providers:
    - name: login
      type: http
      request:
        method: POST
        path: /auth/login
        body: { email: "{{email}}", password: "{{password}}" }
      token_path: "$.data.access_token"     # where the token is in the response
subjects:
  - name: alice
    role: user
    auth: { provider: login, vars: { email: alice@shop.test, password: "${ALICE_PW}" } }
```

**Real objects.** Meaningful object-level testing needs a real owned object.
`objects:` maps each subject to the id it owns; `setup:` steps run once before the
suite as a chosen subject and `extract` values into a capture context that fills
`{{name}}` placeholders, including in `objects:`; `teardown:` steps clean the
fixtures up best-effort afterwards. A runnable version of exactly this lives at
[`examples/mcp_api/matrix_setup.yaml`](examples/mcp_api/matrix_setup.yaml).

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

Six checks run against every Streamable HTTP server beyond what the matrix
declares. The first three ask about the **credential** and the **connection**
rather than about any one operation; the last three ask whether the server meets
a requirement the specification places on it, whoever is asking. None is
available on stdio, where identity is an environment variable the server itself
named rather than anything travelling on a connection.

| Probe | Default | Asks |
|---|---|---|
| Credential audience | on | does the server check who the credential was issued *for*? |
| Session binding | on | can a session id stand in for a credential? |
| Tool enumeration | off | is the privileged half of the catalogue advertised to everyone? |
| Metadata identity | on | does the server's OAuth metadata name the server? |
| Open registration | off | will its authorization server register a client for anyone? (reported, never gating) |
| Token passthrough | off | does the server forward *your* credential to an upstream API? |

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
as the subject, then sends an **anonymous** request carrying that session id. Two
controls decide whether the answer means anything, and both have to agree before
it is a finding:

- **the same request without the session id.** A server whose listing is simply
  public answers that too, and calling it a hijack would be a finding about
  nothing.
- **the same request with a session the anonymous caller opened itself.** The
  first control is not enough on a stateful server: such a server requires a
  session id on *every* request and refuses one that carries none with a
  protocol error — `Bad Request: Missing session ID` — which says nothing about
  authority. On its own, that control can never clear the probe, so every
  subject would yield a confirmed hijack for free. What makes a hijack real is
  that the victim's session carried authority the caller could not obtain alone;
  if the caller can open its own session and be served **the same access**, it
  could not have. Such a server needs no credential at all, which the
  function-level and enumeration probes report instead.

  What is compared is the access, not the two outcomes, and both catalogues are
  followed to the last page. A server may let anyone open a session and still
  filter the listing by the identity bound to it, which allows both requests
  while the victim's session returns more of the catalogue than the caller could
  reach alone — the defect, and invisible if both are read as merely "allowed".

  The control also has to answer, and a server has two ways of saying the same
  thing: it may refuse the anonymous handshake (`401`/`403`), or accept it and
  issue no session id — a `200` whose whole message is the absent header. Both
  confirm the hijack. Anything else — no response, a `500`, a `429` that
  outlived its retries, a control request that fails after its handshake
  succeeded — says nothing, and the probe is skipped with the reason rather than
  resting a high-severity finding on a dropped connection.

A server that issues no session id has nothing to hijack, and the probe is
recorded as skipped rather than passed — as it is when the second control shows
there was nothing to gain.

**Tool enumeration.** Opt-in via `modules.mcp.probes.tool_enumeration: true`, because listing
everything and enforcing at call time is a common and defensible design. It calls
`tools/list` as each subject and compares the result against the policy already
written; a paginated listing is followed to the end. A tool the matrix does not
declare is *undescribed* rather than disallowed — that is
[coverage](#what-a-clean-result-is-allowed-to-mean)'s gap to report — and a subject
that cannot list at all has nothing to disclose. Enumeration probes are never
counted as positive controls, since a public listing answers with no credential at
all.

**Server conformance.** Two requirements the MCP authorization specification
places on the server rather than on its policy, grouped under
`modules.mcp.probes.conformance`.

*Metadata identity* is on by default and sends nothing of its own. Before
overstep will request a token it already checks that the documents a server
serves describe that server: the `resource` in its Protected Resource Metadata
(RFC 9728 §3.3), the `issuer` in its Authorization Server Metadata (RFC 8414
§3.3), that no redirect moved a metadata fetch to another origin, and that both
hops are HTTPS. A document failing any of those still **stops the run** — the
next thing to travel that way is a client secret — and now also produces a
`metadata-spoof` finding, so the report says why it stopped instead of leaving a
console line and no documents. Such a run is reported as inconclusive: one
finding about the metadata is not a tested authorization surface.

*Open registration* is opt-in, the one write overstep aims at a third party,
and the only finding in this tool that is **not a defect**. It POSTs an RFC 7591
client registration — carrying no credential — to the authorization server the
target named, and reports `open-registration` when a `client_id` comes back. It
needs a redirect URI you control, so that what it minted is recognisable as its
own; `--read-only` skips it, and the phased dispatcher sends it last with the
other writes. Whatever the response holds, a `client_secret` or a registration
access token it just issued is removed before the evidence is stored: those are
credentials this run caused to exist, so the masking that covers the ones your
matrix declared cannot know about them.

Read the result as a property of the deployment, not as a hole. RFC 7591 §3 says
the endpoint **SHOULD** allow registration with no authorization, and no MCP
revision places an authentication requirement on it, so a server that registers
anonymously is doing what the specifications suggest. A caller that registers
gets its own client id bound to its own redirect URI and reaches nobody's
resources with it. overstep therefore scores it `low`, leaves it out of the
vulnerability count and fails no default gate on it — `--fail-on any` is what
includes it. What it is worth knowing for: it decides how much a client id is
evidence of, on a server where anyone can have one.

```yaml
modules:
  mcp:
    probes:
      conformance:
        metadata_identity: true
        open_registration: true
    canary:
      redirect_uri: https://canary.example/cb
```

*Token passthrough* is opt-in and is the one probe here whose question the
protocol answers with a flat **MUST NOT**: the server must not pass through the
token it received from the client, and if it calls an upstream API it acts as an
OAuth client to that API with a separate token of its own. A credential forwarded
instead reaches a host its owner never authorized and is replayable at every
service trusting the same issuer, which is why it scores above the audience
probe.

Nothing in the protocol reports what a server sent onward, so the matrix
supplies the observation point. Four values, and the probe does not run without
all of them:

```yaml
modules:
  mcp:
    probes:
      conformance:
        token_passthrough: true
    canary:
      upstream:
        url: https://canary.example/echo   # your endpoint; it echoes the request
        resource: fetch_page               # a declared resource whose tool takes a URL
        argument: url                      # which argument
        marker: overstep-canary-7f3a       # a string your canary echoes back
```

The echo returns as the tool's result, and three things have to hold before it
is a finding: the call was **allowed**, the canary's own **marker** came back,
and the caller's **credential** came back with it.

The marker is what makes the finding a confirmation rather than a guess. A tool
that reflects its arguments and headers to the caller — exactly the shape of
tool a canary gets pointed at — returns the credential having called nothing at
all, and some servers quote the credential they *refused* in their error text.
Neither carries the marker, and neither is reported.

So there are four outcomes and only one of them is a finding. A refusal, an
allowed call with no content, and an allowed call whose result does not carry
the marker are each reported as **inconclusive** with the reason: the server did
not reach the canary, or there was nothing to read, and silence about credential
handling must never be mistaken for a server that behaved. The marker coming
back **without** the credential is the fourth: a server using a separate
upstream token of its own, which is the specification being obeyed and a clean
pass.

The credential the probe recovers is masked everywhere a report could carry it —
the body, the headers, and the matched marker that confirmed the finding.

On revision `2026-07-28` Dynamic Client Registration is marked deprecated — new
implementations should use Client ID Metadata Documents — but it is retained as
a `MAY` for backwards compatibility, with no removal date and still no
authentication requirement on the endpoint.

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
§3.3); and a metadata request must not be redirected to another origin. Each
failure stops the run *and* is reported as a `metadata-spoof` finding — see
[the conformance probes](#the-mcp-protocol-probes). None of those catches a
target that names an authorization server it simply owns and describes honestly
— `issuer:` is what refuses that, and `validate` warns when a provider sends a
secret without one.

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
`--read-only`, reports. None of the five protocol probes applies: there is no
connection to carry a credential or a session, and no OAuth metadata to check.

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
(POST/PUT/PATCH/DELETE over HTTP, any tool marked `mutating` over MCP, and the
client-registration conformance probe), and the run says so: `Tests run` counts what was sent, with the planned total and the
skipped count on rows of their own, the summary names the surfaces nothing was
sent to, and `findings.json` records `read_only`, `skipped_tests` and
`skipped_surfaces`. It does **not** skip `setup:` and `teardown:` steps, which
still run and still change state, and a mutating operation the matrix declares as
non-mutating is still sent — the flag reads the declaration, not the target.
`--max-retries N` (default 2) retries `429`/`503`, honouring `Retry-After`.
`--concurrency N` bounds in-flight requests, and `--delay SECONDS` sets the least
time between the start of one test request and the next — across the whole pool
and from one phase of the run to the next, so it is a rate a target would
recognise rather than a pause multiplied by the
concurrency. `--timeout SECONDS` (default 15) is how long any connection waits,
logins and `setup:` steps included. `--proxy URL` sends every request through a
proxy; without it the usual `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY` variables
are honoured as they always were. Ready-made artifacts:
[`examples/ci/github-actions.yml`](examples/ci/github-actions.yml),
[`examples/ci/gitlab-ci.yml`](examples/ci/gitlab-ci.yml), the
`ghcr.io/kabiri-labs/overstep` image, and an `overstep-validate` pre-commit hook.

**Running part of the matrix.** `--resource NAME` and `--subject NAME` (both
repeatable) narrow a run to the cases you are working on; a subject narrows by
who sends the request, so its probes at other subjects' objects stay. Such a run
is **partial** and says so before the summary, inside it, in `findings.json`
(`partial`, `selection`, `planned_tests`) and at the top of the HTML report,
because a clean result for one resource says nothing about the rest. A name the
matrix does not declare is refused before anything is sent. `snapshot` does not
take these flags: a baseline of part of the matrix would report the rest as new.
`--verbose` prints one line per request on `stderr` as results come back —
method, path, subject, what came back and what was expected — and never a header
or a body.

**Destructive operations go last.** The plan is not sent as one concurrent pool.
Requests that change nothing go first; then writes that are not a `DELETE`,
together with every MCP tool marked `mutating`; then `DELETE`s. Inside steps 2
and 3 the requests the matrix expects *refused* go before the ones it expects
allowed, and `--concurrency` applies within a step. An allowed `DELETE` really
deletes, so sent alongside everything else it takes an object other requests
still target: they come back `404`, which is an unexpected denial on a different
test each run — and an expected-deny probe that "passes" against an object that
is no longer there. Ordering makes one run stable; it does not bring the object
back, so `validate` warns when a `DELETE` the policy allows shares its objects
with other resources at the same path or beneath it. Create those objects in
`setup:` and every run starts with its own; objects that are already
`{{captures}}` are not warned about.

**Reports are cleared before the run, not written after it.** `run` removes the
documents a previous run left in `--out` before it reads anything, because a run
that will not parse, finds no base URL, dies in setup or is interrupted never
reaches the writing step and would otherwise leave last week's reports looking
exactly like this run's — and a stale `Vulnerabilities 0` reads as a pass. Only
the filenames overstep's own reporters own are touched, and a file the run was
told to read, such as the matrix or a baseline, that sits on one of those names
is refused rather than deleted: the report of that name would overwrite it at the
end regardless.

### What a clean result is allowed to mean

An absence of findings is worth something only if the run could have seen them.
Two checks enforce that: a verdict on whether the run proved anything at all, and
a measure of how much of the surface it could reach.

**Inconclusive runs.** If the requests never arrived or the credentials were never
accepted, every negative test "passes" for the wrong reason and a naive summary
reads `Vulnerabilities 0`. overstep calls that run **inconclusive** and exits `3`.
A run is inconclusive when, for any one target, at least half its requests failed
at the transport layer, or nothing proves its credentials work — every
expected-allow test skipped, or none of the ones that ran allowed — or when the
run stopped before it could send anything, which today means a
[metadata document](#the-mcp-protocol-probes) that failed its identity check.
That last case is the one that can carry a finding and still be inconclusive: a
`metadata-spoof` says something about the server's OAuth documents and nothing
about whether it enforces your policy. The judgement is
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

**A matrix with an error in it is not run at all.** An error-level problem — a
`PASTE_..._TOKEN` nobody filled in, a policy naming a resource that does not
exist — stops `run` and `snapshot` with exit `2` before the first request,
auth-provider logins and `setup:` steps included. A run over such a file could
only mislead: a placeholder credential is refused everywhere, so every negative
test passes because nothing was authorized. And it is not harmless to send — an
untouched scaffold carries writes and deletes. `--allow-inconclusive` does not
change this; it is for a run that happened and proved nothing. Warnings do not
count; they describe a matrix that runs and tests less than it looks like, which
is a legitimate file with a gap worth naming. `validate` is where both are
cheapest to see, and `--strict` is what fails on the warnings too.

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
| `overstep validate MATRIX` | lint for structural problems and unfilled placeholders (`--live` probes the target, and takes `--timeout` and `--proxy`; `--strict` fails on warnings) |
| `overstep plan MATRIX` | print the generated test cases (no network; `--env-file` for a matrix whose credentials are `${VAR}`) |
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
| `--timeout SECONDS` | ✅ | ✅ | how long a connection waits (default 15) |
| `--delay SECONDS` | ✅ | ✅ | least time between request starts |
| `--proxy URL` | ✅ | ✅ | send every request through a proxy |
| `--resource NAME` | ✅ | — | run only this resource (repeatable; the run is partial) |
| `--subject NAME` | ✅ | — | run only this subject's requests (repeatable; the run is partial) |
| `--verbose` | ✅ | — | one line per request on `stderr` |
| `--env-file FILE` | ✅ | ✅ | dotenv for `${VAR}` values |
| `--allow-inconclusive` | ✅ | ✅ | report/write anyway, keeping the old exit code |
| `--insecure` | ✅ | ✅ | disable TLS verification |

Exit codes: **0** clean · **1** findings (per `--fail-on`) · **2** bad input or
setup failure — including a matrix with an error in it, which is refused before
anything is sent · **3** inconclusive run.

`run` and `snapshot` share one pipeline — authenticate → setup → plan → dispatch
(destructive operations last) → teardown — so every transport behaves identically
and setup fixtures are cleaned up even if a run is interrupted.

### Finding taxonomy

Every class maps to its CWE and OWASP API Security Top 10 entry, carried in the
SARIF rules (with a `security-severity` score) and on every JSON finding.

| Class | CWE | OWASP API Top 10 | Surface |
|---|---|---|---|
| BOLA | CWE-639 | API1:2023 | MCP, REST |
| BOPLA | CWE-213 | API3:2023 | MCP, REST |
| BFLA | CWE-285 | API5:2023 | MCP, REST |
| privilege-escalation | CWE-269 | API5:2023 | MCP, REST |
| token-audience | CWE-863 | API2:2023 | MCP |
| session-hijack | CWE-287 | API2:2023 | MCP |
| tool-enumeration | CWE-200 | API5:2023 | MCP |
| metadata-spoof | CWE-346 | API2:2023 | MCP |
| token-passthrough | CWE-522 | API2:2023 | MCP |
| open-registration | CWE-1188 | API8:2023 | MCP |

## What overstep does not do

Knowing the edges is part of deciding whether this fits.

- **It does not discover your surface.** You declare it. `scaffold` drafts a matrix
  from a live MCP server, an OpenAPI document or a HAR capture, but you review it.
- **It does not invent your policy.** The matrix *is* the specification. A wrong
  matrix produces wrong results; `validate`, the plan table and the coverage and
  inconclusive checks exist to catch the common mistakes, not to guess intent.
- **It does not test authentication.** Login strength, token forgery and session
  fixation are out of scope: overstep tests what an *already authenticated*
  identity is permitted to do. The exceptions are admitted by one rule and no
  other: the MCP specification places the requirement on the server under test.
  Three qualify today — credential audience validation, session binding and
  metadata identity. A requirement the spec places on the *client* or on the
  authorization server is not overstep's to check, which is why PKCE downgrade,
  `state` handling and redirect-URI matching are absent however often they
  appear in MCP flaw counts. The open-registration probe is not a fourth: it
  reports a permitted behaviour, which is why it never gates.
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
| MCP and REST modules as described above | **implemented** |
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
