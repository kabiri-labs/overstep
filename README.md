# overstep

**Authorization testing for MCP servers. Declare who may invoke which tool and reach which object, and overstep proves whether the server enforces it — including the REST API behind the server, in the same run.**

![Version](https://img.shields.io/badge/version-1.13.0-blue)
[![CI](https://github.com/kabiri-labs/overstep/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/kabiri-labs/overstep/actions/workflows/ci.yml)
![License](https://img.shields.io/badge/license-Apache--2.0-green)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)

An MCP server decides, on every call, whether this caller may invoke this tool
and reach this object. When that check is missing nothing looks wrong: the call
is well-formed, the result is an ordinary tool result, and the server hands one
tenant's documents to another. overstep takes the intended answer as a file,
turns it into positive and negative calls against a running server, and reports
every one that should have been refused and wasn't.

```
   authorization matrix  ──►  positive + negative tests  ──►  run  ──►  findings
   (subjects × resources)     (self / other, per role)      (MCP + the API behind it)
```

**Contents** · [Quick start](#quick-start) ·
[The matrix](#the-authorization-matrix) ·
[Common scenarios](#common-scenarios) ·
[Reading the output](#reading-the-output) ·
[Probes](#the-mcp-protocol-probes) ·
[Reference](#reference) ·
[How it works](#how-it-works) ·
[Non-goals](#what-overstep-does-not-do) ·
[Roadmap](#roadmap)

---

## Quick start

Five commands from nothing to a result you can act on.

```bash
pip install overstep                                    # Python 3.10+

# 1. draft a matrix from the server itself
overstep scaffold http://127.0.0.1:9000/mcp --fmt mcp \
    --server-name docs --token "$TOKEN" > matrix.yaml

# 2. fill in the two things only you know (see below), then lint it
overstep validate matrix.yaml

# 3. read every request before sending one
overstep plan matrix.yaml

# 4. send them
overstep run matrix.yaml --out out
```

`scaffold` asks the server for its tools and resource templates and writes a
whole matrix, including a starter policy. It leaves `PASTE_..._TOKEN` and
`REPLACE_ME_1` / `REPLACE_ME_2` where it cannot know the answer. **Two of those
are the whole job:** give two subjects genuinely *different* objects, and review
the policy — it is a guess, and the one part only you can write.

`run` exits non-zero on findings, so it fails a pipeline out of the box. Exit
codes: **0** clean · **1** findings · **2** bad input · **3** the run proved
nothing (see [Reading the output](#reading-the-output)).

No install needed:

```bash
docker run --rm -v "$PWD:/work" -w /work ghcr.io/kabiri-labs/overstep \
    run matrix.yaml --out out
```

---

## The authorization matrix

Three parts — **subjects** (who), **resources** (what), **policy** (the
allow-list). Everything not explicitly allowed is denied. `roles:` is ordered
least- to most-privileged, which is what separates a function-level finding from
vertical privilege escalation.

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
    type: object            # object-level: the BOLA surface, on the tool argument
    owner: doc_id           # the argument that must match the caller's own
    owner_attr: doc_id
  - name: list_all_users
    call: { server: docs, tool: list_all_users }
    type: function          # function-level: the BFLA surface

policy:
  read_document:
    allow:
      - { role: user, scope: own }    # a user may read only their own document
      - { role: admin, scope: any }   # admins may read anyone's
  list_all_users:
    allow:
      - { role: admin }               # admin-only
```

Three things to know, and the rest can wait:

- **A resource never names its module.** An HTTP `request`, an MCP `call` (a
  tool) or `read` (a resource URI) — the body is what places it, so a resource
  cannot contradict itself about what it sends.
- **Every deny case is a probe, every allow case is a control.** If the target
  answers a deny case, that is a finding. If it refuses an allow case, either
  the matrix or the target is wrong, and overstep says `unexpected-deny`.
- **`marker:` is what makes a finding confirmed.** A successful cross-owner call
  may have returned an empty list; the marker is the string that proves the
  victim's data actually came back.

Everything a run needs regardless of transport sits at the top level. Anything
that means something to one surface only lives under its name in `modules:`.

Credentials: any `${VAR}` is filled from the environment at load time
(`${VAR:-default}` for a fallback), or pass `--env-file`. A subject can instead
log in before the run; see [Common scenarios](#common-scenarios).

Runnable demos ship with the repository — a deliberately broken MCP server at
[`examples/mcp_api/`](examples/mcp_api/), the server that enforces the same
matrix at [`examples/secure_mcp/`](examples/secure_mcp/), the REST pair at
[`examples/rest_api/`](examples/rest_api/) and
[`examples/secure_api/`](examples/secure_api/), and a matrix against a live
[OWASP crAPI](https://github.com/OWASP/crAPI) at [`examples/crapi/`](examples/crapi/).

---

## Common scenarios

### An OAuth-protected remote server

Let the provider discover where to authenticate instead of hardcoding a token
endpoint. overstep reads the server's Protected Resource Metadata (RFC 9728),
then the Authorization Server Metadata (RFC 8414), and sends the resource
indicator (RFC 8707) so the token is audience-bound.

```yaml
auth:
  providers:
    - name: mcp_oauth
      type: oauth2_client_credentials
      discover_from: docs                  # the MCP server name, or a URL
      issuer: https://login.example.com    # where these credentials are registered
      client_id: "{{client_id}}"
      client_secret: "${CLIENT_SECRET}"
subjects:
  - { name: alice, role: user, auth: { provider: mcp_oauth, vars: { client_id: alice-app } } }
```

Discovery starts at the server under test, which means the least trusted host in
the picture names where your `client_secret` is posted. Four checks are
automatic and each failure both stops the run and reports a `metadata-spoof`
finding — see [the probes](#the-mcp-protocol-probes). **Set `issuer:`**: it is
the only thing that refuses an authorization server the target simply owns and
describes honestly, and `validate` warns when a provider sends a secret without
one.

### A local server over stdio

```yaml
modules:
  mcp:
    servers:
      - name: docs
        command: ["python", "server.py"]
        token_env: MCP_TOKEN           # each subject's token -> this env var
```

One process per subject, JSON-RPC over stdin/stdout. Everything else is
identical. None of the protocol probes applies: there is no connection carrying
a credential and no OAuth metadata to check.

### A user delegating to an agent

The caller is usually an agent acting for a person, and the question is whether
its authority shrank to what the delegation was meant to convey. Declare the
chain and what it must **not** reach:

```yaml
auth:
  providers:
    - name: agent-exchange
      type: oauth2_token_exchange      # RFC 8693
      token_url: https://as.example/token
      client_id: overstep

modules:
  mcp:
    delegation:
      - name: agent-for-alice
        delegator: alice               # the human, an existing subject
        actor: support-agent           # the agent identity
        grant:
          provider: agent-exchange
          scopes: [docs.read]          # what the delegation is meant to convey
        expect:
          denied: [read_salary, list_all_users]
          actor_claim: required        # see below
```

overstep takes alice's credential, exchanges it for the agent's, and probes each
`denied:` resource as the agent. An object resource is probed at **alice's**
object, because that is the interesting reach, and her `marker:` confirms a real
read. Reached → `scope-escalation`. Refused → the pass.

**`denied:` names resources rather than being derived from scopes, and that is
deliberate.** RFC 8693 places no attenuation requirement on a token exchange —
the word does not appear in it, and the `scope` parameter is a *suggested*
mitigation in its security considerations. So the boundary here is one you drew,
not one the specification drew, and the finding says so. Deriving the probe from
scopes would also need a scope-to-resource mapping this matrix does not have,
and would make you restate in scope terms what your policy already says in role
terms.

What the RFC does give is a check worth having: section 2.2.1 requires the
exchange response to carry `scope` whenever the issued scope differs from the
one requested. So if your authorization server declined the request, the run
says so and tells you the probes below tested the credential that was actually
issued.

`actor_claim: required` reports `delegation-opacity` when the delegated
credential carries no RFC 8693 `act` claim — nobody can say which agent acted
after an incident. It is off by default, scored lowest in the table and **never
gates**, because issuing that claim is at the authorization server's discretion
and its absence breaks no rule. It is an attribution defect, not an exploit.

### One matrix across MCP and the API behind it

The headline case, and the one an MCP-only check cannot see. An MCP server is
almost never the system of record: it is a façade over an API, and the check
either holds at the object or it does not. A server that enforces ownership
perfectly on every tool proves nothing about the object underneath it — anyone
reaching the API directly goes around the wrapper.

Give both doors the same objects, in one file:

```yaml
modules:
  rest:
    base_url: https://api.internal
  mcp:
    servers: [{ name: docs, url: https://mcp.internal/mcp }]

resources:
  - name: read_document            # through the MCP tool
    call: { server: docs, tool: read_document }
    type: object
    owner: doc_id
    owner_attr: doc_id
  - name: get_document             # the same object, through the API
    request: { method: GET, path: "/documents/{doc_id}" }
    type: object
    owner: doc_id
    owner_attr: doc_id
```

One run, one baseline, one report. A finding on one and not the other tells you
exactly where the check sits.

Three more reasons this matters. What the server's own service credential can
reach is the blast radius of a compromised MCP server — point the REST module at
the backing API with that credential and the answer is a list rather than a
guess; the companion question, whether the server forwards *your* credential
upstream, is what the
[token-passthrough probe](#the-mcp-protocol-probes) answers. A policy fix
landing on one door and not the other shows up as drift rather than as an
incident. And a deployment's health, admin and OAuth routes are plain HTTP
needing the same matrix.

### Gating a pull request on change

Finding today's holes is the first run. What compounds is the run after it,
because an authorization surface usually breaks by *changing*.

```bash
overstep snapshot matrix.yaml --out baseline.json                          # once, after triage
overstep run matrix.yaml --baseline baseline.json --fail-on vuln-or-drift  # every PR
```

**Gate on `vuln-or-drift`, not `drift`.** A diff only speaks about cells that
existed on both sides, so a newly added tool has nothing to differ from: it is
reported as a vulnerability, and a drift-only gate goes green on exactly the
case that motivates the baseline.

Pre-existing findings fail the build too, which is what **waivers** are for —
each accepted finding named by its stable `test_id`, with a reason and an
optional expiry, reviewed like any other code:

```yaml
# waivers.yaml
waivers:
  - id: read_document::alice::other
    vuln_class: BOLA
    reason: "Tracked in SEC-1234; fix scheduled next release."
    expires: 2026-12-31
```

Waived findings leave the gating set and stay visible in the reports; an expired
waiver stops suppressing and prints a warning. Keep `matrix.yaml`,
`baseline.json` and `waivers.yaml` in version control and authorization gets
reviewed like any other code. Ready-made CI artifacts:
[`examples/ci/`](examples/ci/).

### Running part of the matrix

```bash
overstep run matrix.yaml --resource read_document --subject alice --read-only
```

`--resource` and `--subject` are repeatable. Such a run is **partial** and says
so everywhere, because a clean result for one resource says nothing about the
rest. Neither flag applies to `snapshot`: a baseline of part of the matrix would
report the rest as new.

`--read-only` skips every mutating *test* — mutating verbs over HTTP, any tool
marked `mutating`, and the client-registration probe — and the run reports what
it did not send. Two exceptions matter if you are pointing this at something you
care about. It does **not** skip `setup:` and `teardown:` steps, which still run
and still change state. And a mutating operation the matrix declares as
non-mutating is still sent, because the flag reads the declaration, not the
target.

---

## Reading the output

Every run prints five sections, in this order, because the reader is usually
somebody scrolling a CI log days later with one of five questions.

```
overstep 1.13.0
authorization testing for MCP servers

Configuration ──────────────────────────────────────────────────
  overstep     1.13.0
  matrix       examples/mcp_api/matrix.yaml
  targets      http://127.0.0.1:9000/mcp
  started      2026-11-13T07:12:47+00:00
  fail-on      vuln
  concurrency  10
  timeout      15s
  probes       token-audience, session-binding, tool-enumeration,
               metadata-identity

Warnings ───────────────────────────────────────────────────────
  none

Results ────────────────────────────────────────────────────────
  planned  27 tests from 4 subjects × 4 resources
   Tests run               27
   Positive / negative     8 / 15 (+4 listing)
   Vulnerabilities         16 (7 defects)
   Object resources probed 2/2
  Defects (7) — one line per thing to fix:
    privilege-escalation  tools/call list_all_users  as alice, anon, bob  (high, confirmed)
    BOLA  resources/read doc://acme/{doc_id}  as alice, bob  (high, confirmed)
    …

Health ─────────────────────────────────────────────────────────
  conclusive — the run was in a position to see findings
  27 requests sent, 0 never delivered; 8/8 expected-allow allowed

Artifacts ──────────────────────────────────────────────────────
  reports  out/
```

| Section | Answers |
|---|---|
| Configuration | what ran — version, matrix, targets, and every setting that could change the numbers, including which optional probes were on |
| Warnings | what the matrix complained about, and anything teardown reported |
| Results | the counts, then one line per thing to fix |
| Health | whether the run is worth believing, printed whichever way it goes |
| Artifacts | where the documents went |

Three things worth understanding:

**One defect, not one finding per identity.** A missing check is reported once
per identity that reaches it, so one bug arrives as a dozen findings. The defect
roll-up is one row per thing to fix, with the subjects as evidence of blast
radius. Gating still counts findings.

**A finding carries a reproduction that runs.** A command and a structured
request record, with the credential left as a shell variable named after its
subject (`OVERSTEP_TOKEN_<SUBJECT>`), so the line is safe to paste into a ticket
and still works once the variable is set. No credential appears in any document
overstep writes.

**An absence of findings is worth something only if the run could have seen
them.** If the requests never arrived or the credentials were never accepted,
every negative test "passes" for the wrong reason. overstep calls that run
**inconclusive** and exits `3` — distinct from 1 and 2 so CI can tell "your
server has a hole" from "the scan never ran". A run is inconclusive when, for
any one target, at least half its requests failed at the transport layer, or
nothing proves its credentials work, or it stopped before sending anything.

**The credential half of that check needs expected-allow tests to work, on the
target you want it to speak for.** An allowed request is the only thing that
proves a credential is still accepted, so a target with no expected-allow case
has no such proof to lose. overstep does not condemn an intentionally
all-negative matrix for that — it reports conclusive and clean, and that is the
one case where a clean run does not mean the credentials worked. The judgement
is also per target, which is sharper than it looks: a matrix spanning a REST API
and an MCP server, with its only positive control on the REST side, says nothing
about the MCP server's credentials. If that server rejects every one of them,
its every expected-deny case is denied and the run reads conclusive and clean.
The healthy target does not vouch for the silent one. So give every target at
least one expected-allow case if you want expired credentials to fail the build;
unreachability is caught either way.

**Coverage.** `overstep coverage` measures the other half and sends nothing: the
*outer* gap is what the matrix never declared, measured against an independent
description of the surface (`--spec`), and the *inner* gap is what the run could
not ask about — a cross-owner probe is the only thing that tests object-level
authorization, and the planner generates one only where two subjects resolve to
genuinely different objects. `--fail-under N` gates on either percentage.

Reports land in `--out`:

| File | For |
|---|---|
| `report.html` | humans — findings with evidence and repro, every case, filters |
| `findings.json` | scripts and dashboards, CWE + OWASP tagged, every case and its outcome |
| `overstep.sarif` | GitHub code scanning |
| `junit.xml` | CI test reporters |

Both open by saying which run they describe, and list every case the run
planned — not only the ones that went wrong. A case is recorded by method, path,
status and outcome; no header and no body, so no credential.

---

## The MCP protocol probes

Six checks run against every Streamable HTTP server beyond what the matrix
declares. The first three ask about the **credential** and the **connection**;
the last three ask whether the server meets a requirement the specification
places on it, whoever is asking.

| Probe | Default | Asks |
|---|---|---|
| Credential audience | on | does the server check who the credential was issued *for*? |
| Session binding | on | can a connection identifier stand in for a credential? |
| Tool enumeration | off | is the privileged half of the catalogue advertised to everyone? |
| Metadata identity | on | do the server's OAuth documents name the server? |
| Open registration | off | will its authorization server register a client for anyone? (reported, never gating) |
| Token passthrough | off | does the server forward *your* credential to an upstream API? |

```yaml
modules:
  mcp:
    probes:
      token_audience: true
      session_binding: true
      tool_enumeration: false
      conformance:
        metadata_identity: true
        open_registration: false
        token_passthrough: false
    canary:
      redirect_uri: https://canary.example/cb       # for open_registration
      upstream:
        url: https://canary.example/echo            # for token_passthrough
        resource: fetch_page                        # a declared tool that takes a URL
        argument: url
        marker: overstep-canary-7f3a                # a string your canary echoes
```

**Credential audience.** A server must not accept a token that was not issued
for it. Declare what a subject's token is bound to (`token_audience: docs`, or
let a discovered provider infer it) and overstep replays that credential at
every server the audience does not identify. With no audience known, no probe is
generated: overstep does not guess which credential belongs where.

**Session binding.** Streamable HTTP hands out an `Mcp-Session-Id` and the spec
is explicit that it must not authenticate. The probe sends an anonymous request
carrying the subject's session id. Two controls must agree before it is a
finding — the same request without the id, and the same request with a session
the anonymous caller opened itself — because a public listing and a server that
needs no credential at all are different defects, reported by other probes. A
server that issues no session has nothing to hijack, and the probe is recorded
as skipped rather than passed.

**Tool enumeration.** Opt-in, because listing everything and enforcing at call
time is a defensible design. A tool the matrix does not declare is *undescribed*
rather than disallowed — that is `coverage`'s gap to report.

**Metadata identity.** On by default and sends nothing of its own: discovery
already checks that the documents a server serves describe that server. Each
failure both stops the run — the next thing to travel that way is a client
secret — and reports `metadata-spoof`, so the report says why it stopped.

**Open registration.** Opt-in, and the only finding here that is **not a
defect**: RFC 7591 section 3 says the registration endpoint should allow
requests with no authorization, and no MCP revision asks for a credential on it.
Scored low, left out of the vulnerability count, fails no default gate. What it
is worth knowing for: on a server where anyone can hold a client id, a client id
is evidence of less than it looks like. It writes to the target's authorization
server, so it needs a redirect URI you own and `--read-only` skips it.

**Token passthrough.** The one question the specification answers with a flat
**MUST NOT**: the server must not pass through the token it received, and if it
calls an upstream API it acts as an OAuth client there with a separate token of
its own. Nothing in the protocol reports what a server sent onward, so you
supply a canary that echoes the request it received. Three things must hold
before it is a finding: the call was allowed, the canary's marker came back, and
your credential came back with it. A refusal, an empty result, or a result
without the marker are **inconclusive** with the reason; the marker arriving
without the credential is the sound server and a clean pass.

**Protocol revisions.** Through `2025-11-25` a connection opens with an
`initialize` handshake and may carry a session. From `2026-07-28` the core is
stateless. overstep drives both, `scaffold` asks the server which it speaks, and
a mismatch ends the run as inconclusive rather than scoring it. Session binding
is reported as *skipped, not applicable* on `2026-07-28`, because the defect was
removed from the protocol rather than fixed in your server.

**Reading allow and deny.** There is no `403` in MCP, so the deny signal is
declared: `is_error_is_deny`, `jsonrpc_error_is_deny` and `deny_status` under
`modules.mcp.access`. The last is the one people miss — the spec has an
unauthorized request answered with `401` whose body need not be JSON-RPC at all,
so without reading the status the servers that reject *before* dispatching are
exactly the ones a run reports wide open.

---

## Reference

### Commands

| Command | What it does |
|---|---|
| `overstep scaffold SPEC` | draft a matrix from a live MCP server, `tools.json`, OpenAPI or HAR |
| `overstep validate MATRIX` | lint for structural problems and unfilled placeholders (`--live` probes the target; `--strict` fails on warnings) |
| `overstep plan MATRIX` | print the generated test cases, touching the network zero times |
| `overstep coverage MATRIX` | report what the matrix covers, against `--spec` and against its own object surface |
| `overstep run MATRIX` | generate, execute and report; non-zero exit on findings |
| `overstep snapshot MATRIX` | record current decisions as a drift baseline |
| `overstep version` | print the installed version |

Each command names the next on `stderr`; `OVERSTEP_NO_HINTS=1` switches that off.

### Flags

| Flag | `run` | `snapshot` | Meaning |
|---|:--:|:--:|---|
| `--base URL` | ✅ | ✅ | override the matrix base URL |
| `--out PATH` | ✅ | ✅ | report directory / baseline file |
| `--fail-on VALUE` | ✅ | — | `vuln` (default), `drift`, `vuln-or-drift`, `any`, `never` |
| `--baseline FILE` | ✅ | — | compare against a snapshot for drift |
| `--waivers FILE` | ✅ | — | accepted findings |
| `--read-only` | ✅ | ✅ | skip mutating tests — not `setup:`/`teardown:`, which still run and still write |
| `--resource NAME` | ✅ | — | run only this resource (repeatable; the run is partial) |
| `--subject NAME` | ✅ | — | run only this subject's requests (repeatable; partial) |
| `--concurrency N` | ✅ | ✅ | bound in-flight requests |
| `--delay SECONDS` | ✅ | ✅ | least time between request starts, across the whole run |
| `--timeout SECONDS` | ✅ | ✅ | how long a connection waits (default 15) |
| `--max-retries N` | ✅ | ✅ | retry `429`/`503`, honouring `Retry-After` |
| `--proxy URL` | ✅ | ✅ | send every request through a proxy |
| `--insecure` | ✅ | ✅ | disable TLS verification |
| `--env-file FILE` | ✅ | ✅ | dotenv for `${VAR}` values |
| `--allow-inconclusive` | ✅ | ✅ | report or write anyway, keeping the old exit code |
| `--verbose` | ✅ | — | one line per request on `stderr` |

Destructive operations go last: reads first, then writes that are not a
`DELETE` together with every mutating MCP tool, then `DELETE`s — so an allowed
`DELETE` does not remove an object other cases still target.

### Finding taxonomy

Every class carries its CWE and OWASP API Security Top 10 entry, in the SARIF
rules with a `security-severity` score and on every JSON finding.

| Class | CWE | OWASP API | Surface |
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
| scope-escalation | CWE-269 | API5:2023 | MCP |
| delegation-opacity | CWE-778 | API8:2023 | MCP |
| open-registration | CWE-1188 | API8:2023 | MCP |
| authorization-drift | — | — | MCP, REST |
| unexpected-deny | — | — | MCP, REST |

### Module maturity

Conservative markers: **implemented** means exercised by the test suite;
**partial** means it works within a stated limit; **planned** means not built.

| Capability | MCP | REST |
|---|---|---|
| Object-level (BOLA) probes across owners | **implemented** (tool arguments and resource URIs) | **implemented** |
| Function-level (BFLA) and privilege-escalation probes | **implemented** | **implemented** |
| Property-level (BOPLA) forbidden response fields | **implemented** | **implemented** |
| Multi-tenancy isolation via policy conditions | **implemented** | **implemented** |
| Ownership injection points | **implemented** (tool argument, resource URI placeholder) | **implemented** (path, query, header, cookie, form, JSON body, GraphQL variables) |
| Cross-method probing | n/a — MCP has no verb | **implemented** (`probe_methods`) |
| Credential audience probe | **implemented** (Streamable HTTP only) | n/a |
| Session-binding probe | **implemented** (Streamable HTTP, stateful revisions) | n/a |
| Tool-enumeration probe | **implemented**, opt-in | n/a |
| Metadata-identity conformance probe | **implemented** (where a provider discovers its token endpoint) | n/a |
| Open-registration conformance probe | **implemented**, opt-in — writes to the target's authorization server, and reports without gating | n/a |
| Token-passthrough conformance probe | **implemented**, opt-in — needs a canary endpoint you run | n/a |
| Transport | **implemented** (Streamable HTTP and stdio) | **implemented** (HTTP/HTTPS) |
| Matrix scaffolding | **implemented** — a live server or a saved listing drafts a full matrix | **partial** — OpenAPI drafts a full matrix with `--with-policy`; a HAR capture drafts resources only |
| Credential acquisition | **partial** — everything REST does, plus RFC 9728/8414/8707 discovery; the interactive authorization-code flow is not supported | **implemented** (arbitrary login request, OAuth 2.1 password and client-credentials grants) |
| Delegation-chain and scope-attenuation testing | **implemented**, opt-in — a declared chain and what it must not reach | n/a |

The bundled demos are a subset: they cover object- and function-level probes,
resource reads, session binding and tool enumeration. Property-level checks,
policy conditions, cross-method probing, credential audience, OAuth discovery
and the three conformance probes are covered by tests rather than by a demo
matrix — the conformance ones need an authorization server that misbehaves,
which is not something a demo you are invited to run should ship.

---

## How it works

### Why it has to be declared

Most vulnerability classes have a syntactic tell. Authorization has none:
`read_document(doc_id: "d-8842")` is a valid call whether or not that document
belongs to the caller, and the two are byte-identical apart from an identifier.
To call a successful result a finding you must already know this subject was not
supposed to reach this object — and that lives in a product decision, not in a
tool description or an OpenAPI document. The failure is silent by construction:
no error, no log line, nothing that looks anomalous.

So half the problem is discoverable and half is not. An MCP server describes its
own surface, which is why `scaffold` drafts a whole matrix from a live server.
What no server returns is who may reach what, and which ids belong to whom.
That part is declared, and it is the one part only you can write.

### MCP: the hardest instance

One problem class, and MCP is where it is currently hardest to reason about:

- **The caller is an agent, not a person.** Authorization depends on a
  delegation chain rather than a single authenticated principal, and every hop
  is somewhere authority can fail to shrink to what the delegation meant to
  convey. That is the structural difference from a REST endpoint answering one
  user directly, and the part still on the [roadmap](#roadmap).
- **There is no `403`.** A refusal arrives in-band as a JSON-RPC error or an
  `isError` result, or on the HTTP leg as a `401` whose body is not JSON-RPC at
  all. A checker reading only one of those calls a secure server wide open, or a
  broken one clean.
- **The surface is wider than the tool list.** The same objects are reachable
  through `resources/read` by URI. A server can enforce ownership perfectly on
  every tool and hand the data out through the other door.
- **The protocol carries authorization requirements of its own**, which are not
  questions about your policy and do not surface in any test of your tools. See
  [the probes](#the-mcp-protocol-probes).

### The shared core

REST and MCP are two surfaces on one problem class, not two tools sharing a
repository. Everything except delivery is common: the matrix model, the planner,
ownership resolution, the classifier, confidence grading, drift, waivers and
every report format. Each surface is a package under `overstep/modules/`
reaching the core only through registries — how a case is delivered, how a
finding is rendered, how a setup step runs, where a credential is discovered,
which finding classes it can report, and which cases it contributes itself.
Neither module sits at the package root, neither may import the other, the core
may not import either, and an import-graph test measures all three.

That the same code finds the same defect on either door is the evidence that
none of this is MCP-specific hand-waving, and it is what makes one matrix across
both surfaces possible at all.

---

## What overstep does not do

- **It does not discover your surface.** You declare it; `scaffold` drafts and
  you review.
- **It does not invent your policy.** The matrix *is* the specification. A wrong
  matrix produces wrong results, and `validate`, `plan` and the coverage and
  inconclusive checks exist to catch the common mistakes, not to guess intent.
- **It does not test authentication.** Login strength, token forgery and session
  fixation are out of scope. The exceptions are admitted by one rule and no
  other — the MCP specification places the requirement on the server under test
  — and three qualify: credential audience, session binding, metadata identity.
  A requirement the spec places on the *client* or on the authorization server
  is not overstep's to check, which is why PKCE downgrade, `state` handling and
  redirect-URI matching are absent however often they appear in MCP flaw counts.
  The open-registration probe is not a fourth: it reports a permitted behaviour,
  which is why it never gates.
- **It tests one hop of a delegation chain, not all of them.** A declared
  `delegation:` proves whether the agent's credential reaches what the chain
  said it must not, at the callee overstep is talking to. Whether a *downstream*
  service re-checks what an upstream one allowed is [roadmap](#roadmap) — and
  once the matrix declares that downstream resource, the ordinary planner
  already tests it as a resource carrying the delegated credential, which is the
  supported way to express a second hop today.
- **It is not an AI or LLM security tool.** It does not drive an agent with
  prompts and has no opinion about tool descriptions. Prompt injection and tool
  poisoning *against the agent* are a separate, non-deterministic concern, and
  the two are complements: a description scanner will not tell you the server
  hands `doc://acme/anyone` to whoever asks.
- **It does not fuzz.** Every request is one the matrix asked for, which is what
  makes results deterministic and diffable.
- **It is a test, not a control.** It runs in CI against a target you nominate
  and enforces nothing at runtime.
- **It sends real requests.** Use `--read-only` against anything you care about.

---

## Roadmap

Short and honest. Nothing here is scheduled.

| | Status |
|---|---|
| MCP and REST modules as described above | **implemented** |
| Re-checking a delegated credential at each hop of a chain, rather than at the callee overstep talks to | **planned** |
| Policy inference when scaffolding from a HAR capture | **planned** |
| Interactive OAuth authorization-code flow for subjects that cannot use a machine grant | **planned** |
| Further surfaces | **planned**, unscheduled — a third is a package under `overstep/modules/`, an executor, a body shape and a config block; the registries carry the rest |

### What 1.0.0 means

The matrix format, the `test_id` shape, the finding classes and their wire
values, the exit codes and the report documents are the surface this version
freezes. They are pinned by golden files that fail on any change, so a release
that moves one has to say so. It does not mean the roadmap is finished — it
means the parts you would build a pipeline against have stopped moving
underneath you.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the layout, the standards and how to
run the suite. Two rules shape every change: a run that proves nothing must
never report clean, and a probe that proves nothing does not ship.

```bash
git clone https://github.com/kabiri-labs/overstep && cd overstep
pip install -e ".[dev]"
pytest -q
```

Security issues: [SECURITY.md](SECURITY.md). Responsible use: overstep sends
real requests to a target you name — have authorization for it.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
