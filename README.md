# overstep

**Authorization testing for MCP servers. Works on HTTP APIs too.**

![Version](https://img.shields.io/badge/version-0.33.0-blue)
![CI](https://img.shields.io/badge/CI-GitHub%20Actions-blue)
![License](https://img.shields.io/badge/license-Apache--2.0-green)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)

You write down who is allowed to do what. overstep turns that table into concrete
requests — **positive** tests for access that should succeed and **negative**
tests for access that should be denied — fires them at a running server, and
reports every negative test that got through.

```
   authorization matrix  ──►  positive + negative tests  ──►  run  ──►  findings
   (subjects × resources)     (self / other, per role,        (BOLA, BFLA, BOPLA,
                               plus the MCP protocol           privesc, audience,
                               probes)                         session, drift)
```

Findings are classified, mapped to **CWE / OWASP API Top 10**, graded by
**confidence** (did the victim's data actually come back?), and shipped with a
command that reproduces them. Snapshot the results and CI fails the moment your
authorization surface **drifts**.

---

**Contents**

[Why MCP needs this](#why-mcp-authorization-needs-its-own-tool) ·
[What it finds](#what-overstep-finds) ·
[What it doesn't do](#what-it-doesnt-do) ·
[Install](#install) ·
[**Quickstart**](#quickstart-the-vulnerable-mcp-demo) ·
[**Point it at your own server**](#point-it-at-your-own-mcp-server) ·
[The matrix](#the-authorization-matrix) ·
[The MCP surface](#the-mcp-surface) ·
[Trustworthy findings](#making-findings-trustworthy) ·
[Modelling a real target](#modelling-a-real-target) ·
[HTTP APIs](#http-apis) ·
[Running in CI](#running-in-ci) ·
[Commands](#command-reference) ·
[Taxonomy](#finding-taxonomy) ·
[Where this sits](#where-this-sits)

---

## Why MCP authorization needs its own tool

An MCP server is an API with the authorization problem turned up. It hands an
agent a catalogue of tools and resources, and every one of them is a way to reach
somebody's data. The bugs are the familiar ones — a tool that reads any document
id it is given, an admin-only tool with no role check — but three things make them
harder to catch than in a normal API:

- **There is no `403`.** A refusal arrives in-band, as a JSON-RPC error or an
  `isError` result, or on the HTTP leg as a `401` whose body is not JSON-RPC at
  all. A checker that reads only one of those calls a secure server wide open, or
  a broken one clean.
- **The surface is bigger than the tool list.** The same objects are reachable
  through `resources/read` by URI. A server can enforce ownership perfectly on
  every tool and hand the data out through the other door.
- **The protocol has authorization rules of its own.** A server must refuse a
  token that was not issued for it, and must not let a session id stand in for a
  credential. Neither is a question about your policy, and neither shows up in
  any test of your tools.

overstep tests the **server's** enforcement, deterministically: every request is
one your matrix asked for, so results are diffable, gateable, and the same on
every run. It covers all three of the above — and the same matrix file tests
[HTTP APIs](#http-apis), whether they sit behind an MCP server or stand on their
own.

## What overstep finds

Most authorization bugs aren't a missing `if` in one handler — they're a *cell*
in a table nobody wrote down. "Can a plain user read another user's document?" is
a question about the intersection of a **role**, a **resource** and an **ownership
scope**. overstep makes that table explicit and tests every cell.

| Class | What it means | Example probe |
|---|---|---|
| **BOLA** | a subject reaches *another subject's* object | `read_document(doc_id=…)` for an id they don't own; `resources/read doc://acme/…` |
| **BFLA** | a subject invokes a function their role shouldn't have | `list_all_users` as a normal user |
| **Privilege escalation** | a lower-privileged role reaches something reserved for a higher one | a `user` calling `reset_tenant` |
| **BOPLA** | an allowed response exposes a *field* the caller shouldn't see | `password_hash` in a document |
| **Token audience** | a server honours a credential issued for somewhere else | a token minted for server A accepted by server B |
| **Session hijack** | a session id is accepted in place of a credential | a call carrying only somebody else's `Mcp-Session-Id` |
| **Tool enumeration** | a server advertises tools the caller may not invoke | `reset_tenant` listed to a plain user |
| **Authorization drift** | a decision that changed since your last release | a cell that flipped deny → allow |

The last four are MCP-specific. The first four apply to MCP and HTTP alike.

## What it doesn't do

Knowing the edges is part of deciding whether this fits:

- **It doesn't discover your surface.** You declare it; `scaffold` drafts the
  matrix from a live MCP server, an OpenAPI spec or a HAR capture, but you review
  it.
- **It doesn't invent your policy.** The matrix *is* the specification. A wrong
  matrix produces wrong results — `validate`, the plan table and the
  [inconclusive-run check](#inconclusive-runs-the-gate-refuses-to-fail-open)
  exist to catch the common mistakes, not to guess your intent.
- **It doesn't drive an agent with natural-language prompts.** It tests the
  server's enforcement directly. Prompt injection and confused-deputy attacks
  *against the agent* are a separate, non-deterministic concern.
- **It doesn't test authentication.** Login strength, token forgery and session
  fixation are out of scope; overstep tests what an *already authenticated*
  identity is permitted to do. Two deliberate exceptions, both because the MCP
  spec makes them requirements **of the server**: that a credential issued for a
  [different audience](#token-audience-the-credential-that-belongs-somewhere-else)
  is refused, and that a
  [session id is not treated as one](#session-binding-what-a-connection-alone-is-worth).
- **It doesn't fuzz.** Every request is one the matrix asked for, which is what
  makes results deterministic and diffable.
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

To work on overstep itself, or to run the bundled demos, clone the repo and
install it editable — see [CONTRIBUTING.md](CONTRIBUTING.md):

```bash
git clone https://github.com/kabiri-labs/overstep && cd overstep
pip install -e ".[dev]"
```

**The five commands**, in the order you meet them:

| | |
|---|---|
| `overstep scaffold` | draft a matrix from a live server or a spec |
| `overstep validate` | lint it — and with `--live`, check every credential still works |
| `overstep plan` | print what it *would* send, touching the network zero times |
| `overstep run` | send it and report |
| `overstep snapshot` | record today's decisions as a drift baseline |

Each one ends by naming the next on `stderr`, so the sequence doesn't have to be
memorised. Set `OVERSTEP_NO_HINTS=1` to switch that off.

## Quickstart: the vulnerable MCP demo

Two minutes, against an intentionally-broken MCP server that ships with the repo.

```bash
# 1. start the demo server
python -m uvicorn examples.mcp_api.server:app --port 9000

# 2. in another shell, run the matrix against it
overstep run examples/mcp_api/matrix.yaml --out out
```

```
             overstep summary
 Tests run                            27
 Positive / negative   8 / 15 (+4 listing)
 Vulnerabilities           16 (7 defects)
   BOLA                                4
   privilege-escalation                5
   session-hijack                      3
   tool-enumeration                    4
 Object resources probed             2/2
```

Sixteen probes got through, tracing back to **seven** distinct bugs — one row per
thing to fix, with the subjects that reached it as evidence.

The four classes are two different kinds of question. `BOLA` and
`privilege-escalation` are about a declared operation: two of the BOLA findings
come through `tools/call` and two through `resources/read`, on the same two
documents, because the demo server has the same missing ownership check on both
doors — exactly the case a tools-only checker reports clean.

`session-hijack` and `tool-enumeration` are about the connection instead, and
they have no equivalent in an HTTP API scanner. The demo server hands out an
`Mcp-Session-Id` at `initialize` and then accepts it *in place of* a credential,
so anyone who reads one out of a log inherits the identity that opened it; and it
lists `list_all_users` and `reset_tenant` to plain users who cannot invoke them.
The listing probes are counted separately from the positive controls: they report
on what a listing contained, so no credential is proven by their success.

Reports land in `out/`:

| File | For |
|---|---|
| `report.html` | humans — findings with evidence and repro |
| `findings.json` | scripts / dashboards (CWE + OWASP tagged) |
| `overstep.sarif` | GitHub code scanning |
| `junit.xml` | CI test reporters |

`overstep run` exits non-zero when it finds a vulnerability, so it fails a
pipeline out of the box.

There is a **stdio** variant of the same demo — a local server process instead of
an HTTP endpoint — at `examples/mcp_api/matrix_stdio.yaml`.

## Point it at your own MCP server

The demo proves the tool runs. This is the part that matters — six steps from a
running server to a result you can trust.

### 1. Scaffold the matrix

```bash
overstep scaffold http://127.0.0.1:9000/mcp --fmt mcp --server-name docs \
    --token "$TOKEN" > matrix.yaml
```

Drop `--token` if the server lists to anyone; most require a credential, and the
bundled demo does too.

overstep asks the server what it exposes and drafts a full matrix — servers,
roles, placeholder subjects, resources and a starter policy. It reads **both**
listings, because drafting only the tools would build in the blind spot from the
start:

| Source | What you get |
|---|---|
| `tools/list` | a `call` per tool. An id-like argument becomes the `owner_arg` (the BOLA surface); `annotations.destructiveHint` — or a name that reads like a write — marks it `mutating` |
| `resources/templates/list` | a `read` per template. The URI placeholder is read the same way: an id-like `{doc_id}`, or a lone `{key}`, becomes the `owner_uri` |

A template with several placeholders and no obvious object among them —
`repo://{owner}/{repo}/tree` — gets one injection per placeholder, each from its
own subject attribute. Every one has to be filled or the URI goes out with a
literal brace in it, so the scaffold wires them all and leaves you to decide which
is the thing being owned. A template with no placeholder addresses one fixed
object, so it is drafted as a `function`.

Two things it will **not** draft: a template using an RFC 6570 operator
(`{+path}`, `{?query}`), which ownership substitution cannot fill — it says so on
stderr rather than emitting a resource that cannot work; and concrete
`resources/list` entries, since a fixed URI per object says nothing about which
object belongs to whom, so no cross-owner probe follows from one.

A listing that comes back **refused** is an error, not an empty server: only
JSON-RPC `-32601` ("no such method") is read as "there is no surface of this
kind", which is why a server without resources still scaffolds its tools. Any
other refusal stops the command instead of drafting an empty matrix — and stops
`coverage` too, where the number is a denominator and a `401` read as zero
operations would report the matrix 100% complete.

You can also scaffold from a saved capture, or from
[an OpenAPI spec or HAR file](#http-apis):

```bash
overstep scaffold listing.json --fmt mcp --server-url http://127.0.0.1:9000/mcp
```

### 2. Fill in the placeholders

The scaffold leaves `PASTE_..._TOKEN` and `REPLACE_ME_1` / `REPLACE_ME_2` where it
cannot know the answer. Two things to get right:

- **Give the two peer subjects genuinely different objects.** A cross-owner probe
  only exists when two subjects own *different* things; filling both placeholders
  with the same id silently removes every BOLA test.
- **Keep secrets out of the file** — write `${ALICE_TOKEN}` and pass the value
  through the environment or `--env-file`. See
  [Credentials](#credentials-dynamic-tokens--secrets).

Then review the starter policy. It is a *guess* (object → owner may read their
own, admin anyone's; function → admin only), and it is the one part of the file
only you can get right.

### 3. Lint it

```bash
overstep validate matrix.yaml
```

This catches the mistakes that would otherwise produce a confidently wrong run,
and separates the two kinds:

- **`error:`** — the matrix cannot produce a trustworthy result. A policy naming
  an unknown role, an injection pointing at a placeholder the URI doesn't
  contain, or a `PASTE_..._TOKEN` / `REPLACE_ME` left over from `scaffold`. Each
  is reported with the line number to edit and what to put there. Exits `1`.
- **`warning:`** — the run will happen and its findings will be real, but it
  tests less than its size suggests: a resource with no policy entry (denied by
  default), or subjects that all resolve to the same object so no BOLA probe can
  be generated. Exits `0`; pass `--strict` to fail on these too.

Placeholders are worth the loudest of those, because leaving one in does not
half-configure a run — it kills it. Every credential is rejected, so every
expected-allow test fails and every expected-deny test "passes" for the wrong
reason. `run` prints the same lines before it sends its first request.

Two things the file cannot tell you — whether the server answers, and whether
each credential is still accepted — need the server itself:

```bash
overstep validate matrix.yaml --live
```

```
error: subject 'alice' was denied tools/call read_document (HTTP 401), which the
matrix expects to be allowed — its credential is rejected or expired, or the
policy is wrong; every negative result for it would be meaningless
```

`--live` sends **one** request per subject: an expected-*allow* case, which is by
definition a request the matrix says that subject may make, so seeing it allowed
is the cheapest proof the identity works. This is the same judgement the
[inconclusive-run check](#inconclusive-runs-the-gate-refuses-to-fail-open) makes
afterwards, asked first and answered per subject — an expired token becomes
"alice is rejected" before the run instead of "the credentials or the matrix are
wrong" after it.

It is side-effect free: probes go out `--read-only`, and non-mutating operations
are preferred, so a subject whose only positive control is a destructive tool is
reported as unverifiable rather than verified destructively. Setup steps are not
run either, for the same reason. Anonymous subjects are not flagged — carrying no
credential, having nothing to verify is their normal shape.

### 4. Read the plan before sending anything

```bash
overstep plan matrix.yaml
```

`plan` prints every request it *would* send, with the decision the matrix expects,
and touches the network zero times. If a row looks wrong here, the matrix is
wrong — fix it before you point this at a real system.

### 5. Run it

```bash
overstep run matrix.yaml --out out --read-only   # drop --read-only once you trust it
```

### 6. Tighten the loop

An `unexpected-deny` finding means the matrix claims access the server refuses:
usually your policy is stricter than reality, occasionally the server is broken.
Either way, resolve it — a matrix that matches reality is what makes the *next*
run's silence meaningful. Then take a [baseline](#catching-authorization-drift)
and let CI gate on change.

## The authorization matrix

Three parts — **subjects** (who), **resources** (what) and **policy** (the
allow-list). Everything not explicitly allowed is denied.

```yaml
roles: [anonymous, user, admin]        # least -> most privileged

servers:
  - name: docs
    url: http://127.0.0.1:9000/mcp     # MCP over Streamable HTTP (JSON-RPC)

subjects:
  - { name: alice, role: user, token: ${ALICE_TOKEN}, marker: "alice@corp", attributes: { doc_id: d-alice } }
  - { name: bob,   role: user, token: ${BOB_TOKEN},   marker: "bob@corp",   attributes: { doc_id: d-bob } }
  - { name: root,  role: admin, token: ${ADMIN_TOKEN} }
  - { name: anon,  role: anonymous, token: null }

resources:
  - name: read_document
    transport: mcp
    call: { server: docs, tool: read_document }
    type: object            # object-level -> BOLA surface
    owner_arg: doc_id       # the argument that carries the object id
    owner_attr: doc_id      # matched against the subject's doc_id attribute
  - name: list_all_users
    transport: mcp
    call: { server: docs, tool: list_all_users }
    type: function          # function-level -> BFLA / privesc surface

policy:
  read_document:
    allow:
      - { role: user, scope: own }    # a user may read only their own document
      - { role: admin, scope: any }   # admins may read anyone's
  list_all_users:
    allow:
      - { role: admin }               # admin-only
```

`overstep plan` expands that into eleven cases — every subject against every
resource:

| Expected | Request | Subject | Variant | |
|---|---|---|---|---|
| allow | `read_document(d-alice)` | alice | self | |
| **deny** | `read_document(d-bob)` | alice | other | ← BOLA probe |
| allow | `read_document(d-bob)` | bob | self | |
| **deny** | `read_document(d-alice)` | bob | other | ← BOLA probe |
| allow | `read_document(d-alice)` | root | other | admins may read anyone's |
| **deny** | `read_document(d-alice)` | anon | other | ← unauthenticated probe |
| **deny** | `list_all_users()` | alice | na | ← BFLA / privesc probe |
| **deny** | `list_all_users()` | bob | na | |
| allow | `list_all_users()` | root | na | |
| **deny** | `list_all_users()` | anon | na | |

Every **deny** row is a probe: if the server answers it successfully, that's a
finding. Every **allow** row is a control: if the server refuses it, either your
matrix or your server is wrong, and overstep reports it as `unexpected-deny`.

On top of these, the [protocol probes](#the-mcp-surface) add a few rows per
server that no resource declares.

## The MCP surface

A resource sets `transport: mcp` and, instead of an HTTP `request`, either a
`call` (a tool) or a `read` (a resource URI). `servers:` declares the endpoints —
**Streamable HTTP** (`url:`) or **stdio** (`command:`, a local process).

### Deciding allow vs. deny

MCP has no `403` of its own, so the deny signal has to be spelled out:

```yaml
mcp_access:
  is_error_is_deny: true                  # a result with isError: true -> denied
  jsonrpc_error_is_deny: true             # a JSON-RPC error -> denied
  deny_status: ["4xx", "5xx"]             # an HTTP-leg refusal (401/403) -> denied
  # deny_content_regex: "permission denied"
```

`deny_status` is the half that is easy to miss. Over Streamable HTTP the
authorization spec has an unauthorized request answered with `401` and a
`WWW-Authenticate` header, and nothing requires the body to be a JSON-RPC message
— an empty body, or a framework's own `{"detail": "Not authenticated"}`, is what
many servers send. Such a response has no in-band deny signal at all, so it is
read from the status: any `4xx`/`5xx` means the call was never delivered. Without
that, the servers that reject *before* dispatching — the ones doing it right —
are exactly the ones a run reports as wide open.

Set `deny_status: []` for a server that reports real denials in-band under a
non-2xx status of its own. It does not apply to stdio, which has no HTTP leg.
`mcp_access` can be set matrix-wide and overridden per resource.

### Tools

```yaml
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

overstep performs an `initialize` handshake — completing the lifecycle with
`notifications/initialized`, so a server entitled to enforce it answers — and then
one `tools/call` per subject, using that subject's token and headers for identity.
Because a denial is usually in-band rather than a status code, the
[marker](#confidence-proving-a-leak-not-guessing-from-status) oracle matters more
than it does over HTTP.

### Resources

Tools are one half of what an MCP server exposes. The other is **resources**,
addressed by URI — and a URI carrying an object id is an object-level surface in
exactly the sense the matrix already models. A server can enforce ownership
perfectly on every tool and hand the same documents out through `resources/read`,
so a matrix that declares only tools reports the second door clean because it
never knocked on it.

A resource-read declares `read:` instead of `call:`, and names the URI placeholder
that carries the object id:

```yaml
resources:
  - name: read_doc_resource
    transport: mcp
    read: { server: docs, uri: "doc://acme/{doc_id}" }
    type: object            # object-level -> BOLA surface on the URI
    owner_uri: doc_id       # the {placeholder} filled with the caller's / a victim's object
    owner_attr: doc_id
```

```
│ deny │ object │ resources/read doc://acme/d-bob │ alice (user) │ other │
```

Everything downstream is unchanged — markers, confidence, `--fail-on`, drift,
waivers, coverage, `forbidden_fields`. A cross-owner read that returns the
victim's marker is graded **confirmed**: markers are searched in the body *and*
in the URIs the result named, since a read that answers with the victim's URI
reached the victim's object whatever the body held. The two are searched together
but kept apart — the body stays exactly what the server sent, so a JSON document
is still parseable and [BOPLA](#bopla-forbidden-response-fields) works over reads
too. A `blob` is decoded when it decodes as UTF-8, since a text document served
base64 still carries its owner's marker.

When the URI has no template structure of its own — an S3 key, a file path — make
the whole thing one placeholder and put the real URIs in `objects:`:

```yaml
    read: { server: docs, uri: "{doc}" }
    owner_uri: doc
    objects: { alice: "s3://bucket/a.txt", bob: "file:///srv/b.txt" }
```

A read is never skipped by `--read-only`: reading has no side effects, so there is
nothing to protect against. `validate` flags a resource that sets both `call` and
`read`, a URI injection naming a placeholder the template doesn't contain
(nothing would be substituted, so every subject would read one fixed URI), and an
injection pointing at the wrong half — an `mcp_argument` on a read or an
`mcp_resource_uri` on a call.

### Protocol revisions

MCP comes in two shapes, and a server speaks one of them. Through `2025-11-25` a
connection opens with an `initialize` handshake and may carry an `Mcp-Session-Id`
afterwards. From **`2026-07-28`** the core is stateless: the handshake and the
session header are gone, and every request carries its own protocol version and
client capabilities in `params._meta`, plus `Mcp-Method` and `Mcp-Name` headers
so gateways can route without parsing the body.

overstep drives both. The default stays on the stateful wire, because which
revision to speak is a fact about your target, not a preference:

```yaml
servers:
  - name: docs
    url: https://mcp.example.com/mcp
    protocol_version: "2026-07-28"     # default: 2025-06-18
```

Two consequences worth knowing:

- **Session binding is not applicable on `2026-07-28`.** The defect was removed
  from the protocol rather than fixed in your server, so the probe is reported as
  skipped rather than passed — credit for a control nobody had to implement would
  be the wrong reading.
- **A version mismatch ends the run rather than scoring it.** If the server
  answers `UnsupportedProtocolVersionError`, or rejects the request's headers, or
  refuses a handshake it no longer implements, those refusals are recorded as
  delivery failures and the run is [inconclusive](#inconclusive-runs-the-gate-refuses-to-fail-open).
  They are not denials, and a matrix of negative tests must not pass on them.

A revision overstep does not know is refused outright rather than guessed at.

### The protocol probes

Three checks run against every Streamable HTTP server beyond what the matrix
declares, because they ask about the **credential** and the **connection** rather
than about any one operation. They are the part of MCP authorization your policy
cannot express, and the part a tools-only checker cannot see.

| Probe | Default | Asks |
|---|---|---|
| [Token audience](#token-audience-the-credential-that-belongs-somewhere-else) | on | does the server check who the credential was issued *for*? |
| [Session binding](#session-binding-what-a-connection-alone-is-worth) | on | can a session id stand in for a credential? |
| [Tool enumeration](#tool-enumeration-what-the-server-is-willing-to-list) | off | is the privileged half of the catalogue advertised to everyone? |

None of them is available on stdio, where identity is an environment variable the
server itself named rather than anything travelling on a connection.

### Token audience: the credential that belongs somewhere else

Every check so far asks whether a server enforces its policy on a caller it has
correctly identified. This one asks something prior: does it check *who the
credential was issued for*? The MCP authorization spec is unambiguous — a server
must not accept a token that was not issued for it — and a server that skips the
check is a confused deputy. The token a user handed to one server works at
another, and the blast radius is not one object but every service trusting the
same issuer.

Tell overstep what a subject's token is bound to and it replays that credential at
every MCP server the audience does **not** identify:

```yaml
subjects:
  - name: alice
    role: user
    token: ${ALICE_DOCS_TOKEN}
    token_audience: docs             # a server name from servers:, or an audience URI
```

`token_audience` is inferred when a subject authenticates through a provider that
discovers its token endpoint from a server (`discover_from`) or sends an explicit
`resource` — that token *is* audience-bound, so nothing extra needs saying. Such a
subject usually has no `token:` of its own, because the provider writes what it
obtained straight into the subject's headers; the probe looks for a credential in
either place. With no audience known for a subject, no probe is generated:
overstep does not guess which credential belongs where.

The probe carries that subject's credential and nothing else. A credential
declared on the **server** itself (an `Authorization` or API-key header under
`servers:`) is dropped for this request only — a probe asking whether one identity
is accepted cannot answer that if something else in the request could have done
the authenticating.

`overstep plan` shows the extra row before anything is sent — one per server the
credential is foreign to:

```
│ deny │ function │ tools/list billing │ alice (user) │ audience │
```

The probe is `tools/list`, not a tool-call: it requires authorization, takes no
arguments and changes nothing, so it isolates the single question — was this
credential accepted at all — without invoking anyone's tool. One probe per
(subject, server), because validating the audience is a property of the server
rather than of each tool. A server that serves its catalogue to a foreign token is
graded **confirmed**; one that answers without an error but lists nothing is
**suspected**, since some servers signal refusal with an empty capability set.

Two edges worth knowing:

- **The policy is deliberately not consulted.** An admin's token bound to server A
  must still be refused by server B, so the probe expects a denial regardless of
  what the matrix allows that subject.
- **It assumes one token, one audience.** If a single credential is legitimately
  valid at several of your declared servers, that's a shared audience and a
  refusal isn't required — set `probe_token_audience: false` at the matrix level,
  or leave those subjects' audience undeclared.

### Session binding: what a connection alone is worth

Streamable HTTP hands out an `Mcp-Session-Id` at `initialize`, and the spec is
explicit that it must not be used to authenticate. Session identifiers travel in
headers, and headers end up in proxies, access logs and referrers — so a server
that accepts one as proof of identity lets anybody who obtains the string become
the user who opened it.

This applies to the stateful revisions. `2026-07-28` removed protocol-level
sessions altogether, and there the probe is skipped as not applicable — see
[Protocol revisions](#protocol-revisions).

overstep checks this on every Streamable HTTP server, without configuration:

```
│ deny │ function │ tools/list docs │ alice (user) │ session │
```

The probe opens a session as the subject, then sends the same **anonymous**
`tools/list` twice — once carrying the session id, once without it. The second
request is the control, and it is what keeps the result honest: a server whose
listing is simply public answers the first request too, and calling that session
hijacking would be a finding about nothing. Only the difference between the two
counts, so the probe reports a defect solely when the session is what made the
request work.

The finding carries a two-step repro, because that is what the defect consists of:
open the session as the subject, keep the id the server issued, then send the same
request with that id and no credential.

A server that issues no session id is stateless and has nothing to hijack — the
probe is recorded as skipped rather than answered, because it never ran. Set
`probe_session_binding: false` to switch it off entirely.

The [bundled demo](#quickstart-the-vulnerable-mcp-demo) has this defect on
purpose, so the three `session-hijack` findings in its summary are a live example
— including the repro, which really does read the tool list with nothing but a
stolen session id.

### Tool enumeration: what the server is willing to list

A server that advertises a tool to someone who may not invoke it discloses the
shape of its privileged half. That is where an attack starts rather than where it
ends, but it is not by itself a broken check — listing everything and enforcing at
call time is a common and defensible design. So unlike the two probes above, this
one is **opt-in**:

```yaml
probe_tool_enumeration: true
```

It calls `tools/list` as each subject and compares what came back against the
policy you already wrote: a tool declared as a resource that this subject may not
invoke is reported as `tool-enumeration` (medium). Permission is resolved the way
the planner resolves it, so an allow rule whose `condition` the subject fails is
not a grant; only ownership scope is ignored, since a listing says nothing about
which objects a call would reach. A paginated listing is followed to the end
(bounded at 20 pages), because a restricted tool on page two is exactly the one
worth reporting.

Two deliberate silences — a tool the matrix doesn't declare is *undescribed*
rather than disallowed, which is [coverage](#coverage-what-a-clean-result-is-allowed-to-mean)'s
gap to report; and a subject that cannot list at all has nothing to disclose, so
its refusal is not reported as an over-restriction. An enumeration probe is also
never counted as a positive control for the
[inconclusive check](#inconclusive-runs-the-gate-refuses-to-fail-open): a public
listing answers with no credential at all, and letting it vouch for one would let
a run where every token had expired report itself clean. That is why the demo's
summary counts its four listing probes separately from its eight positive
controls rather than folding them in.

The [bundled demo](#quickstart-the-vulnerable-mcp-demo) turns this on: its server
lists the admin-only `list_all_users` and `reset_tenant` to plain users, and its
anonymous subject — which cannot list at all — is reported as nothing, which is
the second silence above in action.

### OAuth-protected servers

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
calls — and, because overstep knows what it was bound to, the
[audience probe](#token-audience-the-credential-that-belongs-somewhere-else)
follows for free. The interactive authorization-code flow needs a browser and is
out of scope for an automated tool.

### Local (stdio) servers

For a server that runs as a local process, declare a `command` instead of a `url`.
overstep launches the process itself — one per subject — and speaks JSON-RPC over
stdin/stdout. There is no HTTP header for identity on stdio, so the subject's
token is injected into the process **environment** via `token_env`:

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

## Making findings trustworthy

A tool that cries wolf gets switched off. These are the features that decide
whether a finding is real.

### Confidence: proving a leak, not guessing from status

A successful result on a BOLA probe is not proof that data leaked — the call might
have returned an empty list. Give each subject a **`marker`** (a string that
uniquely identifies *its* data) and overstep looks for the victim's marker in the
response before it trusts the outcome:

```yaml
subjects:
  - { name: alice, role: user, token: a, marker: "alice@corp.example", attributes: { doc_id: d-alice } }
  - { name: bob,   role: user, token: b, marker: "bob@corp.example",   attributes: { doc_id: d-bob } }
```

- **confirmed** — the victim's data actually appeared (a proven leak);
- **suspected** — access was granted but the owner's data never showed up
  (downgraded to *medium* — likely an empty result, verify by hand);
- **unverified** — decided on the outcome alone, because no marker was configured.

This matters more on MCP than on HTTP: with no status code to lean on, the marker
is often the only thing separating "the tool ran and returned the victim's
document" from "the tool ran and returned nothing".

### One defect, not one finding per user

A missing check is reported once per identity that reaches it, so one bug can
arrive as a dozen findings — triage cost that scales with the size of your matrix
instead of the number of bugs. Every report therefore carries a **defect**
roll-up: one row per thing to fix, with the subjects as evidence of blast radius.

```
Vulnerabilities   16 (7 defects)
```

`findings.json` gains a `defects` array (worst first, each with its `subjects`,
`findings` count and an `example_test_id`), the HTML report leads with a
**Defects** table, and every finding carries its `group` key so a dashboard can
collapse them the same way. Nothing is filtered — the full finding list is still
there, and gating still counts findings.

### A repro that actually runs

Each finding carries a runnable command and a structured request record. The
credential is replaced by a shell variable named after the subject it belongs to,
so the line is safe to paste into a ticket **and** still works:

```bash
export OVERSTEP_TOKEN_ALICE=...     # the only thing that's missing
curl -sS -X POST -H "Authorization: Bearer $OVERSTEP_TOKEN_ALICE" \
    -H 'Content-Type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_document","arguments":{"doc_id":"d-bob"}}}' \
    http://127.0.0.1:9000/mcp
```

A bare `***` would be safe too, but it turns the repro into a command that answers
`401`. Each subject gets its own variable (`OVERSTEP_TOKEN_<SUBJECT>`, or
`OVERSTEP_<HEADER>_<SUBJECT>` for a non-bearer secret) so a repro can never
authenticate as the wrong identity. stdio repros do the same with the server's
token environment variable, and a session-hijack finding gets the two-step form
its defect actually requires.

### BOPLA: forbidden response fields

Even an *allowed* read can over-share. List the JSON keys a response must never
contain; matching is key-based, so a name appearing in free text won't
false-positive:

```yaml
resources:
  - name: read_document
    transport: mcp
    call: { server: docs, tool: read_document }
    type: object
    owner_arg: doc_id
    forbidden_fields: [password_hash, is_admin]
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
  - name: read_report
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
• object resource 'read_document' has no two subjects with different objects
  (all resolve to d-1), so no cross-owner BOLA probe can be generated;
  give at least two subjects distinct objects
```

## Modelling a real target

Everything above assumes a tidy server. This section covers what real ones do.
All of it applies to MCP and HTTP alike.

### Custom conditions

For finer rules — tenant isolation, attribute matching — an allow rule can carry a
boolean `condition` evaluated over `subject` and `target` attributes:

```yaml
policy:
  read_document:
    allow:
      - role: user
        condition: "subject.tenant == target.tenant"
```

Conditions run through a restricted AST evaluator: comparisons, boolean logic and
attribute/index access only. No function calls, no arbitrary names.

### Custom headers, and who wins on `Authorization`

By default each subject authenticates with `Authorization: Bearer <token>`. When a
target needs more — a non-bearer scheme, an API key, a tenant header — set headers
on the **resource** (or, for MCP, the **server**) and/or on the **subject**.
Subject headers override the ones they inherit:

```yaml
servers:
  - name: docs
    url: http://127.0.0.1:9000/mcp
    headers: { X-Api-Version: "2" }    # sent for every subject

subjects:
  - name: alice
    role: user
    token: alice-token                 # -> Authorization: Bearer alice-token
    headers: { X-Tenant: t1 }          # extra per-subject header
    attributes: { doc_id: d-alice }
  - name: svc
    role: admin
    headers: { X-API-Key: "abc123" }   # custom auth, no bearer token
```

An `Authorization` header set on the **subject** is a deliberate choice of auth
scheme for that identity, so the token never overwrites it — that is what the
`svc`-style rows rely on. One set on the **resource or server** is different: it
belongs to no identity in particular, so a subject's token replaces it. Keeping it
would send the same credential for every subject, dropping each one's own token,
and a matrix written to tell callers apart would be testing a single caller under
several names — silently, because the requests still succeed. A subject with no
token of its own still inherits it, since there is nothing to replace it with and
it may be the only way in. Replacement is case-insensitive, so exactly one
`Authorization` is ever sent, never two spellings for the server to choose
between.

### Credentials: dynamic tokens & secrets

Static tokens don't survive CI — they expire and shouldn't be committed.

**`${ENV}` interpolation.** Any `${VAR}` in the matrix is replaced from the
environment at load time (`${VAR:-default}` for a fallback); a missing variable
fails the run loudly instead of sending the literal string. Pass a dotenv file
with `--env-file`.

**Auth providers.** A subject can obtain its token by logging in before the run.
`type: http` posts an arbitrary login request and reads the token out of the JSON
response; `oauth2_client_credentials` and `oauth2_password` build the standard
token-endpoint form, and `discover_from` finds the endpoint from an
[MCP server's own metadata](#oauth-protected-servers). Values may contain
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
    attributes: { doc_id: d-alice }
```

`${...}` resolves once from the environment; `{{...}}` resolves per subject at
login time — so secrets come from the environment and never touch the file.

### Real objects: setup, captured ids & teardown

Meaningful BOLA testing needs a *real owned object* — the document that belongs to
alice, not her user id.

**`objects`** on a resource maps each subject to the id of the object it owns.
**`setup`** steps run once before the suite, as a chosen subject, and `extract`
values from their responses into a capture context that fills `{{name}}`
placeholders — including in `objects`. **`teardown`** steps run best-effort after
the suite (reusing those captures) to clean the fixtures up:

```yaml
setup:
  - name: alice creates a document
    as: alice                          # runs with alice's (dynamic) token
    call: { server: docs, tool: create_document, arguments: { body: "notes" } }
    extract: { ALICE_DOC: "$.id" }     # capture the new id from the tool result
  - name: bob creates a document
    as: bob
    call: { server: docs, tool: create_document, arguments: { body: "plans" } }
    extract: { BOB_DOC: "$.id" }

resources:
  - name: read_document
    transport: mcp
    call: { server: docs, tool: read_document }
    type: object
    owner_arg: doc_id
    objects: { alice: "{{ALICE_DOC}}", bob: "{{BOB_DOC}}" }

teardown:
  - { as: alice, call: { server: docs, tool: delete_document, arguments: { doc_id: "{{ALICE_DOC}}" } } }
  - { as: bob,   call: { server: docs, tool: delete_document, arguments: { doc_id: "{{BOB_DOC}}" } } }
```

Now `read_document::bob::other` reaches for **alice's real document id**, so a
successful result is a genuine BOLA finding. A step can use `request:` instead of
`call:` to create fixtures over HTTP. A teardown failure is reported as a warning,
never a run failure.

### Where the object id lives: injections

The identifier of the object a subject reaches for is the BOLA surface — but it
isn't always a tool argument. It may live in a resource URI, or over HTTP in a
path, a query string, a header, a cookie, a form field, a JSON body or GraphQL
variables. `ownership.injections` says where to write it; overstep fills each
location with the caller's own object (SELF) or a victim's (OTHER), so the same
probe works wherever the id travels.

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
location: a path parameter name, a query/header/cookie/form key, a JSONPath into
the JSON body (`$.order.id`, nested objects and arrays supported), a variable name
(or `$.path`) for GraphQL, a tool-argument key, or a `{placeholder}` in an MCP
resource URI template. A `form` injection sends an
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

The shortcuts are exactly single injections: `owner_arg: doc_id` is one
`mcp_argument`, `owner_uri: doc_id` one `mcp_resource_uri`, and `owner_param: id`
one `path`. An object resource must declare at least one locator; `validate` flags
an injection whose location doesn't match the transport, a selector that isn't a
parameter of the path or URI, and an object no subject can resolve — so overstep
never falls back to a placeholder id. A full example lives in
[`examples/injections/matrix.yaml`](examples/injections/matrix.yaml).

## HTTP APIs

The matrix, the planning and the classification are **transport-agnostic**. The
same file tests an HTTP API sitting behind your MCP server, a mix of the two, or
an HTTP API on its own with no MCP anywhere — everything in this README applies
either way, minus the MCP-specific probes. A resource declares a `request`
instead of a `call`; `transport: http` is the default and may be omitted.

```yaml
base_url: http://127.0.0.1:8000

resources:
  - name: get_user
    request: { method: GET, path: "/users/{id}" }
    type: object            # object-level -> BOLA surface
    owner_param: id         # {id} must match the caller's user_id
    owner_attr: user_id
  - name: admin_list_users
    request: { method: GET, path: "/admin/users" }
    type: function          # function-level -> BFLA surface
```

A single run can mix the two: the dispatcher groups planned cases by transport and
routes each group to its executor. Everything in
[Trustworthy findings](#making-findings-trustworthy),
[Modelling a real target](#modelling-a-real-target) and
[Running in CI](#running-in-ci) applies unchanged.

There is an HTTP demo alongside the MCP one:

```bash
python -m uvicorn examples.mock_api.server:app --port 8000
overstep run examples/mock_api/matrix.yaml --out out
```

```
 Tests run                            18
 Positive / negative               7 / 11
 Vulnerabilities            8 (3 defects)
   BOLA                                2
   privilege-escalation                6
```

### Scaffolding from OpenAPI or HAR

```bash
overstep scaffold openapi.yaml --with-policy > matrix.yaml     # OpenAPI
overstep scaffold traffic.har  --fmt har > resources.yaml      # or a HAR capture
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

### Deciding allow vs. deny (response matcher)

By default `2xx` means access was granted and anything else means it was denied.
That's wrong for APIs that redirect on success, return `200` with an error body,
or mask a `403` as a `404`. A **response matcher** makes the real signal explicit,
matrix-wide under `access:` and/or per resource:

```yaml
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

### Cross-method probing

A GET-only resource can hide a missing check on other verbs. `probe_methods` fires
each verb at *another* subject's object as a negative test — a success is a
missing method-level authorization:

```yaml
resources:
  - name: get_order
    request: { method: GET, path: "/orders/{id}" }
    type: object
    owner_param: id
    probe_methods: [PUT, DELETE]   # can a non-owner modify or delete it?
```

MCP has no verb, so this is HTTP-only.

### Compared with Burp Autorize / AuthMatrix

For HTTP alone, these are the closest tools, and the honest summary is that they
are interactive and overstep is declarative. Autorize replays the traffic you
browse under a second identity, which is excellent for exploration and needs no
setup; AuthMatrix builds a grid inside a Burp session. Both live where a person
is driving.

overstep asks you to write the matrix down first, which is more work up front and
buys four things a session cannot give you:

| | |
|---|---|
| **The matrix is a file** | reviewed in a pull request, versioned with the code, and readable by someone who wasn't there |
| **The same result every run** | no dependence on what you happened to browse, so a diff between two runs means something |
| **Gating on change** | a [drift baseline](#catching-authorization-drift) fails CI when a decision flips, not on a backlog of known findings; [waivers](#waivers-accepted-risk-without-turning-off-gating) carry accepted risk with an expiry |
| **It says what it could not test** | the [inconclusive check](#inconclusive-runs-the-gate-refuses-to-fail-open) and [coverage](#coverage-what-a-clean-result-is-allowed-to-mean) refuse to let silence read as safety |

Findings come out as SARIF (CWE/OWASP-tagged, for code scanning) and JUnit, which
is a packaging difference rather than a capability one, but it is the difference
between a finding a person reads and a finding a pipeline acts on.

Use both. Autorize while you are exploring an API by hand; overstep once you know
what the rules are and want them enforced on every pull request.

### crAPI demo

See [`examples/crapi`](examples/crapi/README.md) to run overstep against OWASP
crAPI for a realistic BOLA/BFLA showcase.

## Running in CI

### Running safely against live targets

- `--read-only` skips every mutating operation — POST/PUT/PATCH/DELETE over HTTP,
  and any tool marked `mutating` over MCP — so the suite can be pointed at a
  sensitive environment without changing state.
- `--max-retries N` (default 2) retries `429`/`503`, honouring `Retry-After` and
  otherwise backing off with full jitter — so a large matrix doesn't trip a rate
  limiter into flaky failures.
- `--concurrency N` bounds in-flight requests.

### Gating with `--fail-on`

| Value | Exits non-zero when… |
|---|---|
| `vuln` (default) | there is an active, non-waived vulnerability (BOLA/BFLA/BOPLA/privilege escalation, or an MCP token-audience/session-hijack/tool-enumeration finding) |
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
reads `Vulnerabilities 0`. A security gate that goes green because the server
never started is worse than no gate at all, so overstep calls that run
**inconclusive** and exits **3**:

```
inconclusive run — a clean result here would be meaningless:
  • 55 of 55 requests never reached the target (first failure: All connection
    attempts failed) — it is unreachable, so these results say nothing about
    authorization
```

A run is inconclusive when, **for any one target**, either

- **unreachable** — at least half its requests failed at the transport layer
  (server down, wrong `--base`, a dead stdio process, DNS or TLS failure);
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
server has an authorization hole" apart from "the scan never ran". The verdict
does **not** depend on `--fail-on` — that flag governs findings and cannot vouch
for a run that never happened — and it travels in `findings.json` under
`summary.inconclusive` so a dashboard doesn't read an empty run as a clean one.
Pass `--allow-inconclusive` to report anyway and keep the old exit code.

`snapshot` applies the same check and **refuses to write the baseline**: one
recorded against a dead target says "everything is denied", which would report the
next healthy run as wholesale authorization drift.

### Coverage: what a clean result is allowed to mean

The inconclusive check answers "did this run happen at all". Coverage answers the
two questions after it, and neither shows up in a finding count. `overstep
coverage` reports both, and sends nothing:

```bash
overstep coverage matrix.yaml --spec http://127.0.0.1:9000/mcp --fmt mcp --token "$TOKEN"
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

**The outer gap — what the matrix never declared.** The matrix *is* the
specification, so an operation nobody declared is invisible by construction: no
run sends it, and nothing in the findings mentions it. The only way to see it is
to compare the matrix against an independent description of the surface. `--spec`
takes an MCP server or `tools.json` (`--fmt mcp`), an OpenAPI document (the
default), or a HAR capture (`--fmt har`). Parameter *names* are the matrix
author's choice, so a spec writing `/users/{user_id}` and a matrix writing
`/users/{id}` match. Resources the spec doesn't mention are listed too — usually
an undocumented operation or a stale spec, occasionally a typo, which shows up as
one gap and one stray.

**The inner gap — what the run could not ask about.** A cross-owner probe is the
only thing that tests BOLA, and the planner generates one only when two subjects
resolve to genuinely *different* objects. When they don't it drops the probe
rather than replaying a subject's own request under a different label, which would
manufacture a pass. That is the right call, but a resource nobody probed and a
resource probed and found clean would otherwise both contribute `0` to the finding
count. So the run says so — in the summary, on the plan, and in `findings.json`:

```
 Object resources probed             2/3

note: no cross-owner probe was generated for 1 object resource(s), so this run
says nothing about BOLA on them:
  • read_invoice
  give at least two subjects different objects (an 'objects:' entry, or the
  owner attribute)
```

`overstep plan` prints that note without touching the network, which is where it
is cheapest to act on, and `validate` warns about the matrix-level cause. Only a
probe with a real victim counts: when *nobody* can resolve an object, the planner
still exercises the operation but reaches for a default id belonging to no
subject, and coverage does not count it.

Both halves are the same principle as the inconclusive check, one level up:
reporting the absence of a finding is worth something only if you can show the run
could have seen it. `--fail-under N` exits `1` when either percentage falls below
`N`, so coverage can gate a pipeline instead of only describing one.

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
for MCP, HTTP and mixed matrices alike, and `teardown:` fixtures are cleaned up
after the snapshot is taken.

### Waivers: accepted risk without turning off gating

A reviewed, consciously-accepted finding shouldn't fail the pipeline forever nor
silence the tool. A waivers file names findings by their stable `test_id`, with a
mandatory reason and an optional expiry:

```yaml
# waivers.yaml
waivers:
  - id: read_document::alice::other
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
| `overstep scaffold SPEC` | draft a matrix from a live MCP server, `tools.json`, OpenAPI or HAR |
| `overstep validate MATRIX` | lint for structural problems and unfilled placeholders (`--live` also probes the target; `--strict` fails on warnings) |
| `overstep plan MATRIX` | print the generated test cases (no network) |
| `overstep coverage MATRIX` | report what the matrix covers, vs. `--spec` and vs. its own object surface (no network) |
| `overstep run MATRIX` | generate, execute and report; non-zero exit on findings |
| `overstep snapshot MATRIX` | record current decisions as a drift baseline |
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
teardown — so every transport (MCP, stdio-MCP, HTTP, mixed) behaves identically
and setup fixtures are always cleaned up, even if a run is interrupted.

Matrix-level switches worth knowing:

| Key | Default | Effect |
|---|---|---|
| `probe_token_audience` | `true` | replay each subject's credential at servers it was not issued for |
| `probe_session_binding` | `true` | check that a session id cannot stand in for a credential |
| `probe_tool_enumeration` | `false` | report tools listed to subjects who may not invoke them |
| `probe_victims` | `one` | `all` sends a probe per distinct object instead of one per subject |

## Finding taxonomy

Every class maps to its CWE and OWASP API Security Top 10 entry, carried in the
SARIF rules (with a `security-severity` score) and on every JSON finding:

| Class | CWE | OWASP API Top 10 |
|---|---|---|
| BOLA | CWE-639 | API1:2023 |
| BOPLA | CWE-213 | API3:2023 |
| BFLA | CWE-285 | API5:2023 |
| privilege-escalation | CWE-269 | API5:2023 |
| token-audience | CWE-863 | API2:2023 |
| session-hijack | CWE-287 | API2:2023 |
| tool-enumeration | CWE-200 | API5:2023 |

## Transports & extensibility

overstep separates *what* it tests (the matrix, the planned probes, the
classification, the reports) from *how* a request is delivered. Delivery lives
behind a **transport registry** (`overstep.transports`) — the same pluggable
pattern as the reporters. A resource picks its transport; everything downstream is
unchanged. `validate` flags a resource whose transport is not registered. The
built-ins are `mcp` and `http`; the registry is the seam any further target plugs
into without changing the core.

## Where this sits

Several kinds of tool point at an MCP server, and they answer different
questions. This is a comparison of *approaches* rather than of products, because
the products move faster than a table can — and because the approach is what
decides whether a given tool can answer your question at all.

| Approach | Answers | Does not answer |
|---|---|---|
| **Static scanning of tool descriptions** | is a tool description malicious or manipulative — tool poisoning, rug pulls, instructions aimed at the agent | whether the server *enforces* anything. It sends no requests, so a server that hands any document to any caller looks identical to one that doesn't |
| **Gateways and policy proxies** | enforcement on live traffic, in front of the server | what the server itself permits. Everything holds until something reaches the server by another route, and nothing tells you whether it would hold then |
| **Generic API scanners / DAST** | input handling, transport and injection classes, on an HTTP endpoint | BOLA, because ownership is not in the spec: nothing tells the scanner which object belongs to whom. Most speak HTTP, not JSON-RPC over it |
| **A script against the MCP SDK** | anything you have time to write | repeatability. It is a point-in-time answer with no baseline, no gate and no record of what it could not reach |
| **overstep** | whether the server enforces ownership and role on its tools **and** its resources, and whether it obeys the protocol's own rules on credential audience and session binding | tool poisoning, prompt injection, and anything at runtime — it is a test, not a control |

The two halves of that last row are the point. overstep will not tell you a tool
description is lying to your agent; a description scanner will not tell you the
server behind it hands `doc://acme/anyone` to whoever asks. They are complements,
not alternatives.

Against other **authorization** testers specifically — Burp's Autorize and
AuthMatrix are the closest — the difference is that the matrix is a file rather
than a session: it is reviewed in a pull request, it produces the same result on
every run, it fails a pipeline on change rather than on a backlog, and it says
what it could *not* probe. See [HTTP APIs](#http-apis) for that comparison, since
neither tool speaks MCP.

## License

Apache-2.0.
