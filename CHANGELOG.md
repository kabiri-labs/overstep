# Changelog

## [0.41.0] - 2026-08-19

### Changed
- **BREAKING: one `owner` replaces `owner_param`, `owner_arg` and `owner_uri`.**
  Three keys expressed one idea — "the object identifier is here" — and each was
  named for a transport, so an author had to restate what the resource body
  already said, in a name that could contradict it.

  Where the id goes now follows from the body: a `request` puts it in the path, a
  `call` in a tool argument, a `read` in the URI placeholder. Each removed key is
  refused with a message naming the new spelling rather than a generic rejection.

  `ownership.injections` is unchanged and still wins when set. It remains the
  model for an id that lives somewhere the body cannot imply — a query string, a
  header, a cookie, a JSON body, GraphQL variables — or in more than one place at
  once. `owner` is the shorthand for the single common case, nothing more.

  A validation failure now names the place to fill in ("the path parameter
  carrying the object id", "the URI placeholder"), because "set owner" alone does
  not tell an author where to put it.

- **The MCP demo's header explained the removed keys.** Migrating a matrix's values
  and migrating the comments that describe them are two different edits, and only
  one of them fails a test — so the example taught `owner_arg` and `owner_uri` in
  prose while the entries beneath used `owner`. A reader following the example
  would have written a matrix the loader rejects. Found in review; a test now reads
  every bundled example line by line for any removed key, comments included.

- **BREAKING: `examples/mock_api` is `examples/rest_api`.** The MCP demo was named
  for its module and the REST demo for its role as a mock, which is the last of
  the naming asymmetries this series set out to remove. The bundled matrices, the
  README, `CONTRIBUTING.md` and the CI workflow follow it.

## [0.40.0] - 2026-08-19

### Changed
- **Each surface is a package, and neither is at the package root.** MCP had a
  consistent `mcp_` prefix while REST occupied the root unmarked, so the file
  listing said one was the tool and the other an addition — the same shape 0.37.1
  removed from the README and 0.38.0 from the matrix format. Fourteen modules move
  under `overstep/modules/rest/` and `overstep/modules/mcp/`, and the `mcp_`
  prefix goes with them: it was only ever there to mark one of two peers.

  The core stays where it is. Extracting the surfaces is what leaves
  `overstep/` as the core, and moving twenty more files would have been diff
  without meaning.

  `tests/test_module_boundary.py` now reads which module belongs to which surface
  off the layout instead of a hand-kept list, so the rule and the tree cannot
  disagree.

- **The MCP surface owns the three finding classes only it can report.**
  Credential audience, session binding and tool enumeration are requirements the
  MCP specification places on a server; nothing else produces them. They sat in
  the shared taxonomy beside BOLA, which meant the table every surface reads
  described one surface's protocol — down to SARIF help beginning "An MCP
  server…". The core keeps what both surfaces report; a surface registers its own
  with `taxonomy.register` and `report.sarif.register_help`.

- **SARIF rules are ordered by declaration, not registration.** With a surface
  contributing classes on import, insertion order decided where they landed in
  the document, so the move reshuffled a file people diff between runs. Ordering
  by the `VulnClass` declaration makes it independent of import order. Caught by
  the golden files, which is what they are for.

### Fixed
- **`overstep coverage --fmt mcp` against a reachable server has been broken
  since 0.38.0.** Removing `transport` from `Resource` missed two constructions in
  `cli.py`, so reading a live MCP surface raised a validation error instead of
  reporting coverage. Everything around it was tested — the comparison logic, and
  the path where the server refuses — but nothing ran the command against a server
  that answers, so a release went out with it. Found by running the command, not
  by the suite; the test that would have caught it now exists.

## [0.39.0] - 2026-08-19

### Changed
- **A surface answers its own questions, through the registry.** 0.38.2 measured
  eight places where a core module reached into a surface's internals. Six were
  the same shape — a question only the surface can answer, asked inline by core —
  and each now goes through a seam. `KNOWN_VIOLATIONS` is down to two.

  `TransportSpec` gains three optional capabilities beside `execute`:
  `build_record` and `build_repro` for turning a case into evidence, and
  `run_step` for a setup or teardown step. Rendering moves to
  `overstep.http_repro` and `overstep.mcp_repro`; running an MCP step moves to
  `overstep.mcp_fixtures`. `overstep.repro` keeps what is genuinely shared —
  masking, shell quoting, the per-subject credential variable — and dispatches
  the rest.

  Discovery gets a registry of its own in `overstep.discovery`, because resolving
  a provider's `discover_from` is not a per-case question. A resolver returning
  `None` means "not mine" and the next surface is asked; raising `DiscoveryFailed`
  means it recognised the reference and could not complete it, which stops the
  run. A metadata document failing its issuer check must not fall through to
  another surface's guess.

  The capabilities are optional. A transport registering only delivery still
  runs; a missing repro is described in the report rather than raised, because a
  finding without a repro is still a real finding.

### Fixed
- **`transports.restore` puts a whole spec back.** `register` defines a transport
  completely, so re-registering a saved *execute function* silently dropped
  everything else it could do. That was harmless while delivery was the only
  capability and became a trap the moment it was not: a test that stubbed HTTP
  delivery and restored it that way left the real transport unable to render a
  repro for every case that followed, surfacing as an unexplained diff in the
  golden files of an unrelated suite. Anything round-tripping a spec should use
  `restore`.

### Added
- `tests/test_transport_capabilities.py` — each surface registers its own
  rendering, a delivery-only transport still runs and describes what it cannot
  do, a restored spec keeps every capability, and the two discovery outcomes stay
  distinguishable.

## [0.38.3] - 2026-08-19

### Fixed
- **The fail-open caveat added in 0.38.1 gave advice that is not enough for a
  mixed matrix.** It said to give at least one subject a positive control, which
  is right for a matrix with one target and wrong the moment there are two.

  `health.assess` judges each target separately — deliberately, so a busy healthy
  target cannot outvote a small one that answered nothing. The same isolation
  means a healthy target cannot cover for a silent one either: a matrix spanning a
  REST API and an MCP server, with its only expected-allow case on the REST side,
  says nothing about the MCP server's credentials. If that server rejects every
  one of them, its every expected-deny case is denied and the run is reported as
  conclusive and clean.

  The guidance is now per target, and says why. Found in review of the PR that
  added the caveat — the test written with it exercised a single target, which is
  exactly the shape that hides this.

### Added
- Multi-target coverage for the credential check: one case pinning that a healthy
  target does not vouch for a silent one, and one pinning that adding the control
  to the quiet target *is* what catches it — including that the verdict names the
  target that failed rather than reporting an anonymous failure.

## [0.38.2] - 2026-08-19

### Added
- **The module boundary is measured instead of asserted.**
  `tests/test_module_boundary.py` builds the real import graph and holds it to two
  rules: no core module may import a surface module's internals, and neither
  surface may import the other.

  The README has claimed since 0.37.1 that overstep is one shared core with two
  peer modules over it, and that delivery is the only seam between them. Measured
  for the first time, that was not true. `models`, `planner`, `auth`, `fixtures`
  and `repro` all reached into MCP internals; `preflight` reached into the REST
  executor; and the MCP matcher imported the REST matcher in order to read its own
  `deny_status`. None of it is visible from a file listing, which is why it
  survived a positioning rewrite that was specifically about this.

  What remains is listed in `KNOWN_VIOLATIONS`, each entry naming what it waits
  on. The list is a ratchet: a new violation fails the build, and so does an entry
  that has been fixed but not removed — so it cannot decay into documentation for
  a problem nobody is addressing.

### Changed
- **Reading a status specification moved out of the REST matcher** into
  `overstep.statuses`. `allow_status` and `deny_status` accept the same three
  spellings because they describe the same thing, but sharing the parser by having
  the MCP matcher import the REST one made two peer surfaces into a base and an
  extension. An HTTP status is a fact about HTTP, and MCP's Streamable HTTP
  transport has an HTTP leg of its own.

- **`--read-only` asks the case whether it mutates.** The REST executor compared
  the verb against a constant it owned, the MCP transport read a flag off the
  invocation, and `preflight` imported the REST executor's constant to prefer a
  side-effect-free probe. `TestCase.is_mutating` answers for either surface, which
  removes the import and leaves one definition where there were three.

## [0.38.1] - 2026-08-19

### Fixed
- **The README no longer implies the gate catches every rejected credential.** The
  0.37.1 rewrite dropped a caveat that mattered: `health.assess` only reaches the
  credential check when the matrix has expected-allow cases, so a suite written
  entirely of negative tests, pointed at a target that rejects every credential it
  holds, is reported as **conclusive and clean** — every expected-deny case was
  indeed denied.

  The behaviour is deliberate and stays: an intentionally all-negative matrix has
  no positive control to lose, and condemning it would be wrong. What was wrong was
  describing the check without its one hole, in the fail-open direction, in the
  section whose whole subject is when a clean result may be believed. The README
  states it and says what to do about it — give at least one subject a positive
  control. Unreachability was, and is, caught either way.

- **The maturity scale claimed evidence it did not have.** `implemented` was
  defined as "covered by the test suite *and* exercised by a bundled demo", but no
  bundled matrix declares `forbidden_fields`, a policy `condition`, `probe_methods`,
  `token_audience` or an `auth` provider — five rows, not the two first noticed.
  The definition now claims test coverage, which is the evidence that exists, and
  says plainly which capabilities the demos do and do not show.

### Added
- `tests/test_readme_accuracy.py` — every capability marked implemented must be
  reachable from a test that names it, the scale's definition may not re-acquire
  the demo claim, and the all-negative caveat must be present *and* match what
  `health.assess` actually does, asserted in both directions so prose and code
  cannot drift apart again.

## [0.38.0] - 2026-08-19

### Changed
- **BREAKING: the matrix has two levels.** Everything a run needs regardless of how
  a request is delivered — `subjects`, `resources`, `policy`, `auth`, `setup`,
  `teardown`, `probe_victims` — stays at the top. Everything that only means
  something to one surface moves under that surface's name in `modules:`.

  Five of the fifteen top-level keys were MCP-only while reading as global. A
  REST-only matrix carried `servers`, `mcp_access` and three `probe_*` switches
  that could never apply to it, and nothing in the file said which of the two the
  next key belonged to — the same "one real tool plus an addition" shape that
  0.37.1 removed from the README, still present in the format.

  ```yaml
  modules:
    rest:
      base_url: http://127.0.0.1:8000
      access: { allow_status: ["2xx"] }
    mcp:
      servers:
        - { name: docs, url: http://127.0.0.1:9000/mcp }
      access: { is_error_is_deny: true }
      probes: { tool_enumeration: true }
  ```

  | Was | Is now |
  |---|---|
  | `base_url` | `modules.rest.base_url` |
  | `access` | `modules.rest.access` |
  | `servers` | `modules.mcp.servers` |
  | `mcp_access` | `modules.mcp.access` |
  | `probe_token_audience` | `modules.mcp.probes.token_audience` |
  | `probe_session_binding` | `modules.mcp.probes.session_binding` |
  | `probe_tool_enumeration` | `modules.mcp.probes.tool_enumeration` |

  There are no aliases: a matrix on the old layout is refused with an error naming
  every key's new home. Accepting one silently was never an option — pydantic
  ignores keys it does not know, so a matrix still declaring `servers:` would have
  loaded, planned no MCP cases, and reported a clean run against a server it never
  contacted.

- **BREAKING: a resource no longer declares `transport:`.** Its module is read off
  its body: a `request` is REST, a `call` or a `read` is MCP. The field was a
  second, independent declaration that could contradict what the resource actually
  sent, and `matrix.py` carried validation whose only job was to catch that
  disagreement. Deriving it makes the state unrepresentable and deletes the check.

- **BREAKING: `access:` and `mcp_access:` are one key on a resource.** Which
  matcher parses it follows from the body, so a REST resource cannot be handed an
  MCP matcher by accident — it is now an error rather than, as before, silently
  ignored keys and a resource judged by the defaults its author was replacing.

### Fixed
- **An unknown key in a matrix is an error, not a comment — at every level.**
  Every model a matrix file can reach now rejects extra fields, enforced by a test
  that walks the model graph rather than by a hand-kept list.

  The first pass covered only the top level, which left the worst case open one
  level down: `modules.mcp.probes.tool_enumeraton: true` loaded happily, left
  `tool_enumeration` false, and the run reported clean without ever having asked
  the question. A single transposed letter silently switching off a security probe
  is the exact failure this tool exists to catch elsewhere. Found in review.

  Writing the migration turned up what the old behaviour cost in the test suite
  too: a test passing `servers=[...]` as an override had it dropped on the floor
  and asserted against the default server instead, and had been doing so silently.

- **The two removed resource keys explain themselves.** `extra=forbid` refuses
  `transport:` and `mcp_access:` on a resource, but "extra inputs are not
  permitted" does not tell somebody holding last release's matrix what to do. Each
  now names the fix — delete the line, and spell the override `access`
  respectively. Before this, `transport: anything` was discarded in silence and a
  resource with a `request` was routed to the built-in REST executor regardless of
  what its author had registered.
- **The README's headline matrix example could never have been pasted.** `${VAR}`
  inside a *flow* mapping opens a nested mapping unless quoted, so
  `- { name: alice, token: ${ALICE_TOKEN} }` was a YAML syntax error. Every fenced
  yaml block in the README is now parsed by a test.

### Removed
- **A resource can no longer select a transport by name**, which is what
  `transport:` was for. The module follows from the body, so a third-party
  executor registered through `overstep.transports` is no longer reachable from a
  matrix: adding a surface now means an executor, a body shape and a config block.
  The README's roadmap says so rather than continuing to advertise the registry as
  a sufficient extension point.

### Added
- `tests/test_matrix_modules.py` — the split, the migration error for each
  relocated key, rejection of unknown keys from both YAML and the library API, the
  module derived from each body shape, `access` routing to the right matcher, a
  mixed-surface plan where nothing names a transport, and every bundled example
  matrix loading.

## [0.37.3] - 2026-08-19

### Fixed
- **Every place the project describes itself now tells the same story.** overstep
  describes itself in six surfaces — the README tagline, the PyPI summary, the OCI
  image label, `overstep --help`, the package docstring and `ABOUT.md` — and
  nothing connected them, so they had drifted into describing two different tools.

  `overstep --help` read "matrix-driven authorization testing for HTTP APIs" and
  omitted MCP entirely, which was wrong under the old positioning as much as the
  new one and had been for many releases. `pyproject.toml` said the opposite,
  "Authorization testing for MCP servers; works on HTTP APIs too", so the PyPI page
  and the terminal disagreed about what the tool covers. The `Dockerfile` label
  matched the CLI, `ABOUT.md` matched pyproject, and the README — as of 0.37.1 —
  matched neither.

  All six now lead with the problem class and name both surfaces. One canonical
  sentence appears verbatim in the three long-form surfaces; the short forms are
  free in their wording but must name REST and MCP.

- **`agent-security` is gone from the packaging keywords.** 0.37.1 added a README
  section explaining that overstep is not an AI or LLM security tool — it tests a
  server's enforcement and has no opinion about what an agent was persuaded to
  ask for — while the keyword advertising exactly that stayed in `pyproject.toml`.
  A keyword is a claim, and PyPI search is where most people meet a project. The
  keyword list also now names the REST surface (`rest`, `idor`,
  `broken-access-control`), which it never did.

### Added
- `tests/test_positioning.py` — the six surfaces pinned to each other rather than
  reviewed by eye: verbatim equality on the long forms, a both-modules-named check
  on the short forms, a length bound where GitHub truncates, and a guard that no
  self-description or keyword claims the non-goal the README states. Each was
  mutation-verified: a paraphrased label, an omitted module and a reinstated
  `agent-security` keyword each fail it.

## [0.37.2] - 2026-08-19

### Added
- **The serialized surface of a run is pinned against golden files.**
  `tests/test_wire_contract.py` runs both bundled demos end to end and compares
  every document they produce — `findings.json`, `overstep.sarif`, `junit.xml`,
  `report.html` and a snapshot's `baseline.json` — against a stored copy under
  `tests/golden/`.

  Three things overstep emits are consumed by something other than a human and
  cannot move without breaking it: `test_id`, which is the key a drift baseline
  and a waivers file are written against; the `vuln_class` wire values, which a
  waiver narrows on and a SARIF rule id carries; and the report documents
  themselves. None of that was covered. The rest of the suite tests behaviour
  through Python objects and would have stayed green while the serialized form
  changed underneath it — so a refactor could have turned every committed
  `baseline.json` into a wall of false drift, and every waiver into a no-op,
  without a single failing test.

  Alongside the golden files: the full set of generated `test_id`s for both demos
  as literals, the `VulnClass` and `Variant` member-to-value maps (renaming a
  member is free, renaming a value is not), a baseline round trip that must
  report zero drift against its own build, waiver matching asserted through a
  real finding, the CLI's command and option names, and the `--fail-on` gate's
  mapping to exit codes 0/1/2/3.

  These are change detectors, not a freeze. Regenerate with
  `OVERSTEP_UPDATE_GOLDEN=1` when a change to the serialized form is intended —
  the resulting diff is the record of what a release breaks, which is what the
  reorganisation ahead of 1.0.0 needs in order to state its breaking changes
  precisely instead of discovering them afterwards. `CONTRIBUTING.md` documents
  the workflow.

  Each guard was verified by mutation: a changed `VulnClass` value, a changed
  `test_id` separator and a renamed `latency_ms` each fail it, while a version
  bump does not — the package version is normalized out, or every release would
  look like a broken contract.

### Fixed
- **`.gitignore` no longer swallows the golden SARIF files.** The `*.sarif` rule
  exists so a user's run output stays out of the repository, and it silently
  excluded the two stored copies as they were written: the suite passed on the
  machine that generated them and would have failed on a fresh clone with a
  missing fixture. The rule now carries an exception for `tests/golden/`, and a
  test asks `git ls-files` rather than the filesystem, because the comparison
  itself cannot see this — the file is right there.

## [0.37.1] - 2026-08-19

### Changed
- **The README leads with the problem class rather than with MCP.** overstep is an
  authorization testing tool; REST and MCP are two surfaces on which one problem
  class shows up, not two tools sharing a repository. The previous framing tied the
  project's identity to a single protocol, which misdescribes the architecture — the
  matrix model, the planner, ownership resolution, the classifier, confidence
  grading, drift, waivers and every reporter are shared, and only delivery differs.

  The document now opens on the class (object-, function- and property-level
  authorization, multi-tenancy isolation), explains why it resists automated
  scanning — it is a logic flaw, so detection needs the intended policy as input —
  and then presents REST and MCP as peer modules under that umbrella, each with a
  worked example. MCP is described as the newest and hardest instance of the class
  (agent-as-caller, multi-hop delegation, no `403`, a second door through
  `resources/read`, protocol-level authorization rules) rather than as the flagship.

  Every capability now carries a conservative maturity marker — implemented,
  partial or planned — and the non-goals say explicitly what is not tested: the
  delegation chain, scope attenuation, and anything about the agent rather than the
  server. overstep is not an AI security tool and the README no longer leaves that
  open to inference.

### Added
- `tests/test_readme_contract.py` — the parts of the README that are claims about the
  code rather than prose, asserted against it: the command reference must name
  exactly the subcommands the CLI exposes, every status marker in a table must be one
  of the three defined words, the sentence defining the scale must define those same
  three, and delegation-chain and scope-attenuation testing must stay marked planned.
  Nothing else in the build would notice any of these drifting.

## [0.37.0] - 2026-08-13

### Fixed
- **Authorization server metadata is looked for where the spec puts it.** RFC 8414
  §3.1 *inserts* the well-known string between host and path rather than appending
  it, so an issuer identifying a tenant at `https://auth.example.com/tenant1` is
  described at
  `https://auth.example.com/.well-known/oauth-authorization-server/tenant1`.
  OpenID Connect Discovery appends instead, and RFC 8414 §5 keeps that form for
  interoperability, which is why the MCP authorization spec requires clients to
  try three addresses for a path-bearing issuer, in a fixed priority order.

  overstep built one of them — the appended OIDC form — and paired it with an
  appended OAuth suffix that no specification defines. So discovery against a
  multi-tenant authorization server tried a URL that names nothing, then one legal
  address, and gave up. That is invisible for Keycloak (`/realms/x`) and Entra
  (`/{tenant}/v2.0`), whose OIDC documents answer the appended form — which is why
  it went unnoticed — and total for a plain OAuth authorization server serving a
  tenant under a path.

  All three addresses are now tried, in the spec's order. Adding them cannot widen
  trust: `_validate_issuer` refuses any document that does not claim the identifier
  the URL was built from, so a new candidate is a new place to be told "no" rather
  than a new thing to believe.

  An issuer without a path is unaffected — the two addresses it had are the two
  the spec requires, in the same order. This is a fix for tenants, not for
  everyone.

## [0.36.1] - 2026-08-13

### Fixed
- **The README stopped contradicting itself about the CI gate.** `0.34.1` added
  the *Authorization regression* section, which argues for `--fail-on
  vuln-or-drift` and explains why `drift` alone goes green on exactly the case
  that motivates it — a newly added tool has nothing in the baseline to differ
  from. Two places further down still recommended `drift`: the runnable example
  under *Catching authorization drift*, and the advice below the `--fail-on`
  table. A reader who scrolled to either got the gate the section above had just
  finished arguing against.

  *Catching authorization drift* is now the mechanics only, pointing up at the
  reasoning rather than restating it — which is what `0.34.1` said it was doing
  and did not finish.
- **Session hijack is qualified where it is first claimed.** The opening section
  and the *What overstep finds* table both stated the rule flatly, and only a
  reader who reached *Protocol revisions* learned that `2026-07-28` removed
  sessions from the protocol. Both now say so where the claim is made.

### Added
- **A test that every README cross-reference resolves.** The document routes the
  reader by anchor and is long enough that sections get renamed without the links
  pointing at them being noticed; a broken `](#...)` renders as ordinary text and
  silently goes nowhere.

  Two details the check has to get right, both of which cost a wrong answer
  first. GitHub replaces each space with a hyphen rather than each run of
  whitespace, so `tokens & secrets` anchors as `tokens--secrets` — collapsing them
  reports a working link as broken. And a shell comment is spelled exactly like a
  heading, so headings are read outside fenced code blocks only; counting
  `# once, after triaging findings` as a heading would let a link resolve against
  a code comment and pass while pointing nowhere.

## [0.36.0] - 2026-08-13

### Added
- **`scaffold --fmt mcp` now asks the server which revision it speaks, and writes
  the answer into the matrix.** Adopting `2026-07-28` previously required knowing
  in advance that you needed it and then editing the file by hand, because
  `scaffold` had no way to be told: there was no `--protocol-version` flag at all,
  and every scaffolded matrix came out pinned to the default whatever the target
  actually spoke.

  That is a bad thing to have to guess. The revisions disagree about whether a
  request opens with a handshake, carries a session id, repeats its metadata in
  `params._meta`, or names itself in routing headers — and sending the wrong shape
  does not fail cleanly, it comes back as refusals that look like the server
  denying access. Since `0.32.1` a run reports that mismatch instead of scoring
  it, but reporting it is still a wasted run.

  Detection asks two questions, in the order that gets the authoritative answer
  first:

  1. `server/discover`, which `2026-07-28` requires every server to implement, and
     which replies with the server's own `supportedVersions` list;
  2. failing that, a legacy `initialize`, whose result carries the negotiated
     `protocolVersion`.

  The second value was already on the wire. Every scaffold ever run sent
  `initialize` and read the response for a session id, discarding the negotiated
  version sitting beside it.

  A `--protocol-version` flag states the answer directly and skips the probe. An
  unknown value is rejected at the flag rather than written into a matrix that
  could not run.

### Changed
- **The scaffolded matrix records `protocol_version` explicitly**, including when
  it is the default and when the source was a saved listing with nobody to ask.
  The revision decides the shape of every request, so a matrix that does not say
  which one it means is a matrix whose results move when the default does — and
  the point of writing the file down is that they do not.
- **A server speaking a revision overstep does not implement is recorded, not
  overwritten.** Substituting the default would send a handshake that server may
  have retired and read the refusals as authorization denials — the fail-open
  closed in `0.32.1`, reintroduced one layer up. The scaffold warns, writes what
  the server said, and lets the run refuse out loud.

  This holds however the answer arrived. A `supportedVersions` list naming only
  revisions overstep lacks is still an answer: detection falls through to
  `initialize` in case there is common ground to find, but if there is none it
  reports what the server said rather than discarding it.

## [0.35.0] - 2026-08-13

### Security
- **The server under test no longer chooses what the token it receives is valid
  for.** Protected Resource Metadata carries a `resource` identifier, and overstep
  used whatever the document claimed — falling back to the server URL only when
  the field was absent entirely. That value does not stay in the metadata: it
  becomes the RFC 8707 `resource` indicator on the token request, so it decides
  what the authorization server audience-binds the issued token to. And the
  document is served by the MCP server under test.

  So a target could name a third party — `resource: https://banking.internal/api`
  — wait for the honest, correctly pinned authorization server to mint a token
  bound to it, and then be handed that token in the `Authorization` header of the
  very next request. Nothing in the chain is inconsistent, and no metadata check
  catches it, which is why the issuer work in 0.34.0 did not: an issuer pin
  settles *which* authorization server the client secret goes to and says nothing
  about *what* the token that comes back is good for. The two halves are now both
  closed.

  Per RFC 9728 §3.3 the returned `resource` must be identical to the identifier
  the well-known URL was built from. overstep now requires the field to be present
  — it is REQUIRED by RFC 9728 §2, and substituting a value of our own hid a
  malformed document from a tool whose job is to report what the target actually
  does — and requires it to match an identifier the run already believed. The
  accepted set is derived from the server URL in the matrix — both spellings of a
  trailing slash, and the bare origin only when the matrix named the bare origin —
  plus an explicit `resource:` pin, so every candidate comes from the operator and
  none from the target.

  A path-scoped URL does not admit its own origin. A matrix naming
  `https://gateway.example/mcp` named a path-scoped service, and where the
  authorization server issues origin-audience tokens, accepting
  `https://gateway.example` would let the target widen its own audience to a token
  every sibling application on that host also honours — the same exfiltration,
  only closer to home. Widening is what `resource:` is for, and the operator has
  to ask for it.

  Comparison is exact, for the same reason the issuer comparison is: normalising
  an attacker-supplied value is how two different identifiers are talked into
  looking like one.

### Changed
- **Protected Resource Metadata is now read from the path-scoped document first.**
  RFC 9728 §3.1 inserts the well-known string between host and path, so a server
  at `/mcp` is described at `/.well-known/oauth-protected-resource/mcp`, with the
  root form as the fallback for a resource that is the whole origin. overstep tried
  them in the opposite order. On a host serving several MCP endpoints that asked
  the wrong question — the root document describes a different resource — and now
  that the answer is checked, it would fail the run outright.

### Fixed
- **Metadata that is valid JSON but not an object no longer crashes discovery.**
  Both readers of a fetched document went straight to `.get`, so a target
  answering the well-known URL with an array, or a bare string, produced an
  unhandled `AttributeError` instead of the refusal every other malformed
  response produces. Found while hardening the document above it — a target
  should not get to choose which exception type comes out of a security check.
  A non-object body is now treated as "this candidate did not answer".

### Migration
- A run whose PRM omits `resource`, or claims an identifier unrelated to the
  server URL in the matrix, now fails discovery instead of proceeding. Set the
  provider's `resource:` when the server is legitimately known to its issuer by
  another name, or its `token_url:` to skip discovery altogether.

## [0.34.1] - 2026-08-12

### Changed
- **The README leads with regression, not just detection.** Drift was a full
  capability — `snapshot`, `--baseline`, `--fail-on drift`, a decision recorded
  per cell — described in one subsection two thirds of the way down, under CI
  configuration. That is the wrong place for the thing the tool is most useful
  for: an authorization surface rarely breaks by being written wrong, it breaks by
  *changing*, and nothing about the changed state looks anomalous on its own. It
  is only wrong relative to what was agreed last month, which is a question only a
  baseline can answer.

  The opening now names both questions the tool answers — "what can each role
  reach today?" and "did this release change who can access what?" — and a new
  **Authorization regression** section sits directly after *What overstep finds*,
  with the mechanics still under *Catching authorization drift* rather than
  duplicated.

  The new section also states the two properties that make a diff worth gating on
  and which were previously only findable elsewhere in the document: the run is
  deterministic, so a difference is a real difference rather than a scanner
  changing its mind; and it refuses to fail open, so an unreachable target or an
  unspeakable protocol reads as inconclusive rather than clean.

  Two corrections to what the document recommends, both of which it previously got
  wrong in the reader's favour:

  - **The CI gate is `vuln-or-drift`, not `drift`.** A diff only speaks about
    cells present on both sides, so a newly added one has nothing to differ from:
    a tool shipped without an owner check is reported as a BOLA vulnerability, not
    as drift, and a drift-only gate exits `0` on it. Measured, not reasoned about
    — the scenario used to motivate the section was the scenario the recommended
    command missed. Waivers, not the baseline, are now what carries accepted
    pre-existing risk.
  - **The fail-closed claim is qualified.** Rejected credentials become an
    inconclusive run only when the matrix has expected-allow tests; those are what
    prove a credential still works, and an intentionally all-negative suite has
    none to lose. Stating it unconditionally promised a guarantee such a matrix
    does not get.

  Documentation only — no behaviour changed. Versioned because the repository
  treats positioning as a released change (see `0.31.1`).

## [0.34.0] - 2026-08-12

### Security
- **OAuth discovery no longer trusts the server under test with the client
  secret.** `discover_from` reads Protected Resource Metadata from the MCP
  server, follows it to an authorization server, and posts `client_id` /
  `client_secret` — or, on the password grant, a real username and password — to
  whatever `token_endpoint` that server's metadata names. Every value in that
  chain came from the target, and the target is the host a security tool trusts
  least. None of it was checked.

  Three checks now apply, each one a client requirement the MCP authorization
  spec states outright:

  - **Issuer validation (RFC 8414 §3.3).** The `issuer` in an authorization
    server's metadata must be identical to the identifier used to construct the
    well-known URL. The spec's own example is the attack: a document served from
    `attacker.example` claiming `"issuer": "https://honest.example"`. Compared as
    strings, with no normalisation beyond the trailing slash this code itself
    strips — normalising an attacker-supplied value is how two identifiers are
    talked into looking like one.
  - **HTTPS.** The authorization server and token endpoint must be HTTPS, since
    the next thing to travel there is a secret. Loopback is exempt — the whole of
    `127.0.0.0/8` and `::1`, not just `127.0.0.1`, since isolating local test
    services on another address is ordinary — as is a run that already disabled
    TLS verification and has made that choice explicitly.
  - **No cross-origin redirects** on a metadata request. Origins are compared as
    scheme, host and effective port rather than as text: httpx canonicalises the
    URL it reports, so `https://Example.com` and `https://example.com:443` come
    back spelled differently than they were requested even when nothing was
    redirected, and a textual comparison would refuse a correct deployment. This
    is deliberately not the normalisation refused for an issuer — an origin is a
    network location and comparing two should see through spelling, while an
    identifier normalised is how two different ones start to look alike.

  Verified by disabling each check and watching the credential arrive at the
  attacker's endpoint.

### Added
- **`issuer:` on an auth provider**, pinning the authorization server its
  credentials were registered with. Client identifiers are unique to the issuer
  that minted them, so a discovery landing anywhere else is refused rather than
  followed.

  This is the only control that stops the second attack, and it is worth being
  precise about why: metadata validation catches an authorization server
  *impersonating* another, but not one the target owns and describes honestly —
  there, nothing is inconsistent and there is nothing to detect. Only knowing in
  advance where the credentials belong refuses it.

- **`validate` warns** when a provider discovers its token endpoint and sends a
  secret without pinning an issuer. A warning rather than an error: existing
  matrices keep running, but a run that is weaker than it looks says so.

## [0.33.0] - 2026-08-12

### Added
- **overstep speaks MCP `2026-07-28`.** The revision made the core stateless:
  the `initialize`/`notifications/initialized` handshake and the `Mcp-Session-Id`
  header are gone, every request carries its own protocol version and client
  capabilities in `params._meta`, and Streamable HTTP requires `Mcp-Method` and
  `Mcp-Name` headers that must agree with the body. `0.32.1` could recognise such
  a server and refuse to guess about it; it could not test one.

  Set it per server:

  ```yaml
  servers:
    - name: docs
      url: https://mcp.example.com/mcp
      protocol_version: "2026-07-28"
  ```

  The handshake is now conditional on the revision, across all four places that
  speak this wire: the run transport, the scaffolding loader, the synchronous
  fixture client used by setup/teardown, and the generated repro. A repro missing
  the required headers would be a command the server rejects before authorization
  is consulted — an all-clear pasted into a bug report — so it carries them too.

  The three headers a stateless request derives from what it is sending
  (`MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name`) are now removed from the
  matrix's own `servers[].headers` in every spelling before being set. Header
  names are case-insensitive while dict keys are not, so a `mcp-method` written
  there would otherwise travel *alongside* the derived `Mcp-Method` and produce
  exactly the header/body contradiction the revision rejects.

  stdio went stateless with the rest of the protocol, so its handshake is skipped
  on that revision as well; the routing headers are HTTP-only and are not sent
  there.

  **The default is unchanged at `2025-06-18`.** Which revision to speak is a fact
  about the target, not a preference, so an existing matrix keeps its wire until
  it says otherwise.

- **Session binding is reported as not applicable on `2026-07-28`.** The defect
  was removed from the protocol rather than fixed in any given server, so the
  probe is skipped before a request is sent. Reporting it as passed would be
  credit for a control the target never had to implement.

- **A version the server will not accept ends the run.** Configured for a
  revision the target does not implement, the two errors the spec defines for it
  — `UnsupportedProtocolVersionError` and `HeaderMismatch` — are recorded as
  delivery failures rather than denials, so the run is inconclusive instead of
  passing a matrix of negative tests. `-32601` is deliberately not read this way:
  a server answering "method not found" to `resources/read` is telling us it has
  no resource surface, which is a true answer to a real question.

### Fixed
- **Generated repros declare their protocol version.** `MCP-Protocol-Version` is
  sent by the executor on every revision, but the repro never carried it, so a
  pasted command was not quite the request the finding came from. On
  `2026-07-28`, where the header is required and must match the body's `_meta`,
  that gap made every stateless repro a command the server rejects before
  authorization is consulted — the failure mode the repro exists to avoid.

- **`2025-11-25` is recognised.** It was missing from the set of known revisions
  added in `0.32.1`, so a server negotiating it was reported as speaking a
  protocol overstep does not implement — a false refusal of a revision the
  handshake path drives correctly. An unknown version is still refused rather
  than guessed at, which is the point of the set.

### Changed
- The default protocol version now has one definition instead of six copies, and
  the wire-format rules for both revisions live in `overstep.mcp_protocol` rather
  than being spelled out separately in each caller.

## [0.32.1] - 2026-08-12

### Fixed
- **A protocol overstep cannot speak was reported as a server that forbids
  everything.** MCP 2026-07-28 retired the `initialize`/`initialized` exchange
  and the `Mcp-Session-Id` header, and requires `Mcp-Method`/`Mcp-Name` on every
  Streamable HTTP request. Against a server on that revision the transport's
  handshake is refused, and so is every request built on it — at the protocol
  layer, before authorization is ever consulted.

  Those refusals were recorded as denials, which is where it turns dangerous: a
  denial is what a *passing* negative test looks like. A matrix with expected-allow
  tests survived this, because the inconclusive check already condemns a target
  that allowed none of them — but it named the wrong cause, sending the reader to
  debug credentials that were never at fault. A matrix without one had nothing
  left to catch it: every request answered `400`, every negative test "passed",
  and the run reported no findings and exited `0`.

  The handshake now carries out the reason it could not be completed, and a
  request rejected in its wake is recorded as a delivery failure — status `0`,
  the same signal every transport already reserves for "never reached the target"
  — so the run is inconclusive on the evidence of the requests themselves, with
  or without a positive control. `validate --live` inherits the same signal and
  names the protocol before a run is sent.

  That rejection is read from the response body as well as its status. JSON-RPC
  is entitled to report a malformed request under an ordinary `200`, so a
  mismatched server can refuse every call without ever emitting an HTTP error —
  and the status alone would miss it, leaving the fail-open exactly where it was.

  Three things are deliberately left alone. A refused handshake is a suspicion,
  not a verdict: it is confirmed against the request that follows, so a lax
  server that ignores the lifecycle and answers tool-calls anyway stays testable
  and its results stay real. A `401`/`403` on the handshake is the server asking
  who is calling — the question the run exists to ask — so it stays on the
  allow/deny path untouched. And only JSON-RPC's four pre-defined codes count as
  an in-band protocol refusal: a server saying "forbidden" answers with `isError`
  or a code from the `-32000..-32099` range reserved for exactly that, so
  treating *any* JSON-RPC error as a protocol failure would rewrite genuine
  denials into transport errors and lose the findings that matter.

  Not covered: the stdio transport, whose handshake is a separate exchange with
  no HTTP status to read, and the 2026-07-28 wire format itself. This change
  makes overstep refuse to guess about a server it cannot drive; it does not yet
  let it drive one.

## [0.32.0] - 2026-08-12

### Changed
- **The bundled MCP demo now demonstrates the protocol probes too.** The demo
  server had both transport-level probes switched on and neither had anything to
  report: `tools/list` was public, so a session id was never what made a request
  work and the control correctly ruled the finding out; and the matrix left
  enumeration opt-in and never opted in. The two probes that have no equivalent
  in an HTTP API scanner were the two the demo did not show.

  The server now issues an `Mcp-Session-Id` only to an authenticated caller and
  then accepts it *in place of* a credential — the defect the MCP spec names —
  and requires a credential, but no role, to list. The matrix sets
  `probe_tool_enumeration: true`. The run reports 16 findings across 7 defects
  where it reported 9 across 5: 3 × `session-hijack` and 4 × `tool-enumeration`
  on top of the BOLA and privilege-escalation findings it always had.

  Consequence worth knowing before you hit it: scaffolding or measuring coverage
  against the demo now needs `--token alice-token`, because listing is no longer
  anonymous. The README snippets pass one.

  `tests/test_examples_demo.py` runs the demo end to end over ASGI and pins its
  numbers, since the README publishes them and nothing else would notice them
  going stale.

- **`Positive / negative` no longer counts enumeration probes as positive.** An
  enumeration probe is nominally allow-expected, so `summarize` counted it —
  while the inconclusive check, correctly, does not: its success proves no
  credential works. The demo turning the probe on made the summary read `12 / 15`
  where only 8 were controls. They are now counted separately and shown as
  `8 / 15 (+4 listing)`, with a `listing_tests` field in `findings.json` and its
  own card in the HTML report, so the three still add up to the total.

### Fixed
- **A refused listing was read as a server with nothing on it.** `fetch_tools`
  and `fetch_resource_templates` treated any unreadable listing as "none",
  because a server without a resource surface answers with an error and that
  answer is genuinely empty. A `401` answers with an error too. The demo change
  above made this reachable from the README's own commands: `overstep coverage
  --spec <url> --fmt mcp --fail-under 100` against a server that refused to list
  computed `0/0 (100%)` and exited 0 — a gate going green because nothing was
  measured.

  Only `-32601` — the code that states the method does not exist — is still read
  as "none", so a server without resources scaffolds its tools exactly as
  before. Every other refusal, in-band or as an HTTP status, now raises
  `McpListingError`; `scaffold` and `coverage` already report a failed listing
  and exit 2.

- **The session-hijack repro sent the literal string `$SESSION`.** Step 2 of the
  two-step repro carried `Mcp-Session-Id: $SESSION`, single-quoted like any other
  literal because the variable was not named with the prefix that marks the ones
  meant to expand. The command ran, the server saw an unknown session id and
  refused, and the repro for a real finding demonstrated nothing. The variable is
  now `$OVERSTEP_SESSION`, matching the convention the credential variables
  already follow, and the test asserts the double quotes rather than only the
  header.

## [0.31.3] - 2026-08-12

### Fixed
- **Release notes now cover every version since the last published tag.** The
  workflow extracted the CHANGELOG section for the version being released and
  nothing else. That is correct when every version is released and quietly wrong
  when several are bundled: `v0.31.2` was published describing two listing
  fixes, while the eleven versions it actually contained — the whole MCP surface,
  the oracle fix, the credential bugs — went unmentioned. Nothing failed. The
  notes were simply the wrong ones, and read like a small patch release.

  The range is now the unit rather than the version: from the version being
  released back to the highest tag below it, each section keeping its own
  heading so a reader can tell which change arrived when. A single-version
  release produces byte-identical output to before.

  Two guards come with it. A version with no CHANGELOG section now fails the
  build instead of publishing an empty page — the way the old extraction failed,
  silently. And the previous version is chosen as the highest tag *strictly
  below* the one being released, so a stray later tag cannot make the range run
  backwards and come out empty.

  The logic moved out of an inline `awk` one-liner into `scripts/release_notes.py`
  so it can be tested; `tests/test_release_notes.py` covers the range, the
  guards, numeric version ordering (`v0.9.0` before `v0.10.0`, which string
  comparison gets backwards) and the CLI as the workflow invokes it. Writing
  those tests caught a bug in the replacement before it shipped.

### Changed
- Documentation landed on `main` after `v0.31.2` was tagged, so it is recorded
  here rather than being lost between releases:
  - the tagline said "and the HTTP APIs behind them", which claimed the HTTP API
    sits behind an MCP server. It often does, but need not, and overstep tests a
    standalone API with no MCP anywhere. Now "Works on HTTP APIs too", in the
    README, the packaging description and `ABOUT.md`.
  - the capability comparison was rewritten as a comparison of *approaches* —
    static description scanning, gateways, generic DAST, hand-written scripts —
    each with what it does **not** answer, overstep included. The old table
    compared against two HTTP testers, so its MCP rows were a clean sweep against
    tools that never claimed to do the thing.

## [0.31.2] - 2026-08-12

### Fixed
- **A failed listing became an empty surface instead of an error.** Reading the
  resource half for `coverage --fmt mcp` was wrapped in a bare `except`, on the
  reasoning that a server without resources should not fail a scan. But a server
  without resources answers with an error the loader already reads as "none" —
  so that clause caught nothing it was written for, and swallowed the one thing
  that mattered: a genuine transport failure.

  The consequence is a false-green gate. The operation count is the denominator
  `--fail-under` compares against, so a matrix could report 100% coverage of a
  surface half of which was never read. The failure is now reported like a
  failure to read the tools, exiting `2`. `scaffold` keeps going — a tools-only
  draft is still worth having — but says on stderr that the resource half is
  missing, rather than emitting a matrix silently blind to it.

- **Listings are paginated.** `tools/list` and `resources/templates/list` were
  read one page deep, so anything behind a `nextCursor` was absent from both the
  scaffolded matrix and the coverage denominator — letting `--fail-under` pass
  for a surface that was never counted. Both are now followed to the end,
  bounded at 20 pages and stopping on a repeated cursor, matching the cap the
  run transport already applies to its own listing.

## [0.31.1] - 2026-08-12

### Changed
- **The README leads with MCP.** The tool's centre of gravity moved there — tools
  and resources, the token-audience, session-binding and tool-enumeration probes,
  MCP-aware scaffolding — while the document still opened on an HTTP quickstart
  and reached MCP two thirds of the way down. It is reorganised around what the
  tool is now for:

  - a new opening section on *why MCP authorization needs its own tool* — no
    `403`, a surface wider than the tool list, and protocol rules that no test of
    your own policy can cover;
  - the quickstart is the vulnerable **MCP** demo, and the six-step "point it at
    your own server" walkthrough starts from an MCP scaffold;
  - the matrix example and the plan expansion are MCP;
  - the MCP material — tools, resources, the three protocol probes, OAuth, stdio,
    the allow/deny matcher — is gathered under one **MCP surface** section
    instead of being scattered across six subsections;
  - **HTTP APIs** keeps everything it had (OpenAPI/HAR scaffolding, the response
    matcher, cross-method probing, the crAPI demo) in one clearly second-priority
    section;
  - the two sections both titled *"…what a clean result is allowed to mean"* are
    merged into one, as the outer gap (what the matrix never declared) and the
    inner gap (what the run could not ask about);
  - a five-command orientation table, a matrix-switch reference, and a
    protocol-probe summary table were added for people who want the shape before
    the prose.

### Fixed
- **`coverage --fmt mcp` compares the resource surface too.** It read only
  `tools/list`, so a matrix that correctly declared a `read:` was reported as a
  stray against its own server — "an undocumented operation or a stale spec" for
  something that was neither. It now reads `resources/templates/list` as well,
  matching each URI by shape so the two sides may name the placeholder
  differently, exactly as paths are already compared.

## [0.31.0] - 2026-08-12

### Added
- **`scaffold --fmt mcp` drafts the resource surface too.** It read `tools/list`
  and nothing else, so a scaffolded matrix started life with the blind spot
  0.30.0 exists to close: a server can enforce ownership on every tool and hand
  the same objects out by URI, and a matrix drafted from the tools alone would
  never ask. It now also reads `resources/templates/list` and emits a `read:`
  resource per template.

  The URI placeholder is read the way a tool's arguments already are: an id-like
  `{doc_id}`, or a lone `{key}`, becomes the `owner_uri` and the resource is
  object-level. A template with several placeholders and no obvious object among
  them — `repo://{owner}/{repo}/tree` — gets one `mcp_resource_uri` injection per
  placeholder, each from its own subject attribute, because every one still has
  to be filled or the URI goes out with a literal brace in it; which of them is
  the thing being owned is left to the author. A template with no placeholder
  addresses one fixed object and is drafted as a `function`.

  Two deliberate omissions. A template using an RFC 6570 operator (`{+path}`,
  `{?query}`) is reported on stderr and left out, since ownership substitution
  cannot fill it and the drafted resource would reach for an address that does
  not exist. Concrete `resources/list` entries are not drafted at all: a fixed
  URI per object says nothing about which object belongs to whom, so no
  cross-owner probe can be derived from one.

  A tool and a template may share a name; the second becomes `<name>_resource`
  rather than overwriting the first. A server exposing no resources still
  scaffolds its tools, and one exposing neither now says so on stderr instead of
  emitting an empty matrix silently.

### Fixed
- The scaffold's own listing calls now send `notifications/initialized` before
  asking, so a server that enforces the initialization lifecycle answers them
  instead of refusing — the same conformance gap fixed for the run transport in
  0.29.2, in the one place that had its own client.

## [0.30.2] - 2026-08-12

### Fixed
- **A credential declared on an HTTP resource authenticated every subject through
  it.** `build_headers` withheld the subject's bearer whenever an
  `Authorization` header was already present — including one inherited from the
  resource's own `request.headers`, which belongs to no identity in particular.
  Every subject then sent that one credential, their own tokens were never sent,
  and a matrix written to tell callers apart was testing a single caller under
  several names. Silently, because the requests still succeeded: the positive
  controls passed, the negative probes were answered by the wrong identity, and
  nothing in the run said so.

  This is the HTTP half of the same defect fixed for MCP in 0.29.1. The token now
  yields only to an `Authorization` the *subject* set — still a deliberate choice
  of auth scheme per identity — and replaces one inherited from the resource. A
  subject with no token of its own still inherits the resource's header, since
  there is nothing to replace it with and it may be the only way in.

### Changed
- **README scope statements now follow the code rather than the other way round.**
  Several described a narrower tool than the one that exists:

  - "an explicit `Authorization` header is never overwritten by the token" was
    the rule the fix above changes. Replaced with which `Authorization` wins and
    why, for HTTP and MCP alike.
  - the tagline and package description said "MCP tool-calls"; the surface now
    also covers resources, audience, session binding and enumeration, so both
    say "MCP servers".
  - the flow diagram and the capability-comparison row listed only the original
    finding classes.
  - the MCP section said a resource sets "a `call`", and did not mention that
    three protocol probes run beyond what the matrix declares.

- **Credential replacement is case-insensitive.** HTTP header names are, and
  Python dict keys are not: assigning `Authorization` beside an inherited
  lowercase `authorization` left both in place, and both went out on the wire for
  the server to choose between. If it chose the shared one, every subject
  authenticated as the same identity again — the very failure the precedence
  rule exists to prevent, reintroduced by spelling.

  Both directions were affected: a resource/server-level `authorization` beside a
  subject's token, and a resource-level `Authorization` beside a subject's own
  lowercase one. Replacement now removes every spelling first, via a shared
  `drop_header`, on the HTTP executor, the MCP transport, and the MCP fixture
  client. Only one `Authorization` is ever sent.

## [0.30.1] - 2026-08-12

### Fixed
- **A resource read switched off its own forbidden-field detection.**
  `contents_text` put each entry's URI on the line above its body. The BOPLA
  check parses that body as JSON to find forbidden property keys, and
  `doc://acme/alice` followed by a JSON document is not JSON — so `_json_keys`
  returned nothing and `forbidden_fields` silently found nothing on every
  resource read that returns JSON, which is most of them.

  The URI now travels separately, in `contents_uris`. It is still searched for
  markers alongside the body, so a read that comes back naming the victim's URI
  still grades **confirmed** — searched together, stored apart.

- **A stdio resource read did not record what it read.** The structured request
  on a finding carries `tool` and `arguments`, both empty for a read, and the
  `uri` was added only to the HTTP branch. Findings from a stdio server named no
  resource at all in `findings.json` or the HTML report.

## [0.30.0] - 2026-08-12

### Added
- **MCP resources are now an authorization surface, not a blind spot.** Tools
  were one half of what an MCP server exposes; the other is *resources*,
  addressed by URI. A URI carrying an object id is an object-level surface in
  exactly the sense the matrix already models — and a server can enforce
  ownership perfectly on every tool while handing the same documents out through
  `resources/read`. A matrix that declared only tools reported that second door
  clean because it never knocked on it.

  A resource-read declares `read:` instead of `call:`, and names the URI
  placeholder carrying the object id:

  ```yaml
  resources:
    - name: read_doc_resource
      transport: mcp
      read: { server: docs, uri: "doc://acme/{doc_id}" }
      type: object
      owner_uri: doc_id
      owner_attr: doc_id
  ```

  `owner_uri` is the shortcut for a single `mcp_resource_uri` injection, the way
  `owner_param` is for a path and `owner_arg` for a tool argument, so the general
  `ownership.injections` model covers it too. Where a URI has no template
  structure of its own — an S3 key, a file path — the whole URI is written as one
  placeholder with the real values in `objects:`.

  Everything downstream is unchanged: markers, confidence, `--fail-on`, drift,
  waivers and probe coverage all treat a read like any other object resource. A
  cross-owner read that returns the victim's marker is graded **confirmed** — the
  oracle reads each result entry's URI *and* its body, decoding a `blob` when it
  decodes as UTF-8, since a text document served base64 still carries its owner's
  marker and one that is genuinely binary would only add noise a regex could
  match by accident.

  A read is never skipped by `--read-only`, having no side effects. `validate`
  rejects a resource that sets both `call` and `read`, a URI injection naming a
  placeholder the template does not contain (nothing would be substituted, so
  every subject would read one fixed URI — a cross-owner probe in name only), and
  an injection pointing at the wrong half of the resource.

  The bundled demo server now serves `doc://acme/{doc_id}` with the same missing
  check as its `read_document` tool, so `overstep run examples/mcp_api/matrix.yaml`
  reports four BOLA findings across the two doors instead of two across one.

  Not included: scaffolding reads from a server's `resources/templates/list`.
  They are written by hand for now.

## [0.29.2] - 2026-08-12

### Fixed
- **A public tool listing could vouch for credentials that had all expired.**
  Enumeration cases carry `expected: allow`, and the run-health check counted
  every expected-allow case as a positive control. On a server whose
  `tools/list` is public, that case is answered with no credential at all — so
  with `probe_tool_enumeration` enabled, every real tool-call could fail on a
  rejected token while the enumeration observation kept `health.reasons` empty,
  and a run that authenticated nobody reported a conclusive `Vulnerabilities 0`.
  That is the fail-open the health check exists to catch, reintroduced through a
  case that only looks like a positive control.

  `TestCase.is_positive_control` now names the distinction — an allowed result
  is evidence about a credential only when the matrix granted *this subject*
  something — and both the health check and `validate --live` use it.

- **The MCP initialization lifecycle was never completed over HTTP.** The client
  sent `initialize` and went straight to the next request, without
  `notifications/initialized`. A server entitled to enforce the lifecycle
  refuses everything that arrives before it, and that refusal was recorded as a
  denial: a clean-looking result produced by overstep's own non-conformance
  rather than by the server's authorization. stdio always sent it; HTTP now does
  too.

- **A conditional allow rule counted as permission it never granted.** The
  enumeration check read `required_roles()`, which lists a rule's role
  regardless of its `condition`. A subject matching the role but failing the
  condition — one the planner denies — was treated as allowed, so a restricted
  tool shown to them was reported clean. Permission is now resolved through the
  planner's own policy evaluation (`grants_access`), which applies conditions and
  still ignores only ownership scope.

- **A paginated `tools/list` was read one page deep.** Any restricted tool on a
  later page was absent from `listed_tools` and could not produce a finding.
  The enumeration probe now follows `nextCursor` and accumulates, bounded at 20
  pages and stopping on a repeated cursor so a server cannot hold a run open.
  Only that probe paginates; the audience and session probes need allow/deny,
  not contents.

- **The session-hijack repro did not reproduce the session hijack.** The generic
  MCP repro ignored `anonymous` and `handshake_headers` and emitted a single
  `tools/list` carrying the subject's bearer and no session id — a command that
  succeeds against a correctly secured server and demonstrates nothing. The
  finding now carries the two steps the defect actually consists of: open the
  session as the subject, keep the id the server issued, then send the same
  request with that id and no credential. `findings.json` gains a `handshake`
  object alongside the request for the same reason.

## [0.29.1] - 2026-08-12

### Fixed
- **The audience probe skipped exactly the subjects it was built for.** It
  required a static `token:` on the subject, but `authenticate()` writes what a
  provider returned into `subject.headers` under that provider's `token_header`
  and leaves `token` unset. Every identity using the discovered-OAuth flow — the
  one case RFC 9728 discovery and audience binding exist for — therefore
  generated no probe at all, and so did every subject using a custom scheme (an
  API key header, a session cookie). The feature reported nothing and looked
  like it had found nothing. A subject now counts as credentialed when it has a
  token *or* a credential-bearing header; the session probe uses the same
  test, which also stops a bare `X-Tenant` from being mistaken for an identity.

- **A credential declared on a server authenticated every subject through it.**
  `mcp_headers` withheld the subject's bearer whenever an `Authorization` header
  was already present — including one inherited from `servers[].headers`, which
  belongs to no identity in particular. Every subject then authenticated as that
  one credential: their own tokens were never sent, and a matrix meant to
  distinguish callers was testing a single caller under several names. The token
  now yields only to an `Authorization` the *subject* set, which remains a
  deliberate choice of auth scheme. `overstep.mcp_client` (setup/teardown
  fixtures) had the same precedence bug and also ignored subject headers
  entirely; both are fixed.

  For the audience probe this was additionally a false-positive source: the
  target server's own key would authorize the `tools/list`, and the result read
  as acceptance of the foreign token. That probe now drops server-declared
  credentials outright — the only request in the suite that does — because its
  verdict is meaningless if anything else could have authenticated the call.
  Non-credential server headers are still sent, so the probe otherwise looks
  like a real client.

- `SECRET_HEADERS` moved to `overstep.models` as the single definition of "this
  header carries a credential", shared by redaction and by the two checks above,
  so masking and probing cannot disagree about what a credential is.

## [0.29.0] - 2026-08-12

### Added
- **Session-binding probing for MCP servers.** Streamable HTTP hands out an
  `Mcp-Session-Id` at `initialize`, and the spec is explicit that it must not be
  used to authenticate: session identifiers travel in headers, and headers end up
  in proxies, access logs and referrers, so a server that accepts one as proof of
  identity lets anybody holding the string become the user who opened it.

  Every Streamable HTTP server is now checked, without configuration. The probe
  opens a session as the subject, then sends the same **anonymous** `tools/list`
  twice — once carrying the session id, once without it. The second request is
  the control, and it is what makes the result mean anything: a server whose
  listing is simply public answers the first request too, and reporting that as
  session hijacking would be a finding about nothing. Only the difference between
  the two counts, so a defect is reported solely when the session is what made
  the request work.

  A server that issues no session id is stateless and has nothing to hijack; the
  probe is recorded as skipped rather than answered, since it never ran. Findings
  are class `session-hijack` (CWE-287, `API2:2023`). Set
  `probe_session_binding: false` to switch it off.

- **Tool-enumeration probing, opt-in.** A server that advertises a tool to
  someone who may not invoke it discloses the shape of its privileged half.
  `probe_tool_enumeration: true` calls `tools/list` as each subject and compares
  what came back with the policy already in the matrix: a declared tool listed to
  a subject with no allow rule for it is reported as `tool-enumeration`
  (CWE-200, `API5:2023`, medium).

  Opt-in unlike the other two probes, and the asymmetry is deliberate — listing
  everything and enforcing at call time is a common, defensible design, so
  reporting it by default would be an opinion dressed as a finding. Session
  hijacking and a token accepted from the wrong audience are never defensible.

  Two deliberate silences: a tool the matrix does not declare is undescribed
  rather than disallowed, which is `overstep coverage`'s gap to report; and a
  subject that cannot list at all has nothing to disclose, so its refusal is not
  reported as an over-restriction.

### Changed
- `Observation` carries `listed_tools` for a `tools/list` request. The names are
  recorded from the result rather than parsed back out of `body_snippet`, which
  is truncated at 2048 characters — a tool catalogue being exactly the kind of
  result long enough to lose its tail. The token-audience confidence grading uses
  it too, in place of the JSON parse it did before.
- `McpInvocation` gains `anonymous` and `handshake_headers`, which let a probe
  open a session as one identity and then send its request as nobody.

## [0.28.0] - 2026-08-12

### Added
- **Token-audience probing for MCP servers.** Every check overstep made until now
  assumed the server had correctly identified its caller, and asked what that
  caller was permitted to do. This asks the question underneath: does the server
  check *who the credential was issued for*?

  The MCP authorization spec answers it for them — a server must not accept a
  token that was not issued for it — and one that skips the check is a confused
  deputy. The token a user handed to one server works at another, so the blast
  radius is not one object but every service trusting the same issuer. overstep
  already spoke the discovery half of this (RFC 9728 metadata, RFC 8707 resource
  indicators) to *obtain* audience-bound tokens; it never tested whether anyone
  validated them.

  Declare what a subject's token is bound to and its credential is replayed at
  every MCP server that audience does not identify:

  ```yaml
  subjects:
    - name: alice
      role: user
      token: ${ALICE_DOCS_TOKEN}
      token_audience: docs        # a server name from servers:, or an audience URI
  ```

  It is inferred for a subject authenticating through a provider that discovers
  its token endpoint from a server, or that sends an explicit `resource` — such a
  token is audience-bound by construction. Where no audience is known, no probe
  is generated: overstep does not guess which credential belongs where, and a
  matrix that declares none plans exactly the cases it planned before.

  The probe is `tools/list` rather than a tool-call. It requires authorization,
  takes no arguments and changes nothing, so it isolates the single question
  being asked — was this credential accepted at all — without invoking anyone's
  tool and without needing an object to be resolvable. One probe per (subject,
  server): validating the audience is a property of the server, not of each tool.
  A server that serves its catalogue to a foreign token is graded `confirmed`;
  one that answers without an error but lists nothing is `suspected`, since an
  empty capability set is how some servers signal refusal.

  Findings are class `token-audience` (CWE-863, `API2:2023`), count as
  vulnerabilities for `--fail-on vuln`, and carry the usual `curl` repro. The
  matrix policy is deliberately not consulted — an admin's token bound to server
  A must still be refused by server B — so the probe expects a denial whatever
  the matrix allows that subject.

  Streamable HTTP only: on stdio the token is placed in the child process's
  environment under a variable that server itself named, so there is no audience
  to violate. Set `probe_token_audience: false` for a deployment where one
  credential is legitimately valid at several declared servers, which is the one
  case where a refusal is not required.

## [0.27.2] - 2026-08-12

### Fixed
- **An MCP server that refuses over HTTP is no longer reported as wide open.**
  The MCP oracle read only the JSON-RPC message: a `error` member, or a result
  with `isError: true`. The HTTP status the message arrived under was recorded on
  the observation and then never consulted.

  That leaves the spec's own refusal path unreadable. MCP authorization has an
  unauthorized request answered with `401` and a `WWW-Authenticate` header, and
  nothing requires the body to be JSON-RPC — an empty body, or a framework's
  `{"detail": "Not authenticated"}`, is what real servers send. Neither has an
  `error` member or an `isError` flag, so evaluation fell through to the final
  "the tool ran and returned data" branch and recorded **allow**.

  The consequences ran in both directions. Every negative test against a properly
  secured server became a BOLA, BFLA or privilege-escalation finding — a false
  positive on the most ordinary case there is, an unauthenticated caller being
  turned away. And a run whose credentials were all rejected looked fully
  authenticated, so the inconclusive check saw healthy positive controls and
  passed a run that had proved nothing.

  `McpMatcher` now carries `deny_status`, defaulting to `["4xx", "5xx"]`: a
  non-2xx response means the tool-call was never delivered, whatever the reason.
  It is consulted after the content regexes and before the in-band signals, so an
  explicit `allow_content_regex` still wins. Streamable HTTP only — stdio has no
  status, and its synthetic delivery marker is not fed to the matcher. Set
  `deny_status: []` to restore the previous behaviour for a server that reports
  genuine denials in-band under a non-2xx status of its own.

## [0.27.1] - 2026-08-11

### Fixed
- **A bad input file now fails as a message, not a traceback.** The two most
  common mistakes with this tool — typing a path that isn't there, and
  mis-indenting a YAML file — escaped as a raw Python traceback from whichever
  loader happened to open the file, burying the one useful line under forty
  lines of overstep's own source. That was the worst diagnostic in the most
  travelled path, and out of step with the rest of the tool, where an expired
  token or an unreachable target is explained precisely.

  Reading is now centralized, and every failure to obtain a document names the
  file, its role in the run, and where the parser stopped:

  ```
  error: matrix 'matirx.yaml' does not exist
  error: matrix 'matrix.yaml' is not valid YAML: mapping values are not allowed here (line 18, column 8)
  error: waivers file 'waivers.yaml' is not valid YAML: ... (line 4, column 3)
  error: baseline 'baseline.json' is not valid JSON: Expecting value (line 1, column 1)
  ```

  This covers every file the CLI reads — matrix, OpenAPI spec, HAR capture, MCP
  tools file, waivers and drift baseline — across `run`, `plan`, `validate`,
  `coverage`, `snapshot` and `scaffold`. All of them exit `2`, the existing
  configuration-error code.

  Two shape checks come with it, for documents that parse but are not what was
  asked for: a spec whose top level is not a mapping, and a HAR file that is not
  an object, are now named as such instead of failing later on an `AttributeError`.

### Changed
- `overstep.drift.load_snapshot`, `overstep.loaders.openapi.load_resources` /
  `scaffold_matrix`, `overstep.loaders.har.load_resources` and
  `overstep.loaders.mcp.load_tools_from_file` raise `overstep.documents.DocumentError`
  instead of `OSError` / `yaml.YAMLError` / `json.JSONDecodeError`. It subclasses
  `ValueError`, so callers already catching `(OSError, ValueError)` are unaffected.
  `load_matrix` and `load_waivers` keep raising `MatrixError` and `WaiverError`.

## [0.27.0] - 2026-08-11

### Added
- **Each command now names the next one.** `scaffold`, `validate`,
  `validate --live` and `plan` are individually clear and collectively a
  sequence nobody is told, so a user who stops after any one of them has a file
  rather than a result. Each step now ends with a `next:` line pointing at the
  one after it.

  The hints go to **stderr**, so a redirected `overstep scaffold ... > matrix.yaml`
  still produces a parseable file, and are suppressed entirely by setting
  `OVERSTEP_NO_HINTS`.

  Two cases deliberately print nothing. A `validate` that found *errors* names no
  next step — the errors are the next step, and each already says what to do.
  And a bare `resources:` block from `scaffold` without `--with-policy` is a
  fragment, not a matrix, so it points at pasting it into one rather than at
  `validate`, which would only fail to parse it.

### Changed
- `validate` prints its verdict before the hint rather than after, so the two
  streams read in the order they happened. Exit codes are unchanged, including
  `--strict`.

## [0.26.0] - 2026-08-11

### Added
- **`overstep coverage MATRIX [--spec SPEC]`** — reports what the matrix covers,
  and sends nothing. Two absences make `Vulnerabilities 0` mean less than it
  looks like, and a finding count can express neither.

  The **API surface** is the outer one: the matrix *is* the specification, so an
  operation nobody declared is invisible by construction — no run sends it, and
  nothing in the findings mentions it. Comparing against an independent
  description of the API is the only way to see it. `--spec` reads OpenAPI
  (default), HAR (`--fmt har`), or an MCP server / `tools.json` (`--fmt mcp`).
  Missing operations are listed; so are matrix resources the spec does not
  mention, which is usually an undocumented endpoint or a stale spec, and
  occasionally a mistyped path — that one shows up as a gap and a stray at once.

  Matching normalizes away parameter naming, letter case and a trailing slash,
  so a spec writing `/users/{user_id}` and a matrix writing `/users/{id}` are
  one operation rather than a phantom gap.

  The **object surface** is the cross-owner probe coverage added in 0.24.0,
  reported here without needing a run.

  `--fail-under N` exits `1` when either percentage is below `N`, so the number
  can gate a pipeline rather than only describe one.

## [0.25.0] - 2026-08-11

### Added
- **`overstep validate --live`** — asks the target the two questions the file
  cannot answer: is it reachable, and is each subject's credential still
  accepted? The inconclusive check already judged both, but only afterwards,
  from a full run's observations, and only as the generic "the credentials or
  the matrix are wrong". Asked first, the same judgement becomes "alice was
  denied `GET /users/u1` (HTTP 401)" before any negative test has been sent.

  It works by borrowing the run's own positive controls: an expected-*allow*
  case is by definition a request the matrix says that subject may make, so
  sending one and seeing it allowed is the cheapest proof the identity works.
  One probe per subject.

  The check does not change state. Probes go through the executor with
  `read_only` set and non-mutating verbs are preferred, so a subject whose only
  positive control is a `DELETE` is reported as unverifiable rather than
  verified destructively; setup steps are not run for the same reason. A
  delivery failure is reported as an unreachable target rather than a bad
  credential, since a request that never arrived says nothing about the token.
  Anonymous subjects are not flagged — carrying no credential, having nothing to
  verify is their normal shape, not a gap.

  `validate` also gained `--base`, `--insecure` and `--env-file`, needed to
  reach a target the way `run` does.

## [0.24.0] - 2026-08-11

### Added
- **Runs now report how much of the BOLA surface they could actually probe.**
  A cross-owner probe is the only thing that tests object-level access control,
  and the planner generates one only when two subjects resolve to genuinely
  different objects — otherwise it drops the probe rather than replaying a
  subject's own request under the OTHER label, which would manufacture a pass.
  That was right but silent: a resource nobody probed and a resource probed and
  found clean both contributed `0` to the finding count, so `Vulnerabilities 0`
  could not be told apart from "the matrix never asked". The summary now carries
  `Object resources probed n/m`, names the resources a probe was never generated
  for, and ships the same numbers in `findings.json` under
  `summary.object_resources{,_probed,_unprobed}`. `overstep plan` prints the note
  too, without touching the network.
- **`TestCase.victim`** — the subject whose object a cross-owner probe reaches
  for. It is what separates a real probe from the victimless OTHER case the
  planner emits when *nobody* can resolve an object for a resource: that case
  exercises the endpoint but reaches for a default id belonging to no subject,
  and counting it would report coverage the run does not have. Test ids are
  unchanged — the victim suffix stays reserved for `probe_victims: all` — so
  existing baselines and waivers keep matching.

## [0.23.0] - 2026-08-11

### Added
- **`validate` now refuses an untouched scaffold.** `overstep scaffold` writes
  `PASTE_..._TOKEN` and `REPLACE_ME_1` where a credential and an object id go;
  `validate` used to answer `ok — matrix is valid` and exit `0` for a file that
  still contained every one of them. Left in, they do not half-configure a run —
  they kill it: every credential is rejected, so every expected-allow test fails
  and every expected-deny test "passes" for the wrong reason. The run was still
  caught afterwards by the inconclusive guard, but only as "the credentials or
  the matrix are wrong", after a full pass over the network. The new scan reads
  the file, so it names the line and what to put there, and `run` prints the same
  lines before sending its first request. Matching is anchored to the whole
  value, so a real credential is never rejected for containing those letters, and
  a `${ENV_VAR}` reference — the fix the message recommends — does not trip it.

### Changed
- **Validation problems now carry a severity.** Everything used to land in one
  list, which forced both kinds to be mishandled: `validate` failed on all of
  them, so a deliberate deny-by-default resource broke a build, while `run`
  printed all of them as warnings, so a broken reference looked cosmetic. Errors
  (broken references, undeliverable resources, unfilled placeholders) mean the
  matrix cannot produce a trustworthy result and exit `1`. Warnings (no policy
  entry, no two subjects with distinct objects) mean the run happens and its
  findings are real, but it tests less than its size suggests — they exit `0`,
  or `1` under the new `--strict`. Errors print first.
- `Matrix.diagnose()` returns the new `Problem` records; `Matrix.validate_refs()`
  is unchanged and still returns the same list of plain strings.

## [0.22.4] - 2026-07-28

### Fixed
- **The requirements/pyproject sync check would have failed on a valid
  dependency.** Its TOML reader split the array on commas and stopped at the
  first `]`, so `urllib3>=1.26,<3` became two entries and
  `pydantic[email]>=2.6` truncated the array — silently dropping every
  dependency declared after it. Either would have blocked CI on a perfectly
  correct `pyproject.toml`, and the second would have done so while *under*
  -reporting what needed to match. The reader now scans with quote awareness,
  and five tests cover both specifier shapes plus empty, adjacent and
  unterminated arrays.

## [0.22.3] - 2026-07-28

### Added
- **`SECURITY.md`.** A security tool had no way to report a vulnerability in
  itself. Reports go through GitHub's private advisory form; the policy also
  draws the line this project needs drawn — a finding overstep reports about
  *your* API is a bug in your API, while leaking a credential into a report,
  escaping the expression sandbox, attaching one subject's token to another
  subject's request, or making a run exit `0` when its probes never executed are
  vulnerabilities in overstep.
- **A pull-request template**, matching what `CONTRIBUTING.md` asks for: tests,
  the three-place version bump, changelog and README. It also asks explicitly
  whether the change alters an exit code, the generated test set, or the shape of
  a report — the three things that break other people's pipelines and baselines.
- **A test that `requirements.txt` agrees with `pyproject.toml`.** CI installs
  from one and the package from the other, so a dependency added to either could
  silently be missing from the other. The two are in sync today; now they stay
  that way.

### Changed
- `CODE_OF_CONDUCT.md` now routes reports to the same private channel. It
  previously suggested opening a GitHub issue, which asks someone to make a
  conduct complaint in public.

## [0.22.2] - 2026-07-28

### Fixed
- **The release checklist described steps the workflow already performs and
  omitted the one that matters.** It told maintainers to create the GitHub
  Release by hand (the workflow does it), never mentioned PyPI publishing or the
  `workflow_dispatch` path that creates the tag — the only usable path where
  pushing tags is blocked — and left out a hard requirement: release notes are
  extracted by matching a `## [X.Y.Z]` heading in this file exactly, so a
  mismatched heading ships an empty release body.
- **The project layout in CONTRIBUTING listed nine modules of the twenty-odd that
  exist**, under paths missing the `src/` prefix, and omitted every pluggable
  seam (`transports/`, `loaders/`) plus `health.py`. Rewritten around what a
  contributor is looking for: the core path of a run, the seams to extend, and
  the supporting modules.
- **Package metadata undersold half the tool.** The PyPI description covered only
  HTTP APIs and omitted BOPLA; keywords named neither MCP nor BOPLA. Both now
  match the repository description.

### Added
- `action.yml` exposes `read-only`, `env-file`, `concurrency`, `max-retries` and
  `allow-inconclusive`. Five of the eleven CLI flags had no Action equivalent, so
  a workflow could not run read-only against a sensitive target or supply
  `${VAR}` values from a dotenv file. A test now asserts every declared input is
  actually passed through to the CLI — an input nobody forwards is a lie in the
  interface.
- Two principles in the contributing standards that this release cycle
  established: never fail open, and never generate a test that proves nothing.

## [0.22.1] - 2026-07-28

### Changed
- **README restructured around the reader's task.** It had grown to 852 lines
  across 35 sections in the order features were added, with no contents list, and
  the section that matters most — how to point the tool at *your own* API — sat at
  line 601, after five hundred lines of tuning reference. It now runs: what it
  finds → what it doesn't do → install → a two-minute demo → **a six-step
  walkthrough from a spec to a trustworthy result** → the matrix → trustworthy
  findings → modelling a real API → MCP → CI → reference.

### Fixed
- **Documentation that no longer matched the tool.** The quickstart summary
  predated the defect roll-up (`Vulnerabilities 8` where the tool prints
  `8 (3 defects)`), and the plan table was attributed to a command that actually
  emits eighteen rows. Both are now the verified output.
- **`Install` never said how to install the tool** — only `pip install -e .`,
  which assumes you already cloned the repo, despite the package being published
  on PyPI. `pip install overstep` is now first, with the editable clone kept for
  contributors and the bundled demo.

### Added
- A **What it doesn't do** section: no endpoint discovery, no policy inference, no
  authentication testing, no fuzzing, no natural-language agent driving, and a
  reminder that runs send real requests. Previously these limits were scattered,
  or present only as a footnote in the MCP section.
- A contents list, and a flag reference table (which flags apply to `run` vs
  `snapshot`, plus the exit-code meanings) in place of a prose list.

## [0.22.0] - 2026-07-28

### Added
- **`probe_victims: one | all`** — how many distinct objects each subject reaches
  for on an object resource, set matrix-wide or per resource. The default stays
  `one`, which is what every existing matrix gets.

  A single cross-owner probe per subject catches a check that is missing
  outright, but not one that **holds for some owners and not others** — a tenant
  whose ACL rows were never backfilled, a legacy record with no owner column —
  because the one object a subject happens to reach for may be the protected one.
  Measured against a target carrying exactly that bug (one tenant world-readable,
  every other tenant correctly scoped):

  | | `one` | `all` |
  |---|---|---|
  | Tests | 63 | 85 |
  | Distinct defects found | 3 | **4** |

  `one` missed it entirely; no subject's single probe happened to point at the
  unprotected tenant.

  Victims holding the same object count once, so `all` is not a blind N²: on a
  matrix where subjects share objects it costs almost nothing, and it only grows
  where there are genuinely distinct objects to reach.

### Changed
- A test id gains a `@victim` suffix **only** where a subject probes more than
  one object. Every id a matrix produced before this release keeps its exact
  spelling, so existing drift baselines stay comparable; turning on
  `probe_victims: all` adds ids rather than rewriting them, and `drift.diff`
  ignores ids missing on either side.

## [0.21.0] - 2026-07-28

### Changed
- **The `curl` repro is runnable again.** Credentials were replaced by a bare
  `***`, which made the documented "copy-pasteable repro" a command that answers
  `401` — safe to share and useless to act on. The secret is now a shell variable
  named after the subject that owns it, so exporting one value reproduces the
  exact request:

  ```bash
  curl -sS -X GET -H "Authorization: Bearer $OVERSTEP_TOKEN_ALICE" http://…/users/u2
  ```

  Each subject gets its own variable (`OVERSTEP_TOKEN_<SUBJECT>`, or
  `OVERSTEP_<HEADER>_<SUBJECT>` for a non-bearer secret) so a repro can never
  authenticate as the wrong identity, and the same applies to the stdio MCP
  token environment. No credential is written to any report. `mask_headers()`
  called without a subject name still redacts to `***` as before.

### Added
- **A defect roll-up, so triage tracks bugs instead of identities.** One missing
  check is reported once per subject that reaches it: on the evaluation matrix a
  single over-sharing endpoint produced 7 findings. Reports now group findings
  into the distinct defects behind them (`resource` + `method` + class), keeping
  every finding intact:
  - the summary reads `Vulnerabilities  11 (3 defects)`;
  - `findings.json` gains a `defects` array — worst first, each with its
    `subjects`, `findings` count and an `example_test_id`;
  - the HTML report leads with a **Defects** table above the findings;
  - every finding carries a `group` key so a dashboard can collapse them too.

  Gating is unchanged: `--fail-on` still counts findings, so no run changes its
  exit code because of this.

## [0.20.1] - 2026-07-28

### Fixed
- **An "other" probe could re-send the subject's own request.** The victim for a
  cross-owner probe was the first *other* subject that owned an object, without
  checking it was a **different** object. Subjects legitimately share one — two
  members of a tenant, a service account and the user it acts for — so the probe
  was byte-identical to that subject's own SELF request: it exercised nothing
  while counting as BOLA coverage, and could report the subject's own data as a
  cross-owner leak. On a two-tenant evaluation matrix, 12 of 55 planned cases
  were such probes, silently.

  The victim is now the first subject whose ownership values actually differ.
  Where a real victim exists the probe is redirected to them rather than
  dropped, so coverage *improves*: the same matrix went from 1 to 3 confirmed
  BOLA findings, because cross-tenant reads that were never attempted now are.
- **Both scaffolds emitted a matrix that could not test BOLA.** A single
  placeholder user subject means no two subjects own different objects, so no
  cross-owner probe exists at all — the tool's headline check was unreachable
  from its own starter matrix. `scaffold --with-policy` and `scaffold --fmt mcp`
  now emit two peer subjects with suffixed placeholders (`REPLACE_ME_1` /
  `REPLACE_ME_2`) that say the two must not be filled in with the same id.

### Added
- `validate` reports an object resource whose subjects all resolve to the same
  object, naming the shared value — otherwise the missing probe is invisible.

### Upgrading
A baseline recorded before this version may report one-off drift on `::other`
test ids whose victim changed: the test id is stable but the object it targets
is not the same one. Re-snapshot after reviewing. Cases that disappear entirely
(no distinct victim exists) are skipped by the drift comparison rather than
reported as changes.

## [0.20.0] - 2026-07-28

### Fixed
- **`scaffold --with-policy` no longer declares a whole API public.** Two common
  spec shapes produced a policy of `allow: [{role: anonymous, scope: any}]` for
  every endpoint — a matrix with **zero negative tests**, which then reported
  `Vulnerabilities 0` against an API with real holes:
  - a spec that protects everything with a plain bearer token or api key
    (`security: [{bearerAuth: []}]`). The requirement names no *scope*, and only
    scopes were being read, so "requires a credential" was misread as "public".
    Such an operation is now allowed to any authenticated role — anonymous being
    precisely what the document rules out — with object resources still
    defaulting to owner-scope.
  - a spec that never mentions authorization at all (no `security`, no
    `securitySchemes`), which is what most generated documents look like. Nothing
    can be inferred from silence, so the policy is now a **deny-by-default
    guess** carried behind a warning header in the emitted YAML and a warning on
    stderr, instead of an inverted policy presented as fact.

  An operation a *documented* spec deliberately leaves unprotected is still
  public — that reading is unchanged.

### Changed
- `scaffold_matrix()` takes an optional `warn` callback, invoked when the policy
  had to be guessed, so a caller can surface it outside the emitted document.

### Upgrading
A matrix scaffolded from an authorization-silent spec now denies by default, so
an unmodified scaffold over-reports (`unexpected-deny` findings for access that
is genuinely allowed) where it previously under-reported to zero. That is the
intended direction: loosen the rules as you confirm them.

## [0.19.2] - 2026-07-28

### Fixed
- **A custom transport was judged as part of the HTTP target.** 0.19.1 grouped
  the health verdict by MCP server but folded everything else into HTTP, so a
  transport registered through the public `transports.register()` seam inherited
  HTTP's reachability — six healthy HTTP requests beside four failed custom ones
  stayed under the threshold and reported clean, the same masking the per-target
  split was meant to end. Targets are now grouped by `case.transport` first
  (with MCP still refined per server), and an unregistered or unreachable
  transport is named in the verdict as `the 'name' transport`.

## [0.19.1] - 2026-07-28

### Fixed
Three ways an inconclusive run could still slip through as clean, all found by
review of 0.19.0:

- **A dead stdio MCP server counted as healthy.** The stdio transport turns a
  timeout or premature EOF into `status = 0` with **no** error string, so
  requiring a non-empty `error` missed it entirely: a hung local server produced
  zero transport errors and the run exited clean. `status == 0` is reserved for
  a delivery failure by every transport and skipped tests are excluded
  separately, so the status alone is now the signal.
- **A healthy target could mask an unreachable one.** The verdict aggregated the
  whole run, so a busy HTTP API outvoted an MCP server that answered nothing —
  6 delivered HTTP requests plus 4 failed MCP ones stayed under the threshold,
  and the HTTP positives satisfied the credential check, while the entire MCP
  surface never executed. Reachability and positive controls are now judged
  **per target** (the HTTP base URL, and each MCP server by URL or stdio argv),
  and the verdict names the target that failed.
- **`--read-only` could remove the last positive control.** Skipped
  expected-allow tests were dropped before the credential check, so a matrix
  whose allow-rules all sit on mutating verbs left no positive control and
  passed silently. A run whose planned positive controls were *all* skipped is
  now inconclusive, while an intentionally all-negative matrix — which never had
  one — is still not condemned.

### Changed
- An unreachable target no longer also reports its positive-control failure:
  that is the same fact told twice, since a target nothing reaches denies
  everything by definition.

## [0.19.0] - 2026-07-28

### Added
- **Inconclusive-run detection — the gate no longer fails open.** A run whose
  requests never reached the target, or whose credentials were rejected, used to
  report `Vulnerabilities 0` and exit zero: a green CI build because the API
  never started. Such a run is now called *inconclusive* and exits **3**, a code
  distinct from 1 (findings) and 2 (bad input) so a pipeline can tell "you have
  an authorization hole" apart from "the scan never ran". Two conditions trigger
  it — at least half the requests failing at the transport layer, or not one of
  the expected-*allow* tests being allowed (expired tokens, a bad `--env-file`,
  or a scaffolded matrix still carrying its `PASTE_..._TOKEN` placeholders).
- `--allow-inconclusive` on `run` and `snapshot` restores the previous exit
  code. The verdict is still printed, so the escape hatch cannot hide the cause.
- `summary.inconclusive` and `summary.inconclusive_reasons` in `findings.json`,
  so a dashboard never reads an empty run as a clean one.
- `RunResult.health` (a `RunHealth` with the counts behind the verdict) for
  embedding applications.

### Changed
- `snapshot` **refuses to write a baseline** from an inconclusive run. Such a
  baseline records "everything is denied" and would report the next healthy run
  as wholesale authorization drift. `snapshot_pipeline` raises the new
  `InconclusiveRunError` unless `allow_inconclusive=True` is passed.

### Upgrading
Pipelines that were silently green because their target was unreachable will now
fail with exit 3 — that is the point of the change, and the message names the
cause. A job that must keep its old exit code can pass `--allow-inconclusive`.
The `--fail-on` values are unchanged, but they no longer decide this case: they
govern findings, and cannot vouch for a run that never happened.

## [0.18.1] - 2026-07-28

### Added
- **Version badge in the README**, asserted by `tests/test_distribution.py` to
  match `__version__` and the `pyproject.toml` version, so a release can no
  longer ship with the three drifting apart.

### Fixed
- **A false green from the wrong test runner.** The suite is pytest-based, so
  `python -m unittest discover -s tests` collected zero tests and still exited
  `OK`. `tests/test_runner.py` now fails under any non-pytest runner, and
  CONTRIBUTING names `pytest -q` as the canonical command.

## [0.18.0] - 2026-07-10

### Added
- **Generalized object-identifier injection.** The identifier of the object a
  subject reaches for — the BOLA/BOPLA surface — can now live anywhere in a
  request, not just a path parameter. A resource declares
  `ownership.injections`, each with a `location` (`path`, `query`, `header`,
  `cookie`, `form`, `json`, `graphql_variables`, or `mcp_argument`) and a
  `selector`; overstep writes the caller's own object id (SELF) or a victim's
  (OTHER) into every declared location:
  - `json` selectors are JSONPaths into the request body (`$.order.id`), with
    nested object and array creation.
  - `graphql_variables` writes a GraphQL variable (by name or `$.path` under
    `variables`), giving first-class GraphQL BOLA coverage.
  - `form` sends an `application/x-www-form-urlencoded` body (new `request.form`).
  - `mcp_argument` writes a tool argument (by key or JSONPath into the arguments).
  - Multiple injections are written together (e.g. object id in a header and
    tenant in another), and a per-injection `owner_attr` sources a value from a
    different subject attribute than the object id.
- **Example & validation.** `examples/injections/matrix.yaml` demonstrates every
  location. `validate` now flags an injection whose location doesn't match the
  transport, a `path` selector that isn't a parameter of the path, and an object
  no subject can resolve (so ownership is never faked with a placeholder id).

### Changed
- `owner_param` and `owner_arg` are now thin shortcuts over the injection model
  (a single `path` / `mcp_argument` injection respectively). Existing matrices,
  snapshots and test IDs are unaffected — this is fully backward compatible.

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
  warning and never masks the original error. `snapshot` now surfaces those
  teardown warnings too, instead of writing the baseline silently.
- **SARIF results now carry a physical location.** Every finding is anchored to
  the matrix file it came from (`run` fills this in; a placeholder is used
  otherwise), with the endpoint kept as a logical location. GitHub code scanning
  rejects a result with no physical location, so without this the `upload-sarif`
  step failed even though the scan itself succeeded.

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
