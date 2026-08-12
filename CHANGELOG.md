# Changelog

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
