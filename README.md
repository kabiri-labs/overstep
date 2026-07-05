# overstep

**Matrix-driven authorization testing for HTTP APIs.**

![CI](https://img.shields.io/badge/CI-GitHub%20Actions-blue)
![License](https://img.shields.io/badge/license-Apache--2.0-green)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)

overstep takes a declarative **authorization matrix** — who is allowed to do what
— and turns it into concrete HTTP tests. It generates **positive** tests (access
that *should* succeed) and **negative** tests (access that *should* be denied),
runs them against a live target, and reports every negative test that slipped
through as an authorization vulnerability: **BOLA**, **BFLA** or **privilege
escalation**. Snapshot the results and CI fails the moment your authorization
surface **drifts**.

```
   authorization matrix  ──►  positive + negative tests  ──►  run  ──►  findings
   (subjects × resources)         (self / other, per role)        (BOLA/BFLA/privesc/drift)
```

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
- **Privilege escalation** — a lower-privileged role reaches something reserved
  for a higher one.
- **Authorization drift** — a decision that changed since your last release,
  caught by comparing against a saved baseline.

## Install

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e .            # or: pip install -e ".[dev]" for tests + demo server
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
| `report.html` | humans |
| `findings.json` | scripts / dashboards |
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
  - name: legacy_login_redirect
    request: { method: GET, path: "/account" }
    type: function
    access:
      treat_redirect_as: allow      # this endpoint 302s on success
```

Evaluation order: `deny_body_regex` (wins, fails safe) → `allow_body_regex` →
redirect handling → `allow_status`. Body patterns are case-insensitive and
matched against the full response body.

## Commands

| Command | What it does |
|---|---|
| `overstep run MATRIX` | generate, execute and report; non-zero exit on findings |
| `overstep snapshot MATRIX` | record current decisions as a drift baseline |
| `overstep plan MATRIX` | print the generated test cases (no network) |
| `overstep validate MATRIX` | lint a matrix for structural problems |
| `overstep scaffold SPEC --fmt openapi\|har` | generate a starter `resources:` block |

`run` flags: `--base` (override URL), `--out`, `--baseline`, `--concurrency`,
`--insecure`, and `--fail-on {vuln,drift,any,never}`.

## CI / CD: catching authorization drift

Bake the known-good state into a baseline, then fail only when authorization
*changes*:

```bash
# once, after triaging findings
overstep snapshot examples/mock_api/matrix.yaml --out baseline.json

# on every pull request
overstep run examples/mock_api/matrix.yaml --baseline baseline.json --fail-on drift
```

A cell that flips from **deny → allow** is a newly opened hole (high severity);
**allow → deny** is a new restriction (medium). Keep `matrix.yaml` and
`baseline.json` in version control and authorization gets reviewed like any other
code. See [`.github/workflows/ci.yml`](.github/workflows/ci.yml) for a full
example, including uploading SARIF to GitHub code scanning.

## Bootstrapping a matrix from a spec

Don't write the resource list by hand:

```bash
overstep scaffold openapi.yaml --fmt openapi > resources.snippet.yaml
overstep scaffold traffic.har  --fmt har     > resources.snippet.yaml
```

overstep guesses object-vs-function from id-like path parameters; you add the
policy.

## Comparison

| Capability | overstep | Burp Autorize / AuthMatrix | Schemathesis |
|---|---|---|---|
| Authorization matrix as code | ✅ | ⚠️ (per-request, manual) | ❌ |
| Positive **and** negative tests | ✅ | ⚠️ | ⚠️ |
| BOLA / BFLA / privesc classification | ✅ | ⚠️ | ❌ |
| Drift baselines for CI | ✅ | ❌ | ❌ |
| SARIF + JUnit output | ✅ | ❌ | ⚠️ |

> ⚠️ means possible only with significant manual effort.

## crAPI demo

See [`examples/crapi`](examples/crapi/README.md) to run overstep against OWASP
crAPI for a realistic BOLA/BFLA showcase.

## License

Apache-2.0.
