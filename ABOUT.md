## About (for GitHub)

**One-liner:**
overstep is a matrix-driven authorization testing tool for **MCP servers** — and
for HTTP APIs — that turns a declarative access-control matrix into positive and
negative tests and catches BOLA, BFLA, BOPLA, privilege escalation, token-audience
and session-binding flaws in CI/CD.

**About (repo description):**
Authorization testing for MCP servers; works on HTTP APIs too. Turns an
access-control matrix into positive & negative tests that catch BOLA, BFLA, BOPLA,
privilege escalation, token-audience and session-binding flaws across tools and
resources — with CWE/OWASP-tagged SARIF for CI/CD.

**Short description:**
You describe *who is allowed to do what* as an authorization matrix — subjects
(roles/identities) crossed with resources (**MCP tools and resource URIs**, or API
operations) and an allow-list policy. overstep expands that matrix into concrete
requests: positive tests for access that should succeed and negative tests (self
vs. other, per role) for access that should be denied. It runs them against a live
target — an MCP server or an HTTP API — and reports every negative test that slips
through, classified as BOLA, BFLA, BOPLA or privilege escalation, graded by
confidence and shipped with a copy-pasteable repro. On top of that it probes the
authorization rules the MCP protocol imposes on the server itself: that a token
issued for somewhere else is refused, and that a session id cannot stand in for a
credential. Snapshot the decisions and it fails your pipeline the moment the
authorization surface drifts between releases.

**Highlights:**
- Authorization matrix as code — reviewed and versioned like the rest of your app.
- Covers the **whole MCP surface**: `tools/call`, `resources/read` by URI, and the
  protocol's own rules (token audience, session binding, tool enumeration), over
  Streamable HTTP and stdio, with OAuth 2.1 discovery.
- **HTTP APIs too**, through the same matrix and the same pluggable transport
  registry — behind an MCP server, mixed with one, or on their own.
- Automatic positive + negative test generation (object-, function- and
  property-level), plus cross-method probing on HTTP.
- Findings classified as BOLA / BFLA / BOPLA / privilege escalation /
  token-audience / session-hijack / tool-enumeration, **content-verified**
  (confidence grading via markers) and mapped to CWE / OWASP API Top 10.
- Drift baselines and waivers so CI fails on *changes*, not on known accepted risk.
- **A gate that refuses to fail open** — a run whose target was unreachable or
  whose credentials were rejected is reported as *inconclusive* (exit 3), never
  as a clean bill of health.
- Findings rolled up into the **distinct defects** behind them, so triage tracks
  the number of bugs rather than the number of identities that hit them.
- Coverage reporting for what the matrix never declared *and* what the run could
  not probe, so "no findings" is only ever claimed where it means something.
- JSON, HTML, SARIF (code scanning) and JUnit reports; non-zero exit for gating.
- Scaffold a matrix straight from a live MCP server (both `tools/list` and
  `resources/templates/list`), an OpenAPI spec, or a HAR capture.
- Ships a Docker image, a GitHub Action and a pre-commit hook.

**Topics (GitHub repo tags):**
mcp, model-context-protocol, mcp-security, authorization, api-security, bola,
idor, broken-access-control, security-testing, appsec, owasp, sarif, devsecops,
ci-cd, access-control, authorization-testing, agent-security, dast, bfla,
privilege-escalation
