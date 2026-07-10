## About (for GitHub)

**One-liner:**
overstep is a matrix-driven authorization testing tool for **HTTP APIs and MCP
tool-calls** that turns a declarative access-control matrix into positive and
negative tests and catches BOLA, BFLA, BOPLA, privilege escalation and
authorization drift in CI/CD.

**About (repo description):**
Matrix-driven authorization testing for HTTP APIs and MCP tool-calls. Turns an
access-control matrix into positive & negative tests that catch BOLA, BFLA, BOPLA,
privilege escalation and authorization drift — with CWE/OWASP-tagged SARIF for CI/CD.

**Short description:**
You describe *who is allowed to do what* as an authorization matrix — subjects
(roles/identities) crossed with resources (API operations **or MCP tools**) and an
allow-list policy. overstep expands that matrix into concrete requests: positive
tests for access that should succeed and negative tests (self vs. other, per role)
for access that should be denied. It runs them against a live target — an HTTP API
or an MCP server — and reports every negative test that slips through, classified
as BOLA, BFLA, BOPLA or privilege escalation, graded by confidence and shipped with
a copy-pasteable repro. Snapshot the decisions and it fails your pipeline the
moment the authorization surface drifts between releases.

**Highlights:**
- Authorization matrix as code — reviewed and versioned like the rest of your app.
- Tests **HTTP APIs and MCP / agent tool-calls** through one pluggable transport
  registry (MCP over Streamable HTTP and stdio, with OAuth 2.1 discovery).
- Automatic positive + negative test generation (object-, function- and
  property-level), plus cross-method probing.
- Findings classified as BOLA / BFLA / BOPLA / privilege escalation, **content-
  verified** (confidence grading via markers) and mapped to CWE / OWASP API Top 10.
- Drift baselines and waivers so CI fails on *changes*, not on known accepted risk.
- JSON, HTML, SARIF (code scanning) and JUnit reports; non-zero exit for gating.
- Scaffold a matrix straight from OpenAPI, a HAR capture, or a live MCP server's
  `tools/list`.
- Ships a Docker image, a GitHub Action and a pre-commit hook.

**Topics (GitHub repo tags):**
security, appsec, devsecops, authorization, access-control, api-security, dast,
bola, bfla, bopla, privilege-escalation, authorization-testing, mcp,
model-context-protocol, ai-agents, agent-security, owasp, sarif, ci-cd, api-testing
