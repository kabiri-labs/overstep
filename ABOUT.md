## About (for GitHub)

**One-liner:**
overstep is an authorization testing tool: you declare who is allowed to do what
as a matrix, and it turns that into positive and negative requests against a
running target, reporting every one that should have been refused and wasn't.
REST APIs and MCP servers are two surfaces it covers through the same matrix.

**About (repo description):**
Authorization testing for REST APIs and MCP servers. Declare who may do what as a
matrix, and overstep turns it into positive and negative tests that catch BOLA,
BFLA, BOPLA and privilege escalation — with drift baselines, confidence grading
and CWE/OWASP-tagged SARIF for CI.

**Short description:**
Authorization is the check a callee makes before it acts: *may this caller
perform this action on this object?* It resists automated scanning because it is
a logic flaw rather than a syntactic one — `GET /invoices/8842` is a valid
request whether or not invoice 8842 belongs to the caller, and nothing in the
request, the response or the specification distinguishes the legitimate read from
the cross-tenant one. Detecting it requires knowing what the system is *supposed*
to permit, which lives in a product decision rather than in any spec.

So overstep asks for that knowledge up front. You describe subjects (roles and
identities) crossed with resources (API operations, or MCP tools and resource
URIs) and an allow-list policy. overstep expands the matrix into concrete
requests — positive tests for access that should succeed, negative tests (self
vs. other, per role) for access that should be denied — runs them against a live
target, and reports every negative test that slipped through, classified,
graded by confidence and shipped with a copy-pasteable repro.

REST and MCP are modules over one shared core: the matrix model, the planner,
ownership resolution, the classifier, drift and every reporter are common, and
only delivery differs. MCP is the newest and hardest instance of the class —
the caller is an agent acting on behalf of a user, there is no `403`, the same
objects are reachable through `resources/read` as well as through tools, and the
protocol imposes authorization rules on the server itself — so it also gets
probes that ask about the credential and the connection rather than about any one
operation.

**Highlights:**
- Authorization matrix as code — reviewed and versioned like the rest of your app.
- Object-, function- and property-level authorization (BOLA / BFLA / BOPLA),
  privilege escalation and multi-tenancy isolation, on both surfaces.
- **REST**: ownership injected wherever the object id travels — path, query,
  header, cookie, form, JSON body or GraphQL variables — plus cross-method
  probing, and scaffolding from OpenAPI or a HAR capture.
- **MCP**: the whole surface — `tools/call`, `resources/read` by URI, and the
  protocol's own rules (credential audience, session binding, tool enumeration) —
  over Streamable HTTP and stdio, with OAuth 2.1 discovery (RFC 9728/8414/8707).
- Findings mapped to CWE and the OWASP API Security Top 10, **content-verified**
  through markers so a granted request is only called a leak when the victim's
  data actually came back.
- Findings rolled up into the **distinct defects** behind them, so triage tracks
  the number of bugs rather than the number of identities that hit them.
- Drift baselines and waivers so CI fails on *changes*, not on known accepted risk.
- **A gate that refuses to fail open** — a run whose target was unreachable or
  whose credentials were rejected is reported as *inconclusive* (exit 3), never
  as a clean bill of health.
- Coverage reporting for what the matrix never declared *and* what the run could
  not probe, so "no findings" is only ever claimed where it means something.
- JSON, HTML, SARIF (code scanning) and JUnit reports; non-zero exit for gating.
- Ships a Docker image, a GitHub Action and a pre-commit hook.

**Not this:**
overstep is not an AI or LLM security tool. It does not drive an agent with
natural-language prompts and has no opinion about tool descriptions; prompt
injection and tool poisoning *against the agent* are a separate, non-deterministic
concern. It tests the server's enforcement.

**Topics (GitHub repo tags):**
authorization, authorization-testing, access-control, broken-access-control,
api-security, bola, idor, bfla, privilege-escalation, security-testing, appsec,
owasp, sarif, devsecops, ci-cd, dast, rest-api, mcp, model-context-protocol,
mcp-security
