## About (for GitHub)

**One-liner:**
overstep is a matrix-driven authorization testing tool for HTTP APIs that turns a
declarative access-control matrix into positive and negative tests and catches
BOLA, BFLA, privilege escalation and authorization drift in CI/CD.

**Short description:**
You describe *who is allowed to do what* as an authorization matrix — subjects
(roles/identities) crossed with resources (API operations) and an allow-list
policy. overstep expands that matrix into concrete requests: positive tests for
access that should succeed and negative tests (self vs. other, per role) for
access that should be denied. It runs them against a live target and reports
every negative test that slips through, classified as BOLA, BFLA or privilege
escalation. Snapshot the decisions and it fails your pipeline the moment the
authorization surface drifts between releases.

**Highlights:**
- Authorization matrix as code — reviewed and versioned like the rest of your app.
- Automatic positive + negative test generation (object-level and function-level).
- Findings classified as BOLA / BFLA / privilege escalation with severity.
- Drift baselines so CI fails on *changes*, not on known accepted risk.
- JSON, HTML, SARIF (code scanning) and JUnit reports; non-zero exit for gating.
- Scaffold resources straight from OpenAPI or a HAR capture.
