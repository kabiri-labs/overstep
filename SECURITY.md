# Security Policy

## Reporting a vulnerability in overstep

**Please do not open a public issue for a security problem.**

Report it privately through GitHub: open the
[Security tab](https://github.com/kabiri-labs/overstep/security) and use
**Report a vulnerability**. That opens a private advisory visible only to the
maintainers, where patches can be prepared and a CVE requested before anything
becomes public.

If that button is unavailable to you, open a public issue containing **only** a
request for a private channel — no details, no reproduction — and you will be
given one.

Please include, once you have a private channel:

- what an attacker can do, and what they need in order to do it;
- the affected version (`overstep version`) and Python version;
- a minimal reproduction — for this project that usually means a matrix file and
  the command you ran;
- anything you already know about a fix.

You can expect an acknowledgement within a few days and an assessment of whether
the report is accepted, with an indication of timing. Fixes are released as a new
version with the issue described in the changelog. If you would like credit,
say so and you will be named; otherwise reports stay anonymous.

## What counts as a vulnerability *in overstep*

overstep is a tool that finds authorization flaws in **other** systems. A finding
it reports about your API is a bug in your API, not in overstep — please don't
report those here.

In scope for this policy:

- **Leaking a credential.** Tokens, api keys and cookies must never reach a
  report, a log line or a repro command. `repro.py` writes a named shell variable
  in their place; anything that defeats that is a vulnerability.
- **Escaping the expression sandbox.** Policy `condition:` strings run through a
  restricted AST evaluator that permits comparisons, boolean logic and
  attribute/index access only. Any input that achieves code execution, imports,
  attribute writes or resource exhaustion through it is a vulnerability.
- **Executing untrusted input.** A matrix, an OpenAPI/HAR file, a `tools/list`
  response or a target's response body causing arbitrary code execution, a file
  write outside the report directory, or an unintended subprocess launch.
- **Reporting a clean run that never happened.** overstep is used as a CI gate,
  so any way to make it exit `0` while its probes did not actually execute is a
  security problem, not merely a bug — see the inconclusive-run check in the
  README.
- **Sending credentials to the wrong place**, for example one subject's token
  being attached to another subject's request.

Out of scope:

- Findings overstep reports about a system you scanned.
- Behaviour of the intentionally-vulnerable demos under `examples/` — they are
  broken on purpose.
- Running overstep against a system you are not authorized to test. That is your
  responsibility; the tool sends real requests, including negative authorization
  probes.

## Supported versions

Fixes land on the latest release. There are no long-term support branches, so
please upgrade to the current version before reporting — and if you cannot
upgrade, say so in your report and it will be taken into account.
