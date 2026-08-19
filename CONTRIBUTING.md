# Contributing to overstep

Thanks for considering a contribution!

## Setup
- Python 3.10+
- `python -m venv .venv && . .venv/bin/activate`
- `pip install -e ".[dev]"`

## Dev loop
- `pytest -q` — the canonical test command. The suite is written as pytest
  functions and uses pytest fixtures, so `unittest` discovery collects none of
  it; `tests/test_runner.py` fails loudly if you reach for the wrong runner.
  No test touches the network, but they do need the `dev` extras installed.
- `python -m uvicorn examples.mock_api.server:app --port 8000`
- `overstep run examples/mock_api/matrix.yaml --out out`

### Golden files

`tests/test_wire_contract.py` compares every document a run writes — findings,
SARIF, JUnit, HTML and a drift baseline — against a stored copy under
`tests/golden/`, because nothing else in the suite would notice the serialized
form moving. When a change to that form is intended:

```bash
OVERSTEP_UPDATE_GOLDEN=1 pytest tests/test_wire_contract.py   # rewrite the copies
git diff tests/golden/                                        # then read it
```

The diff is the point. It is the list of what the change breaks for anyone
consuming those documents — a committed `baseline.json`, a waivers file keyed on
`test_id`, a dashboard reading `findings.json`, a SARIF suppression. Regenerating
without reading it turns the whole module into a rubber stamp, and a change that
belongs in the CHANGELOG under a heading that says so goes out unannounced.

## Project layout

The package uses a `src/` layout, so everything below lives under `src/`.

Core path of a run — matrix in, findings out:

- `overstep/matrix.py` — the matrix model, loading and validation (`validate_refs`).
- `overstep/models.py` — every shared pydantic model (subjects, cases, findings).
- `overstep/planner.py` — matrix → positive/negative test cases.
- `overstep/executor.py` — fire HTTP requests, record observations.
- `overstep/classifier.py` — observations → classified findings.
- `overstep/health.py` — decides whether a run proved anything at all; a run that
  never reached its target must never report clean (see *Coding standards*).
- `overstep/drift.py` — snapshot + baseline comparison.
- `overstep/pipeline.py` — orchestration seam (`run_pipeline`, `snapshot_pipeline`,
  `write_reports`).
- `overstep/cli.py` — thin argument parsing / rendering over the pipeline.

Pluggable seams — add capability here, not in the core:

- `overstep/transports/` — how a case is delivered (`http`, `mcp`); register one
  with `register(...)` in `transports/base.py`.
- `overstep/report/` — output formats; add one with `@register(...)` in
  `report/base.py`.
- `overstep/loaders/` — scaffolding a matrix from OpenAPI, HAR or a live MCP
  server's `tools/list`.

Supporting:

- `overstep/auth.py`, `fixtures.py` — obtaining tokens; setup/teardown steps.
- `overstep/repro.py` — the `curl` / tool-call reproduction on each finding.
- `overstep/waivers.py`, `taxonomy.py` — accepted risk; CWE/OWASP mapping.
- `overstep/expressions.py` — the restricted evaluator behind policy conditions.

Outside the package:

- `scripts/` — repository tooling, not shipped in the wheel. `release_notes.py`
  builds a release's notes from the CHANGELOG. It lives here rather than inline
  in the workflow so it can be tested: the logic it replaced published a release
  describing the wrong versions, and nothing failed.

## Coding standards
- Keep it simple and composable; the planner/executor/classifier split should
  stay clean (generation, transport and judgement are separate concerns), and
  the CLI should stay a thin wrapper over `run_pipeline`.
- **Never fail open.** A gate that reports "no vulnerabilities" because nothing
  was actually tested is worse than no gate. If you add a way for a run to
  produce no findings, make sure `overstep.health` can still tell "clean" from
  "never ran" — and add the test that proves it.
- **Never generate a test that proves nothing.** A probe whose request is
  identical to another, or whose object nobody owns, is not coverage; drop it and
  say why in `validate`.
- No network-aggressive defaults. Respect `--concurrency`.
- Keep the expression evaluator **safe** — if you add an AST node or operator,
  add tests that also prove the dangerous cases are still rejected.
- Credentials never appear in a report. `repro.py` writes a named shell variable
  instead, so the output stays shareable *and* runnable.
- New finding types or classification rules need tests in `tests/`.

## Pull Requests
- Open an issue first for significant design/feature changes.
- Include tests for new behaviour.
- Update the README and CHANGELOG.

## Release checklist (maintainers)

Releasing is automated by [`.github/workflows/release.yml`](.github/workflows/release.yml):
it re-runs the tests, verifies the version, builds the sdist and wheel, creates
the GitHub Release, and publishes to PyPI through trusted publishing. You only
need to prepare the commit.

**Before releasing, on `main`:**

1. Bump the version in `pyproject.toml`, `src/overstep/__init__.py` **and** the
   README version badge — `tests/test_distribution.py` asserts the three agree,
   and the release fails if the package version doesn't match what you request.
2. Add a `## [X.Y.Z] - YYYY-MM-DD` section to `CHANGELOG.md`. The workflow
   extracts the release notes by matching that heading exactly, so a typo
   produces an empty release body.

**Then pick one:**

- **Manual (works when pushing tags is blocked):** Actions → Release → Run
  workflow → `version = X.Y.Z`. This creates the tag for you.
- **Tag push:** `git tag vX.Y.Z && git push origin vX.Y.Z`.

The PyPI publish runs in a dedicated `pypi` environment, so protection rules can
require an approval before anything is uploaded.
