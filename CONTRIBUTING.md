# Contributing to overstep

Thanks for considering a contribution!

## Setup
- Python 3.10+
- `python -m venv .venv && . .venv/bin/activate`
- `pip install -e ".[dev]"`

## Dev loop
- `pytest -q`
- `python -m uvicorn examples.mock_api.server:app --port 8000`
- `overstep run examples/mock_api/matrix.yaml --out out`

## Project layout
- `overstep/matrix.py` — the matrix model, loading and validation.
- `overstep/planner.py` — matrix → positive/negative test cases.
- `overstep/executor.py` — fire requests, record observations.
- `overstep/classifier.py` — observations → classified findings.
- `overstep/drift.py` — snapshot + baseline comparison.
- `overstep/report/` — JSON / HTML / SARIF / JUnit reporters.

## Coding standards
- Keep it simple and composable; the planner/executor/classifier split should
  stay clean (generation, transport and judgement are separate concerns).
- No network-aggressive defaults. Respect `--concurrency`.
- Keep the expression evaluator **safe** — if you add an AST node or operator,
  add tests that also prove the dangerous cases are still rejected.
- New finding types or classification rules need tests in `tests/`.

## Pull Requests
- Open an issue first for significant design/feature changes.
- Include tests for new behaviour.
- Update the README and CHANGELOG.

## Release checklist (maintainers)
- Bump the version in `pyproject.toml` and `overstep/__init__.py`.
- Update the CHANGELOG.
- Tag: `git tag vX.Y.Z && git push origin vX.Y.Z`.
- Create a GitHub Release with notes and screenshots.
