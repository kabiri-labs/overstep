## What changes, and why

<!-- What behaviour is different after this PR, and what problem that solves.
     If it fixes a bug, say what the bug did — the symptom, not just the cause. -->

## How it was verified

<!-- What you actually ran, and what it showed. "Tests pass" on its own doesn't
     say much; the useful version names the case that would have failed before. -->

- [ ] `pytest -q` passes
- [ ] Tests added or updated for this change
- [ ] Version bumped in `pyproject.toml`, `src/overstep/__init__.py` and the
      README badge (`tests/test_distribution.py` asserts the three agree)
- [ ] `CHANGELOG.md` updated
- [ ] README updated, if behaviour a user sees has changed

## Anything a reviewer should push back on

<!-- Trade-offs you made, alternatives you rejected, parts you are unsure about.
     A PR that claims to have no trade-offs is usually hiding one. -->

<!-- If this changes the exit code, the generated test set, or the shape of a
     report, say so explicitly: those break other people's pipelines and
     baselines, and belong in the CHANGELOG under a heading that says so. -->
