"""Guard against running the suite with a runner that silently collects nothing.

The tests in this package are written as plain pytest functions and rely on
pytest fixtures, so `python -m unittest discover -s tests` imports every module,
finds no `TestCase`, and exits **"OK" having run zero tests** — a green result
that proves nothing. This module is the one `TestCase` in the suite, and it
fails under any runner that is not pytest, turning that false pass into an
actionable error. The canonical command is `pytest -q`.
"""
import os
import unittest


class RunnerTest(unittest.TestCase):
    def test_suite_is_run_by_pytest(self):
        # Set by pytest for the duration of each test. `pytest in sys.modules`
        # is not a substitute: unittest discovery imports the sibling modules,
        # which import pytest themselves. Checked with an explicit `fail` so a
        # failure does not spill the developer's environment into the report.
        if "PYTEST_CURRENT_TEST" not in os.environ:
            self.fail(
                "This suite must be run with pytest (`pytest -q`); unittest "
                "discovery collects none of its tests and reports a false pass."
            )
