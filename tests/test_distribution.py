"""Tests for the CI distribution artifacts (Docker, GitHub Action, pre-commit).

These files are how a DevSecOps team actually adopts the tool, so their shape is
part of the contract: the Action must expose the inputs the docs promise and run
the CLI; the pre-commit hook must call a real subcommand; the Dockerfile must
install the package and default to the entrypoint. The version a user sees is
part of that contract too, so the three places it is published — the package,
the wheel metadata and the README badge — are asserted to agree.
"""
import os
import re

import pytest

import yaml

from overstep import __version__

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(rel: str) -> str:
    with open(os.path.join(ROOT, rel), "r", encoding="utf-8") as f:
        return f.read()


def test_dockerfile_installs_package_and_sets_entrypoint():
    df = _read("Dockerfile")
    assert "pip install" in df
    # The image must expose the overstep CLI as its entrypoint.
    assert 'ENTRYPOINT ["overstep"]' in df


def test_action_yml_declares_matrix_input_and_runs():
    action = yaml.safe_load(_read("action.yml"))
    assert action["name"]
    assert "matrix" in action["inputs"]
    assert action["inputs"]["matrix"]["required"] is True
    # Composite action so it runs on any GitHub-hosted runner.
    assert action["runs"]["using"] == "composite"
    steps = action["runs"]["steps"]
    assert any("overstep run" in (s.get("run") or "") for s in steps)


def test_action_exposes_documented_inputs():
    action = yaml.safe_load(_read("action.yml"))
    for name in (
        "matrix", "base-url", "out", "fail-on", "waivers", "baseline",
        "read-only", "env-file", "concurrency", "max-retries",
        "allow-inconclusive", "version",
    ):
        assert name in action["inputs"], f"action.yml missing input {name}"


def test_every_action_input_reaches_the_cli():
    """An input nobody passes on is a lie in the interface — it silently does
    nothing. Every optional input must appear in the step that builds the argv."""
    action = yaml.safe_load(_read("action.yml"))
    run_step = next(
        s for s in action["runs"]["steps"] if "overstep run" in (s.get("run") or "")
    )
    for name in action["inputs"]:
        if name == "version":  # consumed by the install step, not the run step
            continue
        assert f"inputs.{name}" in run_step["run"], f"action.yml input {name} is never used"


def test_precommit_hooks_call_validate():
    hooks = yaml.safe_load(_read(".pre-commit-hooks.yaml"))
    assert isinstance(hooks, list) and hooks
    ids = {h["id"] for h in hooks}
    assert "overstep-validate" in ids
    validate = next(h for h in hooks if h["id"] == "overstep-validate")
    assert "validate" in validate["entry"]


def test_dockerignore_excludes_git():
    di = _read(".dockerignore")
    assert ".git" in di


def toml_strings(document: str, name: str) -> list:
    """Read a TOML array of strings without tomllib, which is Python 3.11+.

    Scans character by character tracking whether it is inside a quoted string,
    because both obvious shortcuts are wrong for real dependency specifiers:
    splitting on commas breaks ``urllib3>=1.26,<3``, and stopping at the first
    ``]`` breaks ``pydantic[email]>=2.6``. Getting this wrong would fail the
    sync check on a perfectly valid dependency and block CI.
    """
    start = re.search(rf'(?m)^{name}\s*=\s*\[', document)
    assert start, f"no {name} array found"

    items: list = []
    buffer: list = []
    in_string = False
    for char in document[start.end():]:
        if char == '"':
            if in_string:
                items.append("".join(buffer))
                buffer = []
            in_string = not in_string
        elif in_string:
            buffer.append(char)
        elif char == "]":
            return items
    raise AssertionError(f"unterminated {name} array")


def _pyproject_list(name: str) -> list:
    return toml_strings(_read("pyproject.toml"), name)


def test_requirements_txt_matches_pyproject():
    """requirements.txt is a second source of truth — CI installs from it, while
    the package installs from pyproject. Nothing but this test stops a dependency
    added to one from silently missing in the other."""
    declared = set(_pyproject_list("dependencies")) | set(_pyproject_list("dev"))
    pinned = {
        line.strip()
        for line in _read("requirements.txt").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }

    assert declared == pinned, (
        f"requirements.txt and pyproject.toml disagree; "
        f"missing from requirements.txt: {sorted(declared - pinned)}, "
        f"absent from pyproject: {sorted(pinned - declared)}"
    )


def test_pyproject_version_matches_package_version():
    # Parsed with a regex rather than tomllib so the test still runs on 3.10.
    match = re.search(r'(?m)^version\s*=\s*"([^"]+)"', _read("pyproject.toml"))
    assert match, "pyproject.toml has no version"
    assert match.group(1) == __version__, (
        f"pyproject.toml says {match.group(1)}, __version__ says {__version__}"
    )


def test_readme_version_badge_matches_package_version():
    match = re.search(
        r"!\[Version\]\(https://img\.shields\.io/badge/version-([0-9]+\.[0-9]+\.[0-9]+)-",
        _read("README.md"),
    )
    assert match, "README.md has no version badge"
    assert match.group(1) == __version__, (
        f"README badge says {match.group(1)}, __version__ says {__version__}"
    )


def _github_slug(heading: str) -> str:
    """GitHub's anchor for a heading.

    Each space becomes a hyphen individually rather than each *run* of
    whitespace, which is why `Credentials: dynamic tokens & secrets` anchors as
    `...tokens--secrets` — the removed `&` leaves two spaces behind and therefore
    two hyphens. Collapsing them reports a working link as broken.
    """
    slug = heading.strip().lower()
    slug = re.sub(r"[`*]", "", slug)
    slug = re.sub(r"[^\w\s-]", "", slug)
    return slug.replace(" ", "-")


def _markdown_headings(text: str) -> set:
    """Heading slugs, ignoring anything inside a fenced code block.

    A shell comment is spelled exactly like a heading, and this README has
    several — `# once, after triaging findings`, `# 1. start the demo server`.
    GitHub creates no anchor for them, so counting them would let a link resolve
    against a code comment: rename a real section while a fence keeps the old
    wording, and the check that exists to catch that would pass.
    """
    headings = set()
    in_fence = False
    for line in text.splitlines():
        if line.lstrip().startswith(("```", "~~~")):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        match = re.match(r"^#{1,6}\s+(.*)$", line)
        if match:
            headings.add(_github_slug(match.group(1)))
    return headings


def test_every_readme_cross_reference_resolves():
    """The README routes the reader by anchor, and a dead one is a dead end.

    It is long enough that sections get renamed without the links that point at
    them being noticed, and nothing else in the build would say so — a broken
    `](#...)` renders as ordinary text and simply goes nowhere when clicked.
    """
    text = _read("README.md")
    headings = _markdown_headings(text)
    links = set(re.findall(r"\]\(#([^)]+)\)", text))

    assert links, "no internal links found — the regex is probably wrong"
    assert not links - headings, (
        f"README links point at headings that do not exist: {sorted(links - headings)}"
    )


def test_a_shell_comment_in_a_fence_is_not_a_heading():
    """Otherwise a link could resolve against a code comment.

    Asserted directly rather than only through the README, so the guarantee
    survives the day the README happens to contain no such comment.
    """
    document = (
        "## Real Section\n"
        "```bash\n"
        "# Fake Section\n"
        "overstep run matrix.yaml\n"
        "```\n"
        "~~~\n"
        "# Also Fake\n"
        "~~~\n"
    )

    assert _markdown_headings(document) == {"real-section"}


def test_toml_parser_keeps_a_comma_inside_a_version_specifier():
    """`urllib3>=1.26,<3` is one dependency. Splitting on commas would make it
    two, and the sync check would then fail on a perfectly valid pyproject."""
    document = 'dependencies = [\n    "httpx>=0.27",\n    "urllib3>=1.26,<3",\n]\n'

    assert toml_strings(document, "dependencies") == ["httpx>=0.27", "urllib3>=1.26,<3"]


def test_toml_parser_keeps_a_bracket_inside_an_extra():
    """`pydantic[email]` closes a bracket mid-string; stopping at the first `]`
    would truncate the array and silently drop every later dependency."""
    document = 'dependencies = [\n    "pydantic[email]>=2.6",\n    "rich>=13.7",\n]\n'

    assert toml_strings(document, "dependencies") == ["pydantic[email]>=2.6", "rich>=13.7"]


def test_toml_parser_reads_an_empty_array():
    assert toml_strings('dev = [\n]\n', "dev") == []


def test_toml_parser_stops_at_its_own_array():
    """Two arrays in one document must not bleed into each other."""
    document = 'dependencies = [\n    "httpx>=0.27",\n]\ndev = [\n    "pytest>=8.0",\n]\n'

    assert toml_strings(document, "dependencies") == ["httpx>=0.27"]
    assert toml_strings(document, "dev") == ["pytest>=8.0"]


def test_toml_parser_rejects_an_unterminated_array():
    with pytest.raises(AssertionError, match="unterminated"):
        toml_strings('dependencies = [\n    "httpx>=0.27",\n', "dependencies")
