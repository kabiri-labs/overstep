"""Tests for the release-notes builder.

The failure these exist to prevent has already happened once: `v0.31.2` was
published describing two listing fixes, because the workflow extracted the
section for the version being released and the release actually contained eleven
versions. Nothing errored — the notes were simply the wrong ones, and looked
like the right ones.
"""
import importlib.util
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "scripts", "release_notes.py")

_spec = importlib.util.spec_from_file_location("release_notes", SCRIPT)
release_notes = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(release_notes)

CHANGELOG = """# Changelog

## [0.31.2] - 2026-08-12

### Fixed
- Listings are paginated.

## [0.31.1] - 2026-08-12

### Changed
- The README leads with MCP.

## [0.31.0] - 2026-08-12

### Added
- Scaffold drafts the resource surface.

## [0.27.0] - 2026-08-11

### Added
- Each command names the next one.
"""


# --- the range ---------------------------------------------------------------

def test_a_single_version_release_is_unchanged():
    """The common case must come out exactly as the old extraction produced it."""
    notes = release_notes.extract_notes(CHANGELOG, "0.31.2", since="0.31.1")
    assert notes.strip() == "### Fixed\n- Listings are paginated."
    assert "0.31.1" not in notes


def test_a_bundled_release_covers_every_version_since_the_last_tag():
    notes = release_notes.extract_notes(CHANGELOG, "0.31.2", since="0.27.0")
    assert "Listings are paginated" in notes
    assert "The README leads with MCP" in notes
    assert "Scaffold drafts the resource surface" in notes
    # The tag it stops at is the previous release, so its own notes are not repeated.
    assert "Each command names the next one" not in notes


def test_a_bundled_release_keeps_each_version_heading():
    """Without them the reader cannot tell which change arrived when."""
    notes = release_notes.extract_notes(CHANGELOG, "0.31.2", since="0.27.0")
    assert notes.count("## 0.31.2") == 1
    assert notes.count("## 0.31.1") == 1
    assert notes.count("## 0.31.0") == 1
    assert notes.index("## 0.31.2") < notes.index("## 0.31.0")   # newest first


def test_a_first_release_takes_everything():
    notes = release_notes.extract_notes(CHANGELOG, "0.31.2", since=None)
    assert "Each command names the next one" in notes


def test_versions_newer_than_the_one_released_are_left_out():
    """Releasing 0.31.1 after 0.31.2 exists in the file must not drag it in."""
    notes = release_notes.extract_notes(CHANGELOG, "0.31.1", since="0.27.0")
    assert "Listings are paginated" not in notes
    assert "The README leads with MCP" in notes


# --- the guard ---------------------------------------------------------------

def test_a_missing_section_is_an_error_not_an_empty_page():
    """How the old extraction failed: silently, into a published release."""
    with pytest.raises(LookupError, match=r"no '## \[9\.9\.9\]' section"):
        release_notes.extract_notes(CHANGELOG, "9.9.9")


# --- picking the previous release --------------------------------------------

def test_previous_version_is_the_highest_below_the_target():
    tags = ["v0.10.0", "v0.16.0", "v0.22.2", "v0.27.0", "v0.31.2"]
    assert release_notes.previous_version(tags, "0.31.2") == "0.27.0"


def test_a_later_tag_cannot_make_the_range_run_backwards():
    """'The next tag down' would pick 0.32.0 here and produce nothing."""
    tags = ["v0.27.0", "v0.31.2", "v0.32.0"]
    assert release_notes.previous_version(tags, "0.31.2") == "0.27.0"


def test_no_earlier_tag_means_no_lower_bound():
    assert release_notes.previous_version(["v0.31.2"], "0.31.2") is None
    assert release_notes.previous_version([], "0.31.2") is None


def test_version_sorting_is_numeric_not_lexical():
    """v0.9.0 is older than v0.10.0, which string comparison gets backwards."""
    assert release_notes.previous_version(["v0.9.0", "v0.10.0"], "0.31.2") == "0.10.0"


def test_a_malformed_tag_does_not_fail_the_release():
    assert release_notes.previous_version(["v0.27.0", "vnightly", "v"], "0.31.2") == "0.27.0"


# --- the CLI, as the workflow invokes it -------------------------------------

def _run(args, stdin: str, changelog: str = CHANGELOG, tmp_path=None):
    path = tmp_path / "CHANGELOG.md"
    path.write_text(changelog, encoding="utf-8")
    return subprocess.run(
        [sys.executable, SCRIPT, "--changelog", str(path), *args],
        input=stdin, capture_output=True, text=True,
    )

def test_cli_derives_the_range_from_the_tags_on_stdin(tmp_path):
    proc = _run(["--version", "0.31.2"], "v0.27.0\nv0.31.2\n", tmp_path=tmp_path)
    assert proc.returncode == 0
    assert "The README leads with MCP" in proc.stdout      # the bundled versions
    assert "Each command names the next one" not in proc.stdout
    assert "back to 0.27.0" in proc.stderr                 # says what it covered


def test_cli_exits_non_zero_when_the_version_is_missing(tmp_path):
    proc = _run(["--version", "9.9.9"], "v0.27.0\n", tmp_path=tmp_path)
    assert proc.returncode == 1
    assert "no '## [9.9.9]' section" in proc.stderr
    assert proc.stdout == ""


def test_the_real_changelog_has_a_section_for_the_current_version():
    """The release workflow will fail on the next tag if this ever stops holding."""
    from overstep import __version__

    with open(os.path.join(ROOT, "CHANGELOG.md"), encoding="utf-8") as f:
        assert release_notes.extract_notes(f.read(), __version__).strip()
