"""The claims the README makes *about the code*, asserted against the code.

Most of the README is prose, and prose cannot be tested. Two parts of it are not
prose: the command reference is a list of subcommands the CLI either has or does
not, and the maturity markers are a closed vocabulary that only means something
while every use is one of the three defined words. Both rot silently — a renamed
subcommand leaves a table entry that sends the reader to a `No such command`, and
an invented fourth marker ("mostly done") turns a deliberately conservative scale
back into marketing.

`test_distribution.py` already pins the version badge and the internal anchors.
This file pins what the document asserts about the tool's surface.
"""
import os
import re

from typer.main import get_command

from overstep.cli import app

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The whole scale. Adding a fourth word is a decision, not an edit, so it has to
# happen here as well as in the document.
MATURITY_MARKERS = {"implemented", "partial", "planned"}


def _readme() -> str:
    with open(os.path.join(ROOT, "README.md"), "r", encoding="utf-8") as f:
        return f.read()


def _cli_commands() -> set:
    return set(get_command(app).commands)


def _documented_commands(text: str) -> set:
    """Every `overstep <command>` named in a table cell of the README.

    Read from table rows rather than from the whole document so a command
    mentioned mid-sentence is not required to have a reference entry — the
    reference is the table, and that is what must be complete.
    """
    return set(re.findall(r"^\|\s*`overstep ([a-z-]+)[^`]*`", text, re.MULTILINE))


def test_every_documented_command_exists():
    """A reference entry for a command the CLI does not have is a dead end."""
    documented = _documented_commands(_readme())
    assert documented, "no commands found in the README tables — the regex is wrong"

    assert not documented - _cli_commands(), (
        f"README documents commands the CLI does not expose: "
        f"{sorted(documented - _cli_commands())}"
    )


def test_every_cli_command_is_documented():
    """A command nobody documents is one nobody finds."""
    missing = _cli_commands() - _documented_commands(_readme())

    assert not missing, f"CLI commands absent from the README reference: {sorted(missing)}"


def test_maturity_markers_use_the_defined_vocabulary():
    """The scale is conservative only while it is closed.

    Every status claim in the document is a bold lowercase word in a table cell,
    and nothing else in the README is written that way — bold is otherwise used on
    sentence-leading phrases and on capitalised names. So the check is the whole
    document rather than the rows that already look right: scoping it to rows
    containing a known marker would pass a row whose only marker was replaced by
    an invented one, which is the exact edit worth catching.
    """
    used = set()
    for line in _readme().splitlines():
        if line.startswith("|"):
            used.update(re.findall(r"\*\*([a-z][a-z -]*)\*\*", line))

    assert MATURITY_MARKERS <= used, (
        f"markers missing from the README entirely: {sorted(MATURITY_MARKERS - used)}"
    )
    assert used <= MATURITY_MARKERS, (
        f"README uses maturity markers outside the defined scale: "
        f"{sorted(used - MATURITY_MARKERS)}"
    )


def test_the_scale_is_defined_before_it_is_used():
    """A marker is only conservative if the document says what it costs to claim.

    The tables above carry the markers; this is the sentence that gives them their
    meaning. Asserted separately because it is prose rather than a table row, so
    the scan above cannot see it — and a scale whose definition drifts from the
    words in use is worse than one with no definition at all.
    """
    text = _readme()
    match = re.search(r"(?m)^Conservative markers: (.+?)(?=\n\n)", text, re.DOTALL)
    assert match, "the README no longer defines its maturity scale"

    defined = set(re.findall(r"\*\*([a-z][a-z -]*)\*\*", match.group(1)))
    assert defined == MATURITY_MARKERS, (
        f"the defined scale is {sorted(defined)}, the vocabulary is "
        f"{sorted(MATURITY_MARKERS)}"
    )


def test_the_readme_describes_delegation_testing_accurately():
    """Inverted rather than deleted, like the token-passthrough one before it.

    The README used to describe delegation chains and scope attenuation only to
    explain why MCP is the hard case, which put the vocabulary a few lines from
    the feature list while nothing in `overstep` tested either — so this held
    both on the roadmap. One hop of a declared chain is tested now, so the test
    turns around: the capability is in the maturity table, the roadmap carries
    only the part that is still missing, and the non-goal says which is which.

    What is guarded has not changed. What the document claims about delegation
    has to match what the code does, in whichever direction that currently cuts.
    """
    text = _readme()
    roadmap = text.split("## Roadmap", 1)
    assert len(roadmap) == 2, "the README has no Roadmap section"

    row = next(
        (
            line
            for line in text.splitlines()
            if line.startswith("| Delegation-chain and scope-attenuation testing")
        ),
        None,
    )
    assert row, "the maturity table does not list delegation testing"
    assert "**implemented**" in row, (
        "delegation testing is in the table without an implemented marker"
    )
    assert "opt-in" in row, "the row does not say the capability has to be asked for"

    # The hop that is still not tested stays on the roadmap, and stays planned.
    hop = next(
        (line for line in roadmap[1].splitlines() if line.startswith("| Re-checking")),
        None,
    )
    assert hop, "the un-tested downstream hop left the roadmap"
    assert "**planned**" in hop, "the remaining hop is on the roadmap without a marker"

    # And the non-goal says one hop, not all of them.
    assert "one hop of a delegation chain, not all of them" in " ".join(text.split()), (
        "the non-goal no longer distinguishes the hop that is tested from the one "
        "that is not"
    )


def test_the_readme_describes_upstream_credential_forwarding_accurately():
    """A claim that was once an overclaim, now held to the other direction.

    The section explaining why an MCP engagement needs the API behind the server
    was lifted from a change proposal, where its second item referred *forward*
    to a probe that had not been built. Moved into the README, that forward
    reference became a present-tense claim: that the conformance probes ask
    whether the server leaks the caller's credential upstream. Nothing did, so a
    server that leaked passed every check there was, and the maturity table
    could not catch it because the claim was in prose.

    The probe exists now, which is why this test is inverted rather than
    deleted. The capability is off the roadmap and in the maturity table, and
    the paragraph points at the probe instead of disclaiming it. What is being
    guarded has not changed: what the document says about upstream forwarding
    has to match what the code does, in whichever direction that currently cuts.
    """
    text = _readme()
    roadmap = text.split("## Roadmap", 1)
    assert len(roadmap) == 2, "the README has no Roadmap section"

    assert "Token-passthrough" not in roadmap[1], (
        "token passthrough is implemented but still listed on the roadmap"
    )

    row = next(
        (
            line
            for line in text.splitlines()
            if line.startswith("| Token-passthrough conformance probe")
        ),
        None,
    )
    assert row, "the maturity table does not list the token-passthrough probe"
    assert "**implemented**" in row, (
        "the token-passthrough probe is in the table without an implemented marker"
    )
    assert "canary" in row, (
        "the row does not state the limit: the probe needs an endpoint you run"
    )

    assert "token-passthrough probe](#the-mcp-protocol-probes)" in text, (
        "the blast-radius paragraph no longer points at the probe that answers it"
    )
