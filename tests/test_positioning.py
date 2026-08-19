"""Every place the project describes itself, held to one story.

overstep describes itself in six places: the README tagline, the PyPI summary in
`pyproject.toml`, the OCI label in the `Dockerfile`, the CLI's `--help`, the
package docstring, and `ABOUT.md`, which is the copy for the GitHub sidebar. They
are edited at different times for different reasons, and nothing connected them.

That is not hypothetical. Before this module existed the CLI's help string read
"authorization testing for HTTP APIs" and omitted MCP entirely — wrong under the
old positioning as much as the new one — while `pyproject.toml` said the opposite,
"for MCP servers; works on HTTP APIs too". Both had been that way for many
releases. A user reading `overstep --help` and a user reading the PyPI page were
being told about two different tools.

So the descriptions are pinned to each other rather than reviewed by eye: one
canonical sentence appears verbatim in the three long-form surfaces, and the
short forms must at least name both surfaces the tool covers.
"""
import os
import re

import pytest

# A sibling module, not `tests.test_distribution`: `tests/` has no __init__.py,
# so pytest puts that directory on sys.path rather than the repository root, and
# the dotted form resolves only when the root happens to be there too — which is
# true under `python -m pytest` and false under the bare `pytest` CI runs.
from test_distribution import toml_strings

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The sentence the packaging surfaces publish. Written here rather than read from
# one of them, so that changing it is a deliberate edit to a test and not a
# silent drift in whichever file happened to be touched first.
CANONICAL = (
    "Authorization testing for REST APIs and MCP servers. Declare who may do "
    "what as a matrix, and overstep turns it into positive and negative tests "
    "that catch BOLA, BFLA, BOPLA and privilege escalation — with drift "
    "baselines, confidence grading and CWE/OWASP-tagged SARIF for CI."
)

# GitHub truncates a repository description past this, and the PyPI summary is a
# single line in a card. A sentence nobody can read to the end describes nothing.
MAX_DESCRIPTION = 350

# The tool tests a server's enforcement. It does not drive an agent, and the
# README says so under its own heading — so no self-description may imply
# otherwise, however good the phrase looks in a keyword list.
FORBIDDEN_CLAIMS = ("agent-security", "ai-security", "llm-security", "ai security", "llm security")


def _read(rel: str) -> str:
    with open(os.path.join(ROOT, rel), "r", encoding="utf-8") as handle:
        return handle.read()


def _pyproject_description() -> str:
    match = re.search(r'(?m)^description = "(.+)"$', _read("pyproject.toml"))
    assert match, "pyproject.toml has no description"
    return match.group(1)


def _docker_description() -> str:
    match = re.search(
        r'org\.opencontainers\.image\.description="(.+?)"', _read("Dockerfile"), re.DOTALL
    )
    assert match, "the Dockerfile has no image description label"
    return match.group(1)


def _about_repo_description() -> str:
    """The `**About (repo description):**` paragraph of ABOUT.md, unwrapped."""
    match = re.search(
        r"\*\*About \(repo description\):\*\*\n(.+?)\n\n", _read("ABOUT.md"), re.DOTALL
    )
    assert match, "ABOUT.md has no repo-description block"
    return " ".join(match.group(1).split())


def _cli_help() -> str:
    from overstep.cli import app

    return app.info.help


def _readme_tagline() -> str:
    match = re.search(r"(?m)^\*\*(.+?)\*\*$", _read("README.md"))
    assert match, "the README has no bold tagline under its title"
    return match.group(1)


def _package_docstring() -> str:
    import overstep

    return overstep.__doc__


LONG_FORM = {
    "pyproject.toml": _pyproject_description,
    "Dockerfile": _docker_description,
    "ABOUT.md": _about_repo_description,
}

SHORT_FORM = {
    "README tagline": _readme_tagline,
    "CLI --help": _cli_help,
    "package docstring": _package_docstring,
}


@pytest.mark.parametrize("surface", sorted(LONG_FORM))
def test_the_long_form_surfaces_carry_the_canonical_sentence(surface):
    """One sentence, three files, no paraphrases.

    Equality rather than a keyword check: a paraphrase is exactly how these three
    drifted apart in the first place, and each is read by someone who will never
    see the other two.
    """
    assert LONG_FORM[surface]() == CANONICAL, (
        f"{surface} no longer matches the canonical description; update all "
        f"three surfaces and CANONICAL together"
    )


def test_the_canonical_sentence_fits_where_it_is_published():
    """GitHub truncates past 350 characters, and a truncated sentence misinforms."""
    assert len(CANONICAL) <= MAX_DESCRIPTION, (
        f"the description is {len(CANONICAL)} characters; GitHub shows "
        f"{MAX_DESCRIPTION}"
    )


@pytest.mark.parametrize("surface", sorted(SHORT_FORM))
def test_every_short_form_surface_names_both_modules(surface):
    """The specific bug this module was written for.

    A description that names one surface tells half the users the tool is not for
    them. The check is deliberately loose about wording — REST may be called REST
    or HTTP — and strict about neither being absent.
    """
    text = SHORT_FORM[surface]().lower()

    assert "rest" in text or "http" in text, f"{surface} does not name the REST surface"
    assert "mcp" in text, f"{surface} does not name the MCP surface"


@pytest.mark.parametrize("surface", sorted(LONG_FORM) + sorted(SHORT_FORM))
def test_no_surface_claims_to_be_an_ai_security_tool(surface):
    """A non-goal stated in the README is not a non-goal if the metadata sells it.

    `agent-security` sat in the pyproject keywords while the README explained at
    length that this is not what the tool does. A keyword is a claim; PyPI search
    and GitHub topics are where most people meet a project.
    """
    getter = dict(LONG_FORM, **SHORT_FORM)[surface]
    text = getter().lower()

    for claim in FORBIDDEN_CLAIMS:
        assert claim not in text, f"{surface} claims '{claim}', which the README rules out"


def test_the_packaging_keywords_stay_off_the_non_goal():
    """Same rule, applied to the keyword list rather than to prose."""
    keywords = toml_strings(_read("pyproject.toml"), "keywords")
    assert keywords, "pyproject.toml has no keywords"

    offending = [k for k in keywords if k.lower() in FORBIDDEN_CLAIMS]
    assert not offending, f"pyproject keywords claim {offending}, which the README rules out"


def test_the_keywords_name_both_modules():
    """A REST user searching PyPI has to be able to find this."""
    keywords = {k.lower() for k in toml_strings(_read("pyproject.toml"), "keywords")}

    assert keywords & {"rest", "rest-api", "api-security"}, "no keyword names the REST surface"
    assert keywords & {"mcp", "model-context-protocol"}, "no keyword names the MCP surface"
