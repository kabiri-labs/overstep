"""No document a run writes carries a credential. Asserted over the documents.

Every other guard in this suite checks one path: `test_repro.py` checks the
masking functions, `test_mcp_delegation.py` checks the credential that probe
mints, `test_run_output.py` checks the terminal. Each was written after a leak
reached review, and there have been four:

* a `client_secret` the open-registration probe caused the authorization server
  to mint, which did not exist when the run started;
* a credential sitting in `evidence.matched_markers`, a field the masking did
  not look at, beside a body where it had been replaced;
* a password inside a URL — `--proxy`, `base_url`, a server `url` — which was
  never a *value* the run was told about, so there was nothing to recognise;
* and a delegated token, where the subject carrying it had its own credential in
  a header the validator did not check.

Four leaks, one cause: `credential_values` collects what the matrix *declared*,
and every one of these arrived another way. So this module does not ask whether
a particular function masks a particular field. It takes the documents a run
actually writes and asks of each one: is anything in here a credential?

Two questions, because they fail differently. The first names the credentials
this run holds — declared, inside a URL, or minted mid-run — and asserts none of
them appears anywhere. The second knows no values at all: it reads the documents
looking for the *shape* of a credential, which is what catches the leak nobody
thought to name.
"""
import json
import os
import re

import pytest

from overstep.classifier import classify
from overstep.matrix import Matrix
from overstep.models import Effect, Observation, ResourceType, TestCase, Variant
from overstep.pipeline import run_pipeline, write_reports

# Distinctive enough that a match is never a coincidence, and shaped like the
# real thing so nothing masks them for the wrong reason.
DECLARED = "ovst-declared-subject-token-aaaa"
IN_THE_URL = "ovst-password-inside-a-url-bbbb"
MINTED = "ovst-minted-during-the-run-cccc"

SENTINELS = (DECLARED, IN_THE_URL, MINTED)


def _matrix() -> Matrix:
    """One subject with a declared token, against a base URL carrying another."""
    return Matrix(
        modules={"rest": {"base_url": f"https://u:{IN_THE_URL}@api.test"}},
        roles=["user", "admin"],
        subjects=[
            {"name": "alice", "role": "user", "token": DECLARED,
             "marker": "alice@corp", "attributes": {"user_id": "u1"}},
            {"name": "bob", "role": "user", "token": "ovst-bobs-token-dddd",
             "marker": "bob@corp", "attributes": {"user_id": "u2"}},
        ],
        resources=[{
            "name": "get_user",
            "request": {"method": "GET", "path": "/users/{id}"},
            "type": "object", "owner": "id", "owner_attr": "user_id",
        }],
        policy={"get_user": {"allow": [{"role": "user", "scope": "own"}]}},
    )


def _leaky_executor(base_url, subjects, cases, **kwargs):
    """A target that answers everything, and echoes back what it was given.

    The echo is the shape that has caught this out before: a debug route, a
    session endpoint, an error quoting the header it could not parse. Every
    field a target writes carries a sentinel, because the leak has been in a
    different one each time.
    """
    out = []
    for case in cases:
        out.append(Observation(
            test_id=case.id,
            status=200,
            effect=Effect.ALLOW,
            headers={"X-Echo-Token": f"Bearer {DECLARED}", "Content-Type": "application/json"},
            body_snippet=json.dumps({
                "you_sent": DECLARED,
                "through": f"https://u:{IN_THE_URL}@api.test",
                "we_minted": MINTED,
                "email": "bob@corp",
            }),
            full_body=json.dumps({"you_sent": DECLARED, "we_minted": MINTED}),
            error=f"could not parse Authorization: Bearer {DECLARED}",
            matched_markers=["bob@corp"],
        ))
    return out


@pytest.fixture
def written(tmp_path):
    """Every document one run writes, as text, keyed by filename.

    Driven through `run_pipeline` rather than by calling the writers directly:
    the sanitizing happens in the pipeline, so a test that skipped it would be
    asserting against a path no run takes.
    """
    matrix = _matrix()
    # A credential the run obtained rather than one the matrix declared. The
    # real grants — a client registration, a token exchange — write it onto the
    # subject during `authenticate`, which is before anything is classified, so
    # that is where this goes too. Installed by hand because `auth` would reach
    # the network.
    next(s for s in matrix.subjects if s.name == "bob").token = MINTED

    result = run_pipeline(matrix, executor=_leaky_executor)
    result.source = "matrix.yaml"

    out = tmp_path / "out"
    write_reports(result, str(out))
    return {
        path.name: path.read_text(encoding="utf-8", errors="replace")
        for path in sorted(out.iterdir())
        if path.is_file()
    }


def test_a_run_writes_the_documents_this_module_is_about(written):
    """Otherwise every assertion below passes by having nothing to read."""
    assert set(written) == {
        "findings.json", "junit.xml", "overstep.sarif", "report.html"
    }, sorted(written)
    assert all(text.strip() for text in written.values())


@pytest.mark.parametrize("secret", SENTINELS)
@pytest.mark.parametrize("name", ["findings.json", "junit.xml", "overstep.sarif", "report.html"])
def test_no_document_carries_a_credential_this_run_held(written, name, secret):
    """Declared, inside a URL, or minted mid-run — all three, in every document.

    Parametrized over the cross product rather than searched as one blob, so a
    failure names which document and which kind of credential, which is the
    difference between a one-line fix and an afternoon.
    """
    assert secret not in written[name]


def test_the_evidence_a_finding_needs_is_still_there(written):
    """The other half, and the reason this is not just a `grep -v` of everything.

    Masking that took the evidence with it would pass every assertion above and
    leave the reports useless. The victim's marker is what makes a finding
    confirmed rather than suspected, and it has to survive.
    """
    findings = json.loads(written["findings.json"])["findings"]

    assert findings, "the run produced no findings, so nothing was masked either"
    assert any(f["confidence"] == "confirmed" for f in findings)
    assert "bob@corp" in written["findings.json"], "the marker is the proof"


# --- the net: shapes, not values ---------------------------------------------
#
# The tests above know what to look for. The leak that reaches review is the one
# nobody named, so these read the documents knowing no values at all.

# `scheme://user:password@host`. The thing the URL-userinfo leak was. The two
# stand-ins `safe_url` leaves behind are excluded, because `https://***@host`
# and `https://$OVERSTEP_URL_CREDENTIALS@host` are the fix rather than the leak.
USERINFO = re.compile(
    r"[a-z][a-z0-9+.-]*://(?!\*\*\*@)(?!\$OVERSTEP_)[^/\s\"'<>@]*:"
    r"(?!\*\*\*@)[^/\s\"'<>@]+@"
)

# A credential presented inline. Anything after the scheme word that is not the
# mask or one of the shell variables the repro deliberately emits.
BEARER = re.compile(r"(?i)\b(?:bearer|basic|token)\s+(?!\*\*\*)(?!\$OVERSTEP_)([^\s\"'<>,}]{8,})")

# A field whose own name says what it holds, with something in it.
NAMED_SECRET = re.compile(
    r"(?i)\b(client_secret|password|api[_-]?key|access_token|refresh_token|subject_token)"
    # The closing quote of a JSON key sits between the name and the colon.
    r"[\"']?\s*[=:]\s*[\"']?(?!\*\*\*)(?!\$OVERSTEP_)(?!null)([^\s\"',}&]{8,})"
)


@pytest.mark.parametrize("name", ["findings.json", "junit.xml", "overstep.sarif", "report.html"])
def test_no_document_contains_a_url_with_credentials_in_it(written, name):
    """Nothing overstep writes ever legitimately needs userinfo in a URL.

    Which is what makes this checkable without knowing a single value: the host
    is the part a reader needs, and `repro.safe_url` keeps it.
    """
    found = USERINFO.findall(written[name])

    assert not found, f"{name} carries a URL with credentials: {found[:3]}"


@pytest.mark.parametrize("name", ["findings.json", "junit.xml", "overstep.sarif", "report.html"])
def test_no_document_presents_an_unmasked_credential_inline(written, name):
    """`Bearer <something>` that is neither the mask nor a shell variable.

    The two exceptions are the two things the repro machinery emits on purpose,
    and they are spelled out rather than pattern-matched loosely so a third one
    cannot appear by accident.
    """
    found = BEARER.findall(written[name])

    assert not found, f"{name} presents a credential inline: {found[:3]}"


@pytest.mark.parametrize("name", ["findings.json", "junit.xml", "overstep.sarif", "report.html"])
def test_no_document_carries_a_field_that_says_what_it_holds(written, name):
    """`client_secret=`, `password=`, `access_token:` and friends, with a value."""
    found = NAMED_SECRET.findall(written[name])

    assert not found, f"{name} carries a named secret: {found[:3]}"


# --- the net, proved against the leaks it exists for -------------------------


@pytest.mark.parametrize("sample,pattern,why", [
    (
        'the finding\'s request went to "https://u:s3cr3t@api.test/users/u1"',
        USERINFO,
        "the URL-userinfo leak, which no declared value could have matched",
    ),
    (
        '"curl -H \\"Authorization: Bearer abc123def456\\" https://api.test"',
        BEARER,
        "a credential presented inline, which is what a repro would have carried",
    ),
    (
        '{"client_secret": "minted-by-anyone-9f2a"}',
        NAMED_SECRET,
        "the client_secret the registration probe caused to be minted",
    ),
])
def test_each_pattern_catches_the_leak_it_was_written_for(sample, pattern, why):
    """A net nobody tested is a net with a hole in it.

    Each pattern is run against the shape of an actual leak from this
    repository's history, because a regex that matches nothing passes every
    document in the suite and proves exactly nothing.
    """
    assert pattern.search(sample), why


@pytest.mark.parametrize("sample,pattern", [
    # The two stand-ins the repro emits on purpose.
    ('curl -H "Authorization: Bearer $OVERSTEP_TOKEN_ALICE" https://api.test', BEARER),
    ('"headers": {"Authorization": "Bearer ***"}', BEARER),
    ('"url": "https://***@api.test/users/u1"', USERINFO),
    ('{"client_secret": "***"}', NAMED_SECRET),
    # Ordinary content a report is full of.
    ('"test_id": "get_user::alice::other"', NAMED_SECRET),
    ('"helpUri": "https://owasp.org/API-Security/editions/2023/en/0xa1"', USERINFO),
    ('"detail": "alice (user) read another subject\'s object"', BEARER),
])
def test_no_pattern_fires_on_what_a_report_legitimately_contains(sample, pattern):
    """And a net that catches the furniture gets taken down within a week."""
    assert not pattern.search(sample), sample
