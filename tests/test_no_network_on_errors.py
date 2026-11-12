"""A matrix with an error in it sends nothing: not a case, not a login, not a setup step.

``run`` used to print the errors and carry on. For an untouched scaffold that
meant every generated request - POST, PATCH and DELETE included - went out with
placeholder credentials to the address the scaffold had guessed, which is a
port something unrelated may well be listening on.

Every test here counts requests at the one place all of them pass through,
httpx's ``send``, on both the sync client (auth providers, setup steps) and the
async one (the transports). The count is proven able to see a request before it
is trusted to see none.
"""
import json

import httpx
import pytest
import yaml
from typer.testing import CliRunner

from overstep.cli import app
from overstep.modules.rest.openapi import BASE_URL_PLACEHOLDER, scaffold_matrix

# No `servers`, and writes as well as reads: the document from the evaluation.
SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "orders", "version": "1"},
    "paths": {
        "/orders": {"post": {"responses": {"201": {"description": "created"}}}},
        "/orders/{id}": {
            "get": {"responses": {"200": {"description": "ok"}}},
            "patch": {"responses": {"200": {"description": "ok"}}},
            "delete": {"responses": {"204": {"description": "gone"}}},
        },
    },
}

CLEAN_MATRIX = """\
modules: { rest: { base_url: "http://127.0.0.1:1" } }
roles: [user]
subjects:
  - { name: alice, role: user, token: t }
resources:
  - { name: r, request: { method: GET, path: /x } }
policy:
  r: { allow: [{ role: user }] }
"""

# Valid in every respect but one unknown policy reference, and it has both of
# the things that reach the network before the first case does.
LOGIN_AND_SETUP_MATRIX = """\
modules: { rest: { base_url: "http://127.0.0.1:1" } }
roles: [user]
auth:
  providers:
    - name: login
      type: http
      request: { method: POST, path: /auth/login, body: { email: "{{email}}" } }
      token_path: "$.token"
subjects:
  - name: alice
    role: user
    auth: { provider: login, vars: { email: alice@shop.test } }
setup:
  - name: create order
    run_as: alice
    request: { method: POST, path: /orders }
resources:
  - { name: r, request: { method: GET, path: /x } }
policy:
  r: { allow: [{ role: user }] }
  no_such_resource: { allow: [{ role: user }] }
"""


@pytest.fixture
def sent(monkeypatch):
    """Every request httpx is asked to send, none of which leaves the process."""
    requests = []

    def refuse(request):
        requests.append(f"{request.method} {request.url}")
        raise httpx.ConnectError("blocked by the test", request=request)

    def sync_send(self, request, **kwargs):
        refuse(request)

    async def async_send(self, request, **kwargs):
        refuse(request)

    monkeypatch.setattr(httpx.Client, "send", sync_send)
    monkeypatch.setattr(httpx.AsyncClient, "send", async_send)
    return requests


@pytest.fixture
def scaffolded(tmp_path):
    """`overstep scaffold openapi.json --with-policy > matrix.yaml`, unedited."""
    spec = tmp_path / "openapi.json"
    spec.write_text(json.dumps(SPEC), encoding="utf-8")
    result = CliRunner().invoke(app, ["scaffold", str(spec), "--with-policy"])
    assert result.exit_code == 0
    matrix = tmp_path / "matrix.yaml"
    matrix.write_text(result.stdout, encoding="utf-8")
    return matrix


def _write(tmp_path, text):
    path = tmp_path / "matrix.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_the_request_counter_can_see_a_request(tmp_path, sent):
    """The control: a clean matrix does send, so an empty list below means something."""
    CliRunner().invoke(
        app, ["run", str(_write(tmp_path, CLEAN_MATRIX)), "--out", str(tmp_path / "out")]
    )

    assert sent == ["GET http://127.0.0.1:1/x"]


def test_run_on_an_untouched_scaffold_sends_nothing(scaffolded, tmp_path, sent):
    out = tmp_path / "out"
    result = CliRunner().invoke(app, ["run", str(scaffolded), "--out", str(out)])

    assert result.exit_code == 2
    assert sent == []
    assert "no request was sent" in result.stdout
    assert not out.exists(), "a refused run has no result to write"


def test_allow_inconclusive_does_not_send_a_broken_matrix_either(scaffolded, tmp_path, sent):
    """That flag is for a run that happened and proved nothing. This one must not happen."""
    result = CliRunner().invoke(
        app,
        ["run", str(scaffolded), "--out", str(tmp_path / "out"), "--allow-inconclusive"],
    )

    assert result.exit_code == 2
    assert sent == []


def test_snapshot_on_an_untouched_scaffold_sends_nothing(scaffolded, tmp_path, sent):
    baseline = tmp_path / "baseline.json"
    result = CliRunner().invoke(app, ["snapshot", str(scaffolded), "--out", str(baseline)])

    assert result.exit_code == 2
    assert sent == []
    assert not baseline.exists()


def test_validate_live_does_not_probe_a_matrix_with_errors(scaffolded, sent):
    result = CliRunner().invoke(app, ["validate", str(scaffolded), "--live"])

    assert result.exit_code == 1
    assert sent == []
    assert "--live sent nothing" in result.stdout


def test_validate_live_still_probes_a_clean_matrix(tmp_path, sent):
    """The other direction: the guard must not turn --live into a no-op."""
    CliRunner().invoke(app, ["validate", str(_write(tmp_path, CLEAN_MATRIX)), "--live"])

    assert sent == ["GET http://127.0.0.1:1/x"]


@pytest.mark.parametrize("command", ["run", "snapshot"])
def test_neither_login_nor_setup_runs_ahead_of_the_refusal(command, tmp_path, sent):
    """Auth providers and setup steps are requests too, and they go first."""
    matrix = _write(tmp_path, LOGIN_AND_SETUP_MATRIX)
    result = CliRunner().invoke(app, [command, str(matrix), "--out", str(tmp_path / "o")])

    assert result.exit_code == 2
    assert sent == []
    assert "no_such_resource" in result.stdout


# --- the scaffold's base URL ------------------------------------------------


def test_a_spec_without_servers_gets_a_placeholder_not_a_guess(scaffolded):
    document = yaml.safe_load(scaffolded.read_text(encoding="utf-8"))

    assert document["modules"]["rest"]["base_url"] == BASE_URL_PLACEHOLDER
    assert "localhost" not in scaffolded.read_text(encoding="utf-8")


def test_validate_names_the_base_url_placeholder_and_what_it_needs(scaffolded):
    result = CliRunner().invoke(app, ["validate", str(scaffolded)])
    flat = " ".join(result.stdout.split())

    assert result.exit_code == 1
    assert f"modules.rest.base_url is still the scaffold placeholder '{BASE_URL_PLACEHOLDER}'" in flat
    assert "named no server" in flat


def test_a_declared_server_is_still_used(tmp_path):
    spec = tmp_path / "openapi.json"
    spec.write_text(
        json.dumps({**SPEC, "servers": [{"url": "https://api.shop.test/v1"}]}),
        encoding="utf-8",
    )
    document = yaml.safe_load(scaffold_matrix(str(spec)))

    assert document["modules"]["rest"]["base_url"] == "https://api.shop.test/v1"


# --- an explicit --base stands in for the file's placeholder -----------------


@pytest.fixture
def filled_but_for_the_base_url(scaffolded):
    """Credentials and object ids filled in; the address left for the command line."""
    import re

    text = scaffolded.read_text(encoding="utf-8")
    text = re.sub(r"PASTE_(\w+)_TOKEN", lambda m: f"token-{m.group(1).lower()}", text)
    # Every identifier placeholder, suffixed or bare, and not the base URL's.
    text = re.sub(r"REPLACE_ME(?!_BASE_URL)(\w*)", lambda m: f"u{m.group(1) or '_admin'}", text)
    # The scaffold's header comment mentions the token placeholder by name, so
    # the check is on values rather than on the text.
    assert BASE_URL_PLACEHOLDER in text and "token: PASTE_" not in text
    scaffolded.write_text(text, encoding="utf-8")
    return scaffolded


@pytest.mark.parametrize("command", ["run", "snapshot"])
def test_base_overrides_a_placeholder_base_url(command, filled_but_for_the_base_url, tmp_path, sent):
    result = CliRunner().invoke(
        app,
        [command, str(filled_but_for_the_base_url), "--base", "http://127.0.0.1:1",
         "--out", str(tmp_path / "o")],
    )

    assert BASE_URL_PLACEHOLDER not in result.stdout
    assert sent, "the override names a real address, so the run goes ahead"
    assert all("http://127.0.0.1:1/" in request for request in sent)
    assert result.exit_code != 2


def test_validate_live_with_base_probes_past_a_placeholder_base_url(
    filled_but_for_the_base_url, sent
):
    CliRunner().invoke(
        app, ["validate", str(filled_but_for_the_base_url), "--live", "--base", "http://127.0.0.1:1"]
    )

    assert sent and all("http://127.0.0.1:1/" in request for request in sent)


def test_without_base_the_placeholder_base_url_still_refuses(filled_but_for_the_base_url, tmp_path, sent):
    result = CliRunner().invoke(
        app, ["run", str(filled_but_for_the_base_url), "--out", str(tmp_path / "o")]
    )

    assert result.exit_code == 2
    assert sent == []
    assert BASE_URL_PLACEHOLDER in result.stdout


def test_base_excuses_only_the_base_url(scaffolded, tmp_path, sent):
    """Nothing on the command line stands in for a credential."""
    result = CliRunner().invoke(
        app,
        ["run", str(scaffolded), "--base", "http://127.0.0.1:1", "--out", str(tmp_path / "o")],
    )

    assert result.exit_code == 2
    assert sent == []
    assert "PASTE_" in result.stdout
    assert BASE_URL_PLACEHOLDER not in result.stdout


# --- the MCP scaffold's server URL -------------------------------------------

TOOLS = {"tools": [
    {"name": "read_document", "description": "Read a document.",
     "inputSchema": {"type": "object", "properties": {"doc_id": {"type": "string"}}}},
    {"name": "reset_tenant", "description": "Admin only. Reset the tenant.",
     "inputSchema": {"type": "object", "properties": {}}},
]}


@pytest.fixture
def mcp_scaffolded(tmp_path):
    """`overstep scaffold tools.json --fmt mcp > matrix.yaml`, unedited."""
    listing = tmp_path / "tools.json"
    listing.write_text(json.dumps(TOOLS), encoding="utf-8")

    def scaffold(*flags):
        result = CliRunner().invoke(app, ["scaffold", str(listing), "--fmt", "mcp", *flags])
        assert result.exit_code == 0, result.output
        matrix = tmp_path / "matrix.yaml"
        matrix.write_text(result.stdout, encoding="utf-8")
        return matrix

    return scaffold


def test_a_saved_listing_gets_a_placeholder_server_url_not_a_guess(mcp_scaffolded):
    text = mcp_scaffolded().read_text(encoding="utf-8")
    document = yaml.safe_load(text)

    assert document["modules"]["mcp"]["servers"][0]["url"] == "REPLACE_ME_MCP_URL"
    assert "localhost" not in text


def test_validate_names_the_server_url_placeholder_and_what_it_needs(mcp_scaffolded):
    result = CliRunner().invoke(app, ["validate", str(mcp_scaffolded())])
    flat = " ".join(result.stdout.split())

    assert result.exit_code == 1
    assert "is still the scaffold placeholder 'REPLACE_ME_MCP_URL'" in flat
    assert "saved listing" in flat


def test_run_on_an_untouched_mcp_scaffold_sends_nothing(mcp_scaffolded, tmp_path, sent):
    result = CliRunner().invoke(
        app, ["run", str(mcp_scaffolded()), "--out", str(tmp_path / "out")]
    )

    assert result.exit_code == 2
    assert sent == []


def test_an_explicit_server_url_is_still_used(mcp_scaffolded):
    document = yaml.safe_load(
        mcp_scaffolded("--server-url", "https://mcp.shop.test/mcp").read_text(encoding="utf-8")
    )

    assert document["modules"]["mcp"]["servers"][0]["url"] == "https://mcp.shop.test/mcp"
