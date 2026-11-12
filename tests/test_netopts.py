"""The run's network settings reach every connection it opens, and only that run.

``timeout=15.0`` was typed into each function that builds a client, so a target
slower than that could not be tested and nothing on the command line said
otherwise. These tests watch the clients being built, because that is the only
place the settings become real.
"""
import asyncio
import time

import httpx
import pytest
from typer.testing import CliRunner

from overstep import netopts
from overstep.cli import app
from overstep.matrix import Matrix
from overstep.modules.rest.executor import execute
from overstep.planner import plan

MATRIX = """\
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
  - { name: seed, as: alice, request: { method: POST, path: /orders } }
resources:
  - { name: r, request: { method: GET, path: /x } }
policy:
  r: { allow: [{ role: user }] }
"""


@pytest.fixture
def clients(monkeypatch):
    """Every httpx client built, by what it was built with; nothing leaves."""
    built = []

    def handler(request):
        if request.url.path == "/auth/login":
            return httpx.Response(200, json={"token": "t"})
        return httpx.Response(200, json={})

    def patch(cls):
        original = cls.__init__

        def init(self, *args, **kwargs):
            built.append({"kind": cls.__name__, **{k: kwargs.get(k) for k in ("timeout", "proxy")},
                          "has_proxy_key": "proxy" in kwargs})
            kwargs.pop("proxy", None)
            kwargs["transport"] = httpx.MockTransport(handler)
            original(self, *args, **kwargs)

        monkeypatch.setattr(cls, "__init__", init)

    patch(httpx.Client)
    patch(httpx.AsyncClient)
    return built


def _run(tmp_path, *flags, command="run"):
    path = tmp_path / "matrix.yaml"
    path.write_text(MATRIX, encoding="utf-8")
    out = tmp_path / ("out" if command == "run" else "baseline.json")
    return CliRunner().invoke(app, [command, str(path), "--out", str(out), *flags])


# --- timeout ------------------------------------------------------------------


def test_the_default_is_what_it_always_was(tmp_path, clients):
    _run(tmp_path)

    assert clients, "the control: the fixture sees clients being built"
    assert {c["timeout"] for c in clients} == {15.0}


@pytest.mark.parametrize("command", ["run", "snapshot"])
def test_timeout_reaches_login_setup_and_the_cases(command, tmp_path, clients):
    """One sync client for login, one each for setup and teardown, one async for cases."""
    result = _run(tmp_path, "--timeout", "42", command=command)

    assert result.exit_code == 0, result.output
    assert {c["kind"] for c in clients} == {"Client", "AsyncClient"}
    assert {c["timeout"] for c in clients} == {42.0}


def test_validate_live_takes_the_timeout_too(tmp_path, clients):
    path = tmp_path / "matrix.yaml"
    path.write_text(MATRIX, encoding="utf-8")
    CliRunner().invoke(app, ["validate", str(path), "--live", "--timeout", "7"])

    assert clients and {c["timeout"] for c in clients} == {7.0}


def test_the_setting_ends_with_the_command(tmp_path, clients):
    _run(tmp_path, "--timeout", "42", "--proxy", "http://127.0.0.1:9", "--delay", "0.5")

    assert netopts.current() == netopts.NetOptions()


@pytest.mark.parametrize("flags", [("--timeout", "0"), ("--timeout", "-3"), ("--delay", "-1")])
def test_a_nonsense_value_is_bad_input_and_sends_nothing(flags, tmp_path, clients):
    result = _run(tmp_path, *flags)

    assert result.exit_code == 2
    assert clients == []


# --- proxy --------------------------------------------------------------------


def test_proxy_reaches_every_client(tmp_path, clients):
    _run(tmp_path, "--proxy", "http://127.0.0.1:8080")

    assert clients and {c["proxy"] for c in clients} == {"http://127.0.0.1:8080"}


def test_without_the_flag_no_proxy_argument_is_passed_at_all(tmp_path, clients):
    """`proxy=None` would tell httpx "no proxy" and switch off HTTP_PROXY."""
    _run(tmp_path)

    assert clients and not any(c["has_proxy_key"] for c in clients)


# --- delay --------------------------------------------------------------------


def _five_cases():
    matrix = Matrix(
        modules={"rest": {"base_url": "http://api.test"}},
        roles=["user"],
        subjects=[{"name": f"s{i}", "role": "user", "token": str(i)} for i in range(5)],
        resources=[{"name": "r", "request": {"method": "GET", "path": "/x"}}],
        policy={"r": {"allow": [{"role": "user"}]}},
    )
    return matrix, plan(matrix)


def _starts(monkeypatch, **options):
    """When each request reached the wire, relative to the first."""
    stamps = []

    def handler(request):
        stamps.append(time.perf_counter())
        return httpx.Response(200, json={})

    original = httpx.AsyncClient

    def factory(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return original(*args, **kwargs)

    import overstep.modules.rest.executor as ex

    monkeypatch.setattr(ex.httpx, "AsyncClient", factory)
    matrix, cases = _five_cases()
    with netopts.using(**options):
        asyncio.run(execute("http://api.test", matrix.subjects, cases, concurrency=5))
    return [s - stamps[0] for s in stamps]


def test_delay_spaces_requests_across_the_whole_pool(monkeypatch):
    """Five slots and a 100 ms delay is still one request per 100 ms, not five.

    Asserted on the whole span and with slack on each gap: a timer on Windows
    is good to about 16 ms, and the claim is "spaced", not "spaced to the
    millisecond". Five requests released together would span almost nothing.
    """
    starts = _starts(monkeypatch, delay=0.1)

    gaps = [b - a for a, b in zip(starts, starts[1:])]
    assert len(starts) == 5
    assert starts[-1] >= 0.32, starts
    assert all(gap >= 0.06 for gap in gaps), gaps


def test_without_a_delay_the_pool_is_not_slowed(monkeypatch):
    starts = _starts(monkeypatch)

    assert len(starts) == 5
    assert starts[-1] < 0.2
