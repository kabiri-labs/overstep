"""Setup steps: create fixtures and capture values before the suite runs.

Real BOLA testing needs real, owned object ids — the order that belongs to
alice, not her user id. Setup steps run once, up front, as a chosen subject
(reusing the token dynamic auth just obtained), and pull values out of their
responses into a capture context. Those captures then fill ``{{name}}``
placeholders in resource ``objects`` maps and request bodies, so the generated
tests point at genuine objects.
"""
from __future__ import annotations

import json
from typing import Dict, Optional
from urllib.parse import urljoin

import httpx

from overstep.jsonpath import extract
from overstep.matrix import Matrix
from overstep.mcp_client import mcp_tool_call
from overstep.mcp_matching import content_text
from overstep.models import SetupStep, Subject
from overstep.templating import render


class SetupError(RuntimeError):
    """Raised when a setup step fails or a capture cannot be extracted."""


def _subject_headers(subject: Optional[Subject]) -> Dict[str, str]:
    if subject is None:
        return {}
    headers = dict(subject.headers)
    if subject.token and not any(k.lower() == "authorization" for k in headers):
        headers["Authorization"] = f"Bearer {subject.token}"
    return headers


def _slash(base: str) -> str:
    return base if base.endswith("/") else base + "/"


def _step_label(step: SetupStep) -> str:
    if step.name:
        return step.name
    if step.call is not None:
        return f"tools/call {step.call.tool}"
    return f"{step.request.method} {step.request.path}"


def _mcp_step_result(matrix: Matrix, step: SetupStep, subject, context, label, *, verify_tls: bool) -> str:
    """Run an MCP setup/teardown tool-call and return its result content text.

    Raises SetupError on an unknown server, a JSON-RPC error or an isError result.
    """
    server = matrix.server_map().get(step.call.server)
    if server is None:
        raise SetupError(f"setup step '{label}' references unknown server '{step.call.server}'")
    arguments = render(dict(step.call.arguments), context)
    message = mcp_tool_call(server, subject, step.call.tool, arguments, verify_tls=verify_tls)
    error = message.get("error") if isinstance(message, dict) else None
    result = message.get("result") if isinstance(message, dict) else None
    result = result if isinstance(result, dict) else {}
    if error is not None:
        raise SetupError(f"setup step '{label}' errored: {error.get('message')}")
    if result.get("isError"):
        raise SetupError(f"setup step '{label}' returned an error result")
    return content_text(result.get("content"))


def _run_mcp_setup_step(matrix: Matrix, step: SetupStep, subject, context, label, *, verify_tls: bool) -> None:
    text = _mcp_step_result(matrix, step, subject, context, label, verify_tls=verify_tls)
    if not step.extract:
        return
    try:
        payload = json.loads(text)
    except ValueError as exc:
        raise SetupError(f"setup step '{label}' did not return JSON content") from exc
    for var, path_expr in step.extract.items():
        value = extract(path_expr, payload)
        if value is None:
            raise SetupError(f"setup step '{label}' found nothing at '{path_expr}' for '{var}'")
        context[var] = str(value)


def run_setup(
    matrix: Matrix,
    *,
    base_url: str,
    verify_tls: bool = True,
    client: Optional[httpx.Client] = None,
) -> Dict[str, str]:
    """Run every setup step in order and return the accumulated capture context.

    A no-op returning ``{}`` when the matrix declares no setup steps.
    """
    if not matrix.setup:
        return {}

    subjects = {s.name: s for s in matrix.subjects}
    context: Dict[str, str] = {}

    owns_client = client is None
    client = client or httpx.Client(timeout=15.0, verify=verify_tls, follow_redirects=True)
    try:
        for step in matrix.setup:
            label = _step_label(step)
            if step.run_as and step.run_as not in subjects:
                raise SetupError(f"setup step '{label}' runs as unknown subject '{step.run_as}'")
            subject = subjects.get(step.run_as) if step.run_as else None

            if step.call is not None:
                _run_mcp_setup_step(matrix, step, subject, context, label, verify_tls=verify_tls)
                continue

            path = render(step.request.path, context)
            url = urljoin(_slash(base_url), path.lstrip("/"))
            headers = {**render(step.request.headers, context), **_subject_headers(subject)}
            try:
                resp = client.request(
                    step.request.method,
                    url,
                    params=render(step.request.query, context) or None,
                    json=render(step.request.body, context),
                    headers=headers or None,
                )
            except httpx.HTTPError as exc:
                raise SetupError(f"setup step '{label}' failed: {exc}") from exc

            ok = (
                resp.status_code in step.expect_status
                if step.expect_status is not None
                else resp.status_code < 400
            )
            if not ok:
                raise SetupError(f"setup step '{label}' returned {resp.status_code}")

            if step.extract:
                try:
                    payload = resp.json()
                except ValueError as exc:
                    raise SetupError(f"setup step '{label}' did not return JSON") from exc
                for var, path_expr in step.extract.items():
                    value = extract(path_expr, payload)
                    if value is None:
                        raise SetupError(
                            f"setup step '{label}' found nothing at '{path_expr}' for '{var}'"
                        )
                    context[var] = str(value)
    finally:
        if owns_client:
            client.close()

    return context


def run_teardown(
    matrix: Matrix,
    *,
    base_url: str,
    verify_tls: bool = True,
    context: Optional[Dict[str, str]] = None,
    client: Optional[httpx.Client] = None,
) -> List[str]:
    """Run every teardown step best-effort, returning a list of failure messages.

    Teardown must never fail a run: a cleanup error is reported as a warning, not
    raised. Steps reuse the capture ``context`` from setup so they can address the
    fixtures that were created (``DELETE /orders/{{order_id}}``).
    """
    if not matrix.teardown:
        return []

    subjects = {s.name: s for s in matrix.subjects}
    context = dict(context or {})
    warnings: List[str] = []

    owns_client = client is None
    client = client or httpx.Client(timeout=15.0, verify=verify_tls, follow_redirects=True)
    try:
        for step in matrix.teardown:
            label = _step_label(step)
            subject = subjects.get(step.run_as) if step.run_as else None

            if step.call is not None:
                try:
                    _mcp_step_result(matrix, step, subject, context, label, verify_tls=verify_tls)
                except SetupError as exc:
                    warnings.append(str(exc))
                continue

            path = render(step.request.path, context)
            url = urljoin(_slash(base_url), path.lstrip("/"))
            headers = {**render(step.request.headers, context), **_subject_headers(subject)}
            try:
                resp = client.request(
                    step.request.method,
                    url,
                    params=render(step.request.query, context) or None,
                    json=render(step.request.body, context),
                    headers=headers or None,
                )
                if resp.status_code >= 400:
                    warnings.append(f"teardown step '{label}' returned {resp.status_code}")
            except httpx.HTTPError as exc:
                warnings.append(f"teardown step '{label}' failed: {exc}")
    finally:
        if owns_client:
            client.close()

    return warnings

    return context
