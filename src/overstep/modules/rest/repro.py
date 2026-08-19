"""Rendering a REST request as evidence: a structured record and a curl.

The peer of :mod:`overstep.modules.mcp.repro`. Both were branches of one function in
`overstep.repro`, which is how a core module came to import an executor for its
header-building and a protocol module for its constants. Each surface answers
for itself now; what stays shared is masking, shell quoting and the credential
variable naming, which are the same problem whatever was sent.
"""
from __future__ import annotations

import json
import shlex
from typing import Any, Dict

from overstep.modules.rest.executor import build_headers
from overstep.models import Subject, TestCase
from overstep.repro import _full_url, _shell_arg, mask_headers


def build_record(base_url: str, subject: Subject, case: TestCase) -> Dict[str, Any]:
    """The masked, structured description of what was sent."""
    record: Dict[str, Any] = {
        "method": case.method,
        "url": _full_url(base_url, case.path, case.query),
        "headers": mask_headers(build_headers(subject, case), subject.name),
        "body": case.body,
    }
    if case.form:
        record["form"] = case.form
    return record


def build_repro(base_url: str, subject: Subject, case: TestCase) -> str:
    """The curl that re-runs it, with the credential left as a shell variable."""
    parts = ["curl", "-sS", "-X", case.method]
    for key, value in mask_headers(build_headers(subject, case), subject.name).items():
        parts += ["-H", _shell_arg(f"{key}: {value}")]
    if case.form:
        for key, value in case.form.items():
            parts += ["--data-urlencode", shlex.quote(f"{key}={value}")]
    elif case.body is not None:
        payload = case.body if isinstance(case.body, str) else json.dumps(case.body)
        parts += ["--data", shlex.quote(payload)]
        if not any(p.lower().startswith("content-type") for p in parts):
            parts += ["-H", shlex.quote("Content-Type: application/json")]
    parts.append(shlex.quote(_full_url(base_url, case.path, case.query)))
    return " ".join(parts)
