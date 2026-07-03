"""Scaffold matrix resources from a recorded HAR file.

When there's no OpenAPI spec (or it's incomplete), a HAR captured from the
browser or a proxy is the next best thing: it shows the endpoints that are
actually reachable. We collapse id-like path segments into ``{id}`` so repeated
calls to the same endpoint with different ids fold into one resource.
"""
from __future__ import annotations

import json
import re
from typing import List
from urllib.parse import urlparse

from overstep.models import Request, Resource, ResourceType

_NUMERIC = re.compile(r"^[0-9]{2,}$")
_HEXLONG = re.compile(r"^[a-fA-F0-9]{16,}$")
_UUID = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def _looks_like_id(segment: str) -> bool:
    return bool(_NUMERIC.match(segment) or _HEXLONG.match(segment) or _UUID.match(segment))


def normalize_path(path: str) -> str:
    parts = path.split("/")
    out = ["{id}" if seg and _looks_like_id(seg) else seg for seg in parts]
    joined = "/".join(out)
    return joined if joined.startswith("/") else "/" + joined


def _resource_name(method: str, path: str) -> str:
    slug = re.sub(r"[{}]", "", path).strip("/").replace("/", "_") or "root"
    return f"{method.lower()}_{slug}"


def load_resources(path: str, *, only_get: bool = False) -> List[Resource]:
    with open(path, "r", encoding="utf-8") as f:
        har = json.load(f)

    seen = set()
    resources: List[Resource] = []
    for entry in har.get("log", {}).get("entries", []):
        req = entry.get("request", {})
        method = str(req.get("method", "GET")).upper()
        if only_get and method != "GET":
            continue
        norm = normalize_path(urlparse(req.get("url", "")).path or "/")
        key = (method, norm)
        if key in seen:
            continue
        seen.add(key)

        is_object = "{id}" in norm
        resources.append(
            Resource(
                name=_resource_name(method, norm),
                request=Request(method=method, path=norm),
                type=ResourceType.OBJECT if is_object else ResourceType.FUNCTION,
                owner_param="id" if is_object else None,
            )
        )
    return resources
