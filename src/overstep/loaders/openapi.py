"""Scaffold matrix resources from an OpenAPI document.

Writing the resource list by hand is the boring part of adopting overstep. Point
this at an OpenAPI spec and it emits a starter list of resources — guessing the
object-vs-function type from whether the path carries an id-like parameter — that
you can paste into a matrix and then annotate with a policy.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

import yaml

from overstep.models import Request, Resource, ResourceType

# Path parameters whose name suggests they identify an owned object.
_OWNER_HINTS = {
    "id", "userid", "user_id", "accountid", "account_id", "ownerid",
    "owner_id", "orgid", "org_id", "tenantid", "tenant_id", "customerid",
}

_PARAM_RE = re.compile(r"{([^}]+)}")


def _norm(name: str) -> str:
    return name.replace("_", "").lower()


def _guess_owner_param(path: str) -> str | None:
    params = _PARAM_RE.findall(path)
    for param in params:
        if _norm(param) in _OWNER_HINTS:
            return param
    # Fall back to the last path parameter, which is usually the object id.
    return params[-1] if params else None


def _resource_name(method: str, path: str) -> str:
    slug = re.sub(r"[{}]", "", path).strip("/").replace("/", "_") or "root"
    return f"{method.lower()}_{slug}"


def load_resources(path: str, *, only_get: bool = False) -> List[Resource]:
    with open(path, "r", encoding="utf-8") as f:
        doc = yaml.safe_load(f) or {}

    resources: List[Resource] = []
    for raw_path, item in (doc.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        for method, op in item.items():
            if method.lower() not in {"get", "post", "put", "patch", "delete"}:
                continue
            if only_get and method.upper() != "GET":
                continue

            owner = _guess_owner_param(raw_path)
            is_object = owner is not None
            summary = ""
            if isinstance(op, dict):
                summary = op.get("summary") or op.get("operationId") or ""

            resources.append(
                Resource(
                    name=_resource_name(method, raw_path),
                    request=Request(method=method.upper(), path=raw_path),
                    type=ResourceType.OBJECT if is_object else ResourceType.FUNCTION,
                    owner_param=owner if is_object else None,
                    description=summary,
                )
            )
    return resources


def resources_to_yaml(resources: List[Resource]) -> str:
    """Render scaffolded resources as a matrix ``resources:`` block."""
    payload: List[Dict[str, Any]] = []
    for res in resources:
        entry: Dict[str, Any] = {
            "name": res.name,
            "request": {"method": res.request.method, "path": res.request.path},
            "type": res.type.value,
        }
        if res.owner_param:
            entry["owner_param"] = res.owner_param
        if res.description:
            entry["description"] = res.description
        payload.append(entry)
    return yaml.safe_dump({"resources": payload}, sort_keys=False, allow_unicode=True)
