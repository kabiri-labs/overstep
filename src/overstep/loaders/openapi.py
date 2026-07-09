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


def _resource_payload(resources: List[Resource]) -> List[Dict[str, Any]]:
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
    return payload


def resources_to_yaml(resources: List[Resource]) -> str:
    """Render scaffolded resources as a matrix ``resources:`` block."""
    return yaml.safe_dump({"resources": _resource_payload(resources)}, sort_keys=False, allow_unicode=True)


# --- policy inference from security schemes ---------------------------------

def _collect_scopes(doc: Dict[str, Any]) -> set:
    """Every scope declared across the document's security schemes."""
    scopes: set = set()
    schemes = ((doc.get("components") or {}).get("securitySchemes")) or {}
    for scheme in schemes.values():
        for flow in (scheme.get("flows") or {}).values():
            scopes.update((flow.get("scopes") or {}).keys())
    return scopes


def _rank(scope: str) -> int:
    """A rough privilege weight so roles order least -> most privileged."""
    s = scope.lower()
    if any(k in s for k in ("admin", "root", "super", "owner")):
        return 100
    if any(k in s for k in ("manage", "write", "delete", "moderat")):
        return 50
    if any(k in s for k in ("user", "customer", "member", "read", "view", "basic")):
        return 10
    return 30


def _ordered_roles(scopes: set) -> List[str]:
    return ["anonymous"] + sorted(scopes, key=lambda s: (_rank(s), s))


def _effective_security(op: Dict[str, Any], doc: Dict[str, Any]) -> List[dict]:
    """Operation security overrides the document default; missing inherits it."""
    if isinstance(op, dict) and "security" in op:
        return op.get("security") or []
    return doc.get("security") or []


def _required_scopes(security: List[dict]) -> List[str]:
    scopes: List[str] = []
    for requirement in security or []:
        if isinstance(requirement, dict):
            for granted in requirement.values():
                for scope in granted or []:
                    if scope not in scopes:
                        scopes.append(scope)
    return scopes


def _allow_rules(scopes: List[str], is_object: bool) -> List[dict]:
    """Turn required scopes into allow rules, defaulting owned scope for objects."""
    rules: List[dict] = []
    for scope in scopes:
        scope_kind = "own" if is_object and _rank(scope) < 50 else "any"
        rules.append({"role": scope, "scope": scope_kind})
    return rules


def scaffold_matrix(path: str, *, only_get: bool = False) -> str:
    """Emit a full starter matrix — roles, subjects, resources and a policy —
    inferred from an OpenAPI document's security schemes and per-operation scopes.

    The boring part of adopting overstep is the policy; this reads the spec's own
    ``security`` declarations to draft it. Endpoints with no security become public
    (allow ``anonymous``); endpoints requiring a scope get an allow rule per scope,
    with object resources defaulting to owner-scope for non-admin roles. Review and
    tighten the result — it is a starting point, not a source of truth.
    """
    with open(path, "r", encoding="utf-8") as f:
        doc = yaml.safe_load(f) or {}

    roles = _ordered_roles(_collect_scopes(doc))
    resources = load_resources(path, only_get=only_get)
    resource_by_name = {r.name: r for r in resources}

    policy: Dict[str, Any] = {}
    for raw_path, item in (doc.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        for method, op in item.items():
            if method.lower() not in {"get", "post", "put", "patch", "delete"}:
                continue
            if only_get and method.upper() != "GET":
                continue
            name = _resource_name(method, raw_path)
            resource = resource_by_name.get(name)
            is_object = resource is not None and resource.type == ResourceType.OBJECT
            required = _required_scopes(_effective_security(op if isinstance(op, dict) else {}, doc))
            if required:
                policy[name] = {"allow": _allow_rules(required, is_object)}
            else:
                # No declared security -> a public endpoint.
                policy[name] = {"allow": [{"role": "anonymous", "scope": "any"}]}

    servers = doc.get("servers")
    base_url = (
        servers[0].get("url", "http://localhost:8000")
        if isinstance(servers, list) and servers and isinstance(servers[0], dict)
        else "http://localhost:8000"
    )

    subjects = [{"name": "anon", "role": "anonymous", "token": None}]
    for role in roles:
        if role == "anonymous":
            continue
        subjects.append(
            {
                "name": f"{role}1",
                "role": role,
                "token": f"PASTE_{role.upper()}_TOKEN",
                "attributes": {"user_id": "REPLACE_ME"},
            }
        )

    matrix = {
        "base_url": base_url,
        "roles": roles,
        "subjects": subjects,
        "resources": _resource_payload(resources),
        "policy": policy,
    }
    return yaml.safe_dump(matrix, sort_keys=False, allow_unicode=True)
