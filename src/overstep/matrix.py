"""Loading and validating the authorization matrix.

The matrix file is the single source of truth for a run. It declares the
subjects (identities), the resources (API operations) and the policy (which role
may reach which resource, and with what scope). Everything downstream — test
generation, classification, drift — is derived from it.
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional

import yaml
from pydantic import BaseModel, Field

from overstep.interpolation import InterpolationError, interpolate
from overstep.models import (
    AuthConfig,
    McpMatcher,
    McpServer,
    OwnershipLocation,
    Resource,
    ResourcePolicy,
    ResourceType,
    ResponseMatcher,
    SetupStep,
    Subject,
)

# Default privilege ordering (least -> most) when a matrix doesn't declare one.
DEFAULT_ROLE_ORDER = ["anonymous", "user", "admin"]

_PATH_PARAM_RE = re.compile(r"{([^}]+)}")


class MatrixError(ValueError):
    """Raised when a matrix is structurally invalid."""


class Matrix(BaseModel):
    base_url: Optional[str] = None
    # Roles from least to most privileged; used to classify privilege escalation.
    roles: List[str] = Field(default_factory=list)
    subjects: List[Subject]
    resources: List[Resource]
    policy: Dict[str, ResourcePolicy] = Field(default_factory=dict)
    # Default response matcher applied to every resource that doesn't override it.
    access: ResponseMatcher = Field(default_factory=ResponseMatcher)
    # MCP servers reachable by transport: mcp resources.
    servers: List[McpServer] = Field(default_factory=list)
    # Default MCP matcher applied to every mcp resource that doesn't override it.
    mcp_access: McpMatcher = Field(default_factory=McpMatcher)
    # Providers used to obtain subject tokens dynamically before a run.
    auth: AuthConfig = Field(default_factory=AuthConfig)
    # Requests run once before the suite to create fixtures / capture object ids.
    setup: List[SetupStep] = Field(default_factory=list)
    # Requests run once after the suite (best-effort) to clean up fixtures the
    # setup steps created. Can reference {{captures}} from setup.
    teardown: List[SetupStep] = Field(default_factory=list)

    def resource_map(self) -> Dict[str, Resource]:
        return {r.name: r for r in self.resources}

    def server_map(self) -> Dict[str, McpServer]:
        return {s.name: s for s in self.servers}

    def role_order(self) -> List[str]:
        return self.roles or DEFAULT_ROLE_ORDER

    def role_rank(self, role: str) -> int:
        """Higher number = more privileged. -1 for unknown roles."""
        order = self.role_order()
        return order.index(role) if role in order else -1

    def required_roles(self, resource_name: str) -> List[str]:
        pol = self.policy.get(resource_name)
        if not pol:
            return []
        return sorted({rule.role for rule in pol.allow})

    def _validate_injections(self, res: Resource) -> List[str]:
        """Check a resource's object-identifier injections for coherence.

        Ensures MCP resources use ``mcp_argument`` (and HTTP resources don't),
        that path injections name a real path parameter, and that ownership can
        actually be resolved — an unresolvable default object would make the probe
        silently skip rather than fall back to a placeholder.
        """
        problems: List[str] = []
        injections = res.effective_injections()
        path_params = (
            set(_PATH_PARAM_RE.findall(res.request.path)) if res.request else set()
        )
        for inj in injections:
            is_mcp = inj.location == OwnershipLocation.MCP_ARGUMENT
            if res.transport == "mcp" and not is_mcp:
                problems.append(
                    f"mcp resource '{res.name}' injection must use location "
                    f"'mcp_argument', not '{inj.location.value}'"
                )
            elif res.transport != "mcp" and is_mcp:
                problems.append(
                    f"http resource '{res.name}' cannot use an 'mcp_argument' injection"
                )
            if inj.location == OwnershipLocation.PATH and res.request and inj.selector not in path_params:
                problems.append(
                    f"resource '{res.name}' path injection '{inj.selector}' is not a "
                    f"parameter in path '{res.request.path}'"
                )

        # No placeholder for ownership: warn when no subject can supply a value for
        # every injection (whether it reads the default object or an override
        # attribute), so probes are never silently skipped or half-populated.
        def _resolves(subject) -> bool:
            for inj in injections:
                if inj.owner_attr is not None:
                    if subject.attributes.get(inj.owner_attr) is None:
                        return False
                elif subject.name not in res.objects and subject.attributes.get(res.owner_attr) is None:
                    return False
            return True

        if injections and not any(_resolves(s) for s in self.subjects):
            attrs = sorted({inj.owner_attr or res.owner_attr for inj in injections})
            problems.append(
                f"object resource '{res.name}' has no subject with a resolvable "
                f"object (add an 'objects:' entry or attribute(s): {', '.join(attrs)}); "
                f"ownership probes will be skipped"
            )
        return problems

    def validate_refs(self) -> List[str]:
        """Return a list of human-readable problems; empty means the matrix is ok."""
        problems: List[str] = []
        rmap = self.resource_map()
        subject_names = [s.name for s in self.subjects]

        if len(subject_names) != len(set(subject_names)):
            problems.append("duplicate subject names are not allowed")
        if len(rmap) != len(self.resources):
            problems.append("duplicate resource names are not allowed")

        for name in self.policy:
            if name not in rmap:
                problems.append(f"policy references unknown resource '{name}'")

        from overstep.transports import transport_names
        known_transports = set(transport_names())
        server_names = {s.name for s in self.servers}
        for srv in self.servers:
            if not srv.url and not srv.command:
                problems.append(f"server '{srv.name}' must set a url (http) or a command (stdio)")
        for res in self.resources:
            if res.transport not in known_transports:
                problems.append(
                    f"resource '{res.name}' uses unknown transport '{res.transport}' "
                    f"(known: {', '.join(sorted(known_transports))})"
                )
            if res.transport == "mcp":
                if res.call is None:
                    problems.append(f"mcp resource '{res.name}' must set a 'call'")
                elif res.call.server not in server_names:
                    problems.append(
                        f"mcp resource '{res.name}' references unknown server "
                        f"'{res.call.server}'"
                    )
                if res.type == ResourceType.OBJECT and not res.is_object_locatable:
                    problems.append(
                        f"mcp object resource '{res.name}' must set owner_arg or "
                        f"ownership.injections"
                    )
            else:
                if res.request is None:
                    problems.append(f"http resource '{res.name}' must set a 'request'")
                if res.type == ResourceType.OBJECT and not res.is_object_locatable:
                    problems.append(
                        f"object resource '{res.name}' must set owner_param or "
                        f"ownership.injections"
                    )
            problems.extend(self._validate_injections(res))
            if res.name not in self.policy:
                problems.append(
                    f"resource '{res.name}' has no policy entry (everything will be denied)"
                )

        known_roles = set(self.role_order())
        for name, pol in self.policy.items():
            for rule in pol.allow:
                if rule.role not in known_roles:
                    problems.append(
                        f"policy for '{name}' allows unknown role '{rule.role}'"
                    )

        provider_names = {p.name for p in self.auth.providers}
        for provider in self.auth.providers:
            if provider.type.startswith("oauth2") and not provider.token_url and not provider.discover_from:
                problems.append(
                    f"auth provider '{provider.name}' needs a token_url or discover_from"
                )
            if provider.discover_from and "://" not in provider.discover_from \
                    and provider.discover_from not in server_names:
                problems.append(
                    f"auth provider '{provider.name}' discover_from references unknown "
                    f"server '{provider.discover_from}'"
                )
        for subject in self.subjects:
            if subject.auth and subject.auth.provider not in provider_names:
                problems.append(
                    f"subject '{subject.name}' uses unknown auth provider "
                    f"'{subject.auth.provider}'"
                )

        subject_set = set(subject_names)
        for phase, steps in (("setup", self.setup), ("teardown", self.teardown)):
            for step in steps:
                label = step.name or (step.call.tool if step.call else (step.request.path if step.request else "?"))
                if step.run_as and step.run_as not in subject_set:
                    problems.append(
                        f"{phase} step '{label}' runs as unknown subject '{step.run_as}'"
                    )
                if step.call is None and step.request is None:
                    problems.append(f"{phase} step '{label}' must set a 'request' or a 'call'")
                if step.call is not None and step.call.server not in server_names:
                    problems.append(
                        f"{phase} step '{label}' references unknown server '{step.call.server}'"
                    )
        for res in self.resources:
            for sub_name in res.objects:
                if sub_name not in subject_set:
                    problems.append(
                        f"resource '{res.name}' declares an object for unknown "
                        f"subject '{sub_name}'"
                    )
        return problems


def load_matrix(path: str, env=None) -> Matrix:
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    # Resolve ${ENV} references before building the model so secrets stay out of
    # the committed file.
    try:
        data = interpolate(data, env)
    except InterpolationError as exc:
        raise MatrixError(f"could not load matrix '{path}': {exc}") from exc
    try:
        return Matrix(**data)
    except Exception as exc:  # pydantic ValidationError, etc.
        raise MatrixError(f"could not parse matrix '{path}': {exc}") from exc
