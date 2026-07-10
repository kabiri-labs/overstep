"""Loading and validating the authorization matrix.

The matrix file is the single source of truth for a run. It declares the
subjects (identities), the resources (API operations) and the policy (which role
may reach which resource, and with what scope). Everything downstream — test
generation, classification, drift — is derived from it.
"""
from __future__ import annotations

from typing import Dict, List, Optional

import yaml
from pydantic import BaseModel, Field

from overstep.interpolation import InterpolationError, interpolate
from overstep.models import (
    AuthConfig,
    McpMatcher,
    McpServer,
    Resource,
    ResourcePolicy,
    ResourceType,
    ResponseMatcher,
    SetupStep,
    Subject,
)

# Default privilege ordering (least -> most) when a matrix doesn't declare one.
DEFAULT_ROLE_ORDER = ["anonymous", "user", "admin"]


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
                if res.type == ResourceType.OBJECT and not res.owner_arg:
                    problems.append(f"mcp object resource '{res.name}' must set owner_arg")
            else:
                if res.request is None:
                    problems.append(f"http resource '{res.name}' must set a 'request'")
                if res.type == ResourceType.OBJECT and not res.owner_param:
                    problems.append(
                        f"object resource '{res.name}' must set owner_param"
                    )
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
        for subject in self.subjects:
            if subject.auth and subject.auth.provider not in provider_names:
                problems.append(
                    f"subject '{subject.name}' uses unknown auth provider "
                    f"'{subject.auth.provider}'"
                )

        subject_set = set(subject_names)
        for step in self.setup:
            if step.run_as and step.run_as not in subject_set:
                problems.append(
                    f"setup step '{step.name or step.request.path}' runs as unknown "
                    f"subject '{step.run_as}'"
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
