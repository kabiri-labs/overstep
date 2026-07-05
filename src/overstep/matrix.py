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

from overstep.models import Resource, ResourcePolicy, ResourceType, ResponseMatcher, Subject

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

    def resource_map(self) -> Dict[str, Resource]:
        return {r.name: r for r in self.resources}

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

        for res in self.resources:
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
        return problems


def load_matrix(path: str) -> Matrix:
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    try:
        return Matrix(**data)
    except Exception as exc:  # pydantic ValidationError, etc.
        raise MatrixError(f"could not parse matrix '{path}': {exc}") from exc
