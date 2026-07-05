"""Data models shared across overstep.

Everything the tool passes around — the parsed matrix, generated test cases, the
observations we get back from the target, and the findings we report — is defined
here as pydantic models so that (de)serialization to JSON is free and validated.
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Literal, Optional, Union

from pydantic import BaseModel, Field

HTTPMethod = Literal["GET", "POST", "PUT", "PATCH", "DELETE"]

# Status codes we treat as "access was granted". Anything else (401/403/404 and
# friends, or a transport error) counts as the request having been denied.
ALLOW_STATUSES = frozenset({200, 201, 202, 203, 204, 206})


class Effect(str, Enum):
    """The authorization decision, either expected or observed."""

    ALLOW = "allow"
    DENY = "deny"


class ResourceType(str, Enum):
    """Which authorization layer a resource exercises."""

    OBJECT = "object"      # object-level access control -> BOLA surface
    FUNCTION = "function"  # function-level access control -> BFLA surface


class Variant(str, Enum):
    """For object resources, whose object the subject is reaching for."""

    SELF = "self"    # the subject's own object
    OTHER = "other"  # some other subject's object
    NA = "na"        # not object-scoped (function resources)


class VulnClass(str, Enum):
    BOLA = "BOLA"
    BFLA = "BFLA"
    PRIVILEGE_ESCALATION = "privilege-escalation"
    AUTHORIZATION_DRIFT = "authorization-drift"
    UNEXPECTED_DENY = "unexpected-deny"


class ResponseMatcher(BaseModel):
    """How to decide whether a response means access was *granted*.

    A status code alone is often not enough: some APIs redirect on success,
    return ``200`` with an error body, or mask a ``403`` as ``404``. This lets a
    matrix express the real signal. Evaluation order (see overstep.matching):

      1. ``deny_body_regex`` matches   -> deny  (catches masked errors in a 2xx)
      2. ``allow_body_regex`` matches  -> allow
      3. a 3xx redirect                -> per ``treat_redirect_as``
      4. otherwise                     -> allow iff the status matches ``allow_status``

    ``allow_status`` items may be an exact code (``200``), a range (``"200-299"``)
    or a class (``"2xx"``).
    """

    allow_status: List[Union[int, str]] = Field(
        default_factory=lambda: sorted(ALLOW_STATUSES)
    )
    allow_body_regex: Optional[str] = None
    deny_body_regex: Optional[str] = None
    treat_redirect_as: Literal["allow", "deny", "status"] = "deny"


class Subject(BaseModel):
    """An identity that makes requests against the target."""

    name: str
    role: str = "user"
    token: Optional[str] = None
    # Per-subject headers, merged over the resource's headers at request time.
    # Use these for auth schemes other than bearer (X-API-Key, a custom
    # Authorization value, a session cookie) or per-identity headers (X-Tenant).
    headers: Dict[str, str] = Field(default_factory=dict)
    # Free-form attributes such as user_id / tenant used to resolve object owners
    # and to evaluate custom allow conditions.
    attributes: Dict[str, Any] = Field(default_factory=dict)


class Request(BaseModel):
    """The HTTP request template for a resource."""

    method: HTTPMethod
    path: str
    query: Dict[str, Any] = Field(default_factory=dict)
    body: Optional[Any] = None
    headers: Dict[str, str] = Field(default_factory=dict)


class Resource(BaseModel):
    """A named API operation the matrix makes assertions about."""

    name: str
    request: Request
    type: ResourceType = ResourceType.FUNCTION
    # For object resources: the path parameter that identifies the owning subject
    # and the subject attribute it must match.
    owner_param: Optional[str] = None
    owner_attr: str = "user_id"
    description: str = ""
    # Optional per-resource override of the matrix-level response matcher.
    access: Optional[ResponseMatcher] = None


class AllowRule(BaseModel):
    """A single "this role may do this" entry in a resource's policy."""

    role: str
    scope: Literal["own", "any"] = "any"
    # Optional safe expression, ANDed with the scope check, evaluated over
    # {subject, target} attribute dicts (see overstep.expressions).
    condition: Optional[str] = None


class ResourcePolicy(BaseModel):
    """The allow-list for one resource. Anything not listed is denied."""

    allow: List[AllowRule] = Field(default_factory=list)


class TestCase(BaseModel):
    """A single, fully-resolved request we are about to send, plus what the
    matrix says *should* happen."""

    # Tell pytest this is not a test class despite the "Test" prefix.
    __test__ = False

    id: str
    resource: str
    subject: str
    role: str
    method: str
    path_template: str
    path: str
    variant: Variant
    expected: Effect
    resource_type: ResourceType
    required_roles: List[str] = Field(default_factory=list)
    query: Dict[str, Any] = Field(default_factory=dict)
    body: Optional[Any] = None
    headers: Dict[str, str] = Field(default_factory=dict)
    # The resolved response matcher for this request (resource override or the
    # matrix-level default), used to turn the response into allow/deny.
    matcher: ResponseMatcher = Field(default_factory=ResponseMatcher)

    @property
    def is_negative(self) -> bool:
        return self.expected == Effect.DENY


class Observation(BaseModel):
    """What actually came back from the target for a test case."""

    test_id: str
    status: int
    effect: Effect
    latency_ms: float = 0.0
    headers: Dict[str, str] = Field(default_factory=dict)
    body_snippet: str = ""
    error: Optional[str] = None


class Finding(BaseModel):
    """A mismatch between the matrix and reality worth reporting."""

    test_id: str
    vuln_class: VulnClass
    severity: Literal["high", "medium", "low"]
    resource: str
    subject: str
    role: str
    method: str
    path: str
    expected: Effect
    observed: Effect
    status: int
    variant: Variant
    detail: str
    evidence: Observation


class RunResult(BaseModel):
    """The full outcome of a run: what we planned, what we saw, what was wrong.

    This is the single object the pipeline hands back to callers (the CLI, tests,
    or an embedding application) so nothing has to re-thread the individual lists.
    """

    base_url: str
    cases: List[TestCase] = Field(default_factory=list)
    observations: List[Observation] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)

    @property
    def vulnerabilities(self) -> List[Finding]:
        vuln = {
            VulnClass.BOLA,
            VulnClass.BFLA,
            VulnClass.PRIVILEGE_ESCALATION,
        }
        return [f for f in self.findings if f.vuln_class in vuln]

    @property
    def drift(self) -> List[Finding]:
        return [f for f in self.findings if f.vuln_class == VulnClass.AUTHORIZATION_DRIFT]
