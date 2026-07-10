"""Data models shared across overstep.

Everything the tool passes around — the parsed matrix, generated test cases, the
observations we get back from the target, and the findings we report — is defined
here as pydantic models so that (de)serialization to JSON is free and validated.
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Literal, Optional, Union

from pydantic import BaseModel, ConfigDict, Field

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
    BOPLA = "BOPLA"
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


class SubjectAuth(BaseModel):
    """Ties a subject to an auth provider and supplies its per-subject inputs.

    ``vars`` fill the ``{{placeholders}}`` in the provider's login request, so two
    subjects can share one provider with different credentials.
    """

    provider: str
    vars: Dict[str, str] = Field(default_factory=dict)


class Subject(BaseModel):
    """An identity that makes requests against the target."""

    name: str
    role: str = "user"
    # A static bearer token. Leave unset and use `auth` to obtain one dynamically.
    token: Optional[str] = None
    # Dynamic authentication: obtain a token from a provider before the run.
    auth: Optional[SubjectAuth] = None
    # Per-subject headers, merged over the resource's headers at request time.
    # Use these for auth schemes other than bearer (X-API-Key, a custom
    # Authorization value, a session cookie) or per-identity headers (X-Tenant).
    headers: Dict[str, str] = Field(default_factory=dict)
    # Free-form attributes such as user_id / tenant used to resolve object owners
    # and to evaluate custom allow conditions.
    attributes: Dict[str, Any] = Field(default_factory=dict)
    # A string that uniquely identifies *this* subject's data in a response (an
    # email, a name, a per-user secret). Used by the content-aware oracle: when a
    # BOLA probe is allowed, overstep looks for the victim's marker in the body to
    # confirm real data leaked rather than trusting the status code alone.
    marker: Optional[str] = None


class Request(BaseModel):
    """The HTTP request template for a resource."""

    method: HTTPMethod
    path: str
    query: Dict[str, Any] = Field(default_factory=dict)
    body: Optional[Any] = None
    headers: Dict[str, str] = Field(default_factory=dict)


class McpCall(BaseModel):
    """A tool-call template for an MCP (transport: mcp) resource.

    ``arguments`` may carry ``{{captures}}`` and, for object resources, the
    ``owner_arg`` argument is filled with the caller's / victim's object id at plan
    time (the BOLA surface). ``mutating`` marks a tool with side effects so
    ``--read-only`` can skip it.
    """

    server: str
    tool: str
    arguments: Dict[str, Any] = Field(default_factory=dict)
    mutating: bool = False


class McpServer(BaseModel):
    """An MCP server the matrix can reach, declared under ``servers:``.

    Two kinds are supported:

    * **Streamable HTTP** — set ``url`` (the JSON-RPC endpoint). Per-server
      ``headers`` merge under each subject's own headers, and identity is the
      subject's bearer token / headers.
    * **stdio** — set ``command`` (argv of a local server process). ``env`` is a
      static environment, and ``token_env`` names the variable the subject's token
      is injected into, so each identity launches its own process.
    """

    name: str
    url: Optional[str] = None
    headers: Dict[str, str] = Field(default_factory=dict)
    protocol_version: str = "2025-06-18"
    # stdio transport
    command: Optional[List[str]] = None
    env: Dict[str, str] = Field(default_factory=dict)
    token_env: Optional[str] = None

    @property
    def kind(self) -> str:
        return "stdio" if self.command else "http"


class McpMatcher(BaseModel):
    """How to decide allow/deny from an MCP tool result.

    MCP has no 403: a denial usually surfaces as a JSON-RPC ``error`` or a result
    with ``isError: true``. Evaluation order (see overstep.mcp_matching):

      1. ``deny_content_regex`` matches   -> deny
      2. ``allow_content_regex`` matches  -> allow
      3. a JSON-RPC error                 -> deny iff ``jsonrpc_error_is_deny``
      4. ``isError: true``                -> deny iff ``is_error_is_deny``
      5. otherwise                        -> allow (the tool ran and returned data)
    """

    is_error_is_deny: bool = True
    jsonrpc_error_is_deny: bool = True
    deny_content_regex: Optional[str] = None
    allow_content_regex: Optional[str] = None


class McpInvocation(BaseModel):
    """A fully-resolved MCP tool-call carried on a test case for the executor."""

    kind: Literal["http", "stdio"] = "http"
    # http transport
    url: str = ""
    headers: Dict[str, str] = Field(default_factory=dict)
    # stdio transport (argv + resolved environment carrying this subject's identity)
    command: List[str] = Field(default_factory=list)
    env: Dict[str, str] = Field(default_factory=dict)
    protocol_version: str = "2025-06-18"
    tool: str
    arguments: Dict[str, Any] = Field(default_factory=dict)
    matcher: McpMatcher = Field(default_factory=McpMatcher)
    mutating: bool = False


class AuthProvider(BaseModel):
    """How to obtain a token before the run.

    ``http`` sends an arbitrary login ``request`` and pulls the token out of the
    JSON response at ``token_path``. The ``oauth2_*`` types build the standard
    token-endpoint form for you. Values may contain ``{{var}}`` placeholders that
    are filled from each subject's ``auth.vars`` at login time.
    """

    name: str
    type: Literal["http", "oauth2_password", "oauth2_client_credentials"] = "http"
    base_url: Optional[str] = None  # defaults to the matrix base URL

    # type == "http"
    request: Optional[Request] = None

    # type == "oauth2_*"
    token_url: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    scope: Optional[str] = None

    # How to read and place the resulting token.
    token_path: str = "$.access_token"       # dotted path into the JSON response
    token_header: str = "Authorization"
    token_format: str = "Bearer {token}"     # {token} is the extracted value


class AuthConfig(BaseModel):
    providers: List[AuthProvider] = Field(default_factory=list)


class SetupStep(BaseModel):
    """A request run once before the suite to create fixtures and capture values.

    ``run_as`` (written ``as`` in YAML) picks the subject whose credentials the
    step uses. ``extract`` maps capture names to dotted JSON paths into the
    response; captured values then fill ``{{name}}`` placeholders in resource
    ``objects`` maps and request bodies.

    A step is HTTP (set ``request``) or MCP (set ``call`` — a tool-call whose JSON
    result content is what ``extract`` reads), so fixtures can be created and
    object ids captured over either transport.
    """

    model_config = ConfigDict(populate_by_name=True)

    name: str = ""
    run_as: Optional[str] = Field(default=None, alias="as")
    request: Optional[Request] = None
    call: Optional[McpCall] = None
    extract: Dict[str, str] = Field(default_factory=dict)
    expect_status: Optional[List[int]] = None


class Resource(BaseModel):
    """A named API operation the matrix makes assertions about."""

    name: str
    # The HTTP request template (transport: http). Optional so an MCP resource can
    # supply a `call` instead.
    request: Optional[Request] = None
    # The MCP tool-call template (transport: mcp).
    call: Optional[McpCall] = None
    # Which delivery mechanism carries this resource's request. "http" is the
    # default; other transports (registered in overstep.transports) route through
    # their own executor without the core needing to know how.
    transport: str = "http"
    type: ResourceType = ResourceType.FUNCTION
    # For object resources: the path parameter (http) or tool argument (mcp) that
    # identifies the owned object, and the subject attribute it must match.
    owner_param: Optional[str] = None
    owner_arg: Optional[str] = None
    owner_attr: str = "user_id"
    description: str = ""
    # Optional per-resource override of the matrix-level response matcher.
    access: Optional[ResponseMatcher] = None
    # Optional per-resource override of the matrix-level MCP matcher.
    mcp_access: Optional[McpMatcher] = None
    # Explicit object id owned by each subject (subject name -> id). Takes
    # precedence over owner_attr, and values may reference {{captures}} from
    # setup steps. This is how real BOLA testing points at genuine owned objects
    # (an order id, a document id) rather than a user id.
    objects: Dict[str, str] = Field(default_factory=dict)
    # BOPLA (object property-level): JSON keys that must NOT appear in a response
    # even for an allowed caller (e.g. "password_hash", "is_admin"). If one shows
    # up in a granted response the resource over-shares and a BOPLA is reported.
    forbidden_fields: List[str] = Field(default_factory=list)
    # Cross-method probing: extra HTTP methods to fire at another subject's object
    # (e.g. a GET resource also probed with PUT/DELETE). Each becomes a negative
    # test — if it succeeds the endpoint is missing method-level authorization.
    probe_methods: List[str] = Field(default_factory=list)


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
    # The transport that will deliver this case (carried from the resource).
    transport: str = "http"
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
    # For OTHER-variant object probes: the victim subject's marker(s). If the
    # response body contains one of these, a slipped-through probe is a *confirmed*
    # data leak, not merely a permissive status code.
    expect_markers: List[str] = Field(default_factory=list)
    # For transport: mcp — the fully-resolved tool-call to deliver. None for HTTP.
    mcp: Optional[McpInvocation] = None

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
    # Which of the test case's expected victim markers actually appeared in the
    # response body (empty when none were configured or none matched).
    matched_markers: List[str] = Field(default_factory=list)
    # True when the request was deliberately not sent (e.g. a mutating verb under
    # --read-only). Skipped observations never produce findings.
    skipped: bool = False


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
    # A copy-pasteable reproduction of the request that triggered the finding,
    # with credentials masked. Empty when repro could not be built.
    curl: str = ""
    # A structured, secret-masked record of the same request (method/url/headers/
    # body) for dashboards and tickets.
    request: Optional[Dict[str, Any]] = None
    # How sure we are the finding is real. "confirmed" — the victim's marker was
    # seen in the response (a proven leak) or the signal is unambiguous;
    # "suspected" — access was granted but the expected victim data did not appear;
    # "unverified" — decided on status alone with no content check configured.
    confidence: Literal["confirmed", "suspected", "unverified"] = "confirmed"


class RunResult(BaseModel):
    """The full outcome of a run: what we planned, what we saw, what was wrong.

    This is the single object the pipeline hands back to callers (the CLI, tests,
    or an embedding application) so nothing has to re-thread the individual lists.
    """

    base_url: str
    cases: List[TestCase] = Field(default_factory=list)
    observations: List[Observation] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    # Findings suppressed by a matching, non-expired waiver. Kept out of gating
    # but recorded so accepted risk stays visible in reports.
    waived: List[Finding] = Field(default_factory=list)
    # Non-fatal warnings raised during the run (e.g. an expired waiver).
    warnings: List[str] = Field(default_factory=list)

    @property
    def vulnerabilities(self) -> List[Finding]:
        vuln = {
            VulnClass.BOLA,
            VulnClass.BFLA,
            VulnClass.BOPLA,
            VulnClass.PRIVILEGE_ESCALATION,
        }
        return [f for f in self.findings if f.vuln_class in vuln]

    @property
    def drift(self) -> List[Finding]:
        return [f for f in self.findings if f.vuln_class == VulnClass.AUTHORIZATION_DRIFT]
