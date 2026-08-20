"""Data models shared across overstep.

Everything the tool passes around — the parsed matrix, generated test cases, the
observations we get back from the target, and the findings we report — is defined
here as pydantic models so that (de)serialization to JSON is free and validated.
"""
from __future__ import annotations

from enum import Enum
from typing import Any, ClassVar, Dict, List, Literal, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, computed_field, model_validator

# Imports nothing from overstep, so it stays safe to pull in from the module
# every other one depends on.
from overstep.modules.mcp.protocol import DEFAULT_PROTOCOL_VERSION

HTTPMethod = Literal["GET", "POST", "PUT", "PATCH", "DELETE"]

# Status codes we treat as "access was granted". Anything else (401/403/404 and
# friends, or a transport error) counts as the request having been denied.
ALLOW_STATUSES = frozenset({200, 201, 202, 203, 204, 206})

# Header names whose value is a credential. One definition serves two jobs that
# must agree: redacting secrets from anything overstep writes out, and deciding
# whether an identity carries a credential at all — a subject authenticated by a
# provider, or by a custom scheme, has one of these and no ``token``.
SECRET_HEADERS = frozenset({"authorization", "cookie", "x-api-key", "api-key", "x-auth-token"})


def drop_header(headers: Dict[str, str], name: str) -> None:
    """Remove every spelling of ``name`` from ``headers``, in place.

    HTTP header names are case-insensitive but dict keys are not, so replacing a
    credential by assigning ``headers["Authorization"]`` leaves a lowercase
    ``authorization`` sitting beside it and *both* go out on the wire. Which one
    the server honours is its own business — and if it picks the one that was
    meant to be replaced, every subject authenticates as the same identity while
    the run looks correct. Header replacement therefore always deletes first.
    """
    for key in [k for k in headers if k.lower() == name.lower()]:
        del headers[key]


class Effect(str, Enum):
    """The authorization decision, either expected or observed."""

    ALLOW = "allow"
    DENY = "deny"


class ResourceType(str, Enum):
    """Which authorization layer a resource exercises."""

    OBJECT = "object"      # object-level access control -> BOLA surface
    FUNCTION = "function"  # function-level access control -> BFLA surface


class Variant(str, Enum):
    """What kind of probe a case is.

    The first three are the original meaning — for an object resource, whose
    object the subject is reaching for. The rest are MCP protocol probes, which
    are not about an object at all but about the credential or the connection
    that carried the request; each is named for the question it asks.
    """

    SELF = "self"    # the subject's own object
    OTHER = "other"  # some other subject's object
    NA = "na"        # not object-scoped (function resources)
    # The subject presents a credential issued for a *different* audience.
    AUDIENCE = "audience"
    # A request carrying somebody else's session id and no credential of its own.
    SESSION = "session"
    # What the server is willing to *list* to this subject, as opposed to run.
    ENUMERATE = "enumerate"


class VulnClass(str, Enum):
    BOLA = "BOLA"
    BFLA = "BFLA"
    BOPLA = "BOPLA"
    PRIVILEGE_ESCALATION = "privilege-escalation"
    # An MCP server accepted a token that was not issued for it. The MCP
    # authorization spec forbids this outright: a server that honours a
    # credential minted for someone else is a confused deputy, and the token can
    # be replayed across every service that trusts the same issuer.
    TOKEN_AUDIENCE = "token-audience"
    # An MCP server let a session id stand in for a credential. The spec is
    # explicit that sessions must not be used for authentication: anyone who
    # obtains the identifier — from a log, a proxy, a referrer — becomes the
    # identity that opened it.
    SESSION_HIJACK = "session-hijack"
    # A server advertised tools to a subject the matrix does not allow to invoke
    # them. Disclosure of the function surface rather than access to it.
    TOOL_ENUMERATION = "tool-enumeration"
    AUTHORIZATION_DRIFT = "authorization-drift"
    UNEXPECTED_DENY = "unexpected-deny"


class ResponseMatcher(BaseModel):
    """How to decide whether a response means access was *granted*.

    A status code alone is often not enough: some APIs redirect on success,
    return ``200`` with an error body, or mask a ``403`` as ``404``. This lets a
    matrix express the real signal. Evaluation order (see overstep.modules.rest.matching):

      1. ``deny_body_regex`` matches   -> deny  (catches masked errors in a 2xx)
      2. ``allow_body_regex`` matches  -> allow
      3. a 3xx redirect                -> per ``treat_redirect_as``
      4. otherwise                     -> allow iff the status matches ``allow_status``

    ``allow_status`` items may be an exact code (``200``), a range (``"200-299"``)
    or a class (``"2xx"``).
    """

    model_config = ConfigDict(extra="forbid")

    # A key this matcher does not know is a mistake worth an error rather than a
    # silent default: an MCP matcher written on a REST resource (or the reverse)
    # would otherwise have every key dropped, and the resource would quietly be
    # judged by the defaults the author was trying to replace.
    model_config = ConfigDict(extra="forbid")

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

    model_config = ConfigDict(extra="forbid")

    provider: str
    vars: Dict[str, str] = Field(default_factory=dict)


class Subject(BaseModel):
    """An identity that makes requests against the target."""

    model_config = ConfigDict(extra="forbid")

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
    # Who this subject's token was issued *for*: an MCP server name from
    # ``servers:``, or any audience identifier (the URI in the token's `aud`, the
    # RFC 8707 resource indicator that obtained it). Declaring it lets overstep
    # replay the credential at every MCP server it does *not* identify, which is
    # the one thing the MCP authorization spec says a server must refuse. Left
    # unset, the audience is inferred from the subject's auth provider when that
    # provider discovers its token endpoint from a server; unknown means no
    # audience probe is generated for this subject.
    token_audience: Optional[str] = None


class Request(BaseModel):
    """The HTTP request template for a resource.

    ``body`` is sent as JSON. Set ``form`` instead to send an
    ``application/x-www-form-urlencoded`` body (the two are mutually exclusive; if
    both are set, ``form`` wins). ``form`` is also the target of a ``form`` object
    identifier injection.
    """

    model_config = ConfigDict(extra="forbid")

    method: HTTPMethod
    path: str
    query: Dict[str, Any] = Field(default_factory=dict)
    body: Optional[Any] = None
    form: Dict[str, Any] = Field(default_factory=dict)
    headers: Dict[str, str] = Field(default_factory=dict)


class McpCall(BaseModel):
    """A tool-call template for an MCP (transport: mcp) resource.

    ``arguments`` may carry ``{{captures}}`` and, for object resources, the
    ``owner`` argument is filled with the caller's / victim's object id at plan
    time (the BOLA surface). ``mutating`` marks a tool with side effects so
    ``--read-only`` can skip it.
    """

    model_config = ConfigDict(extra="forbid")

    server: str
    tool: str
    arguments: Dict[str, Any] = Field(default_factory=dict)
    mutating: bool = False


class McpResourceRead(BaseModel):
    """A ``resources/read`` template for an MCP (transport: mcp) resource.

    Tools are one half of what an MCP server exposes; the other is *resources*,
    addressed by URI. That makes the URI an object-level surface in exactly the
    sense the matrix already models: one subject reaching for another's
    ``doc://acme/bob`` is BOLA, the same bug as an id in a path parameter. A
    server can enforce ownership perfectly on every tool and hand out the same
    data through ``resources/read``, so testing only tools leaves the second door
    unopened.

    ``uri`` is a template. An ownership injection substitutes ``{placeholder}``
    the way a path injection fills a path parameter, so a URI built around an
    object id is written ``doc://acme/{doc_id}``. Writing the whole URI as one
    placeholder — ``"{doc}"`` with the full URI in ``objects:`` — covers the case
    where the object simply *is* the URI, with no template structure to exploit.
    """

    model_config = ConfigDict(extra="forbid")

    server: str
    uri: str


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

    model_config = ConfigDict(extra="forbid")

    name: str
    url: Optional[str] = None
    headers: Dict[str, str] = Field(default_factory=dict)
    protocol_version: str = DEFAULT_PROTOCOL_VERSION
    # stdio transport
    command: Optional[List[str]] = None
    env: Dict[str, str] = Field(default_factory=dict)
    token_env: Optional[str] = None

    @property
    def kind(self) -> str:
        return "stdio" if self.command else "http"


class McpMatcher(BaseModel):
    """How to decide allow/deny from an MCP tool result.

    MCP has no 403 *inside* JSON-RPC: a denial normally surfaces as a JSON-RPC
    ``error`` or a result with ``isError: true``. But MCP over Streamable HTTP
    still travels on HTTP, and the authorization spec has the server answer an
    unauthorized request with ``401`` and a ``WWW-Authenticate`` header — often
    with no JSON-RPC message in the body at all. Such a response carries no
    in-band deny signal, so it has to be read from the status; without that, a
    correctly-denying server looks like one that ran the tool.

    Evaluation order (see overstep.modules.mcp.matching):

      1. ``deny_content_regex`` matches   -> deny
      2. ``allow_content_regex`` matches  -> allow
      3. HTTP status in ``deny_status``   -> deny (the call never ran)
      4. a JSON-RPC error                 -> deny iff ``jsonrpc_error_is_deny``
      5. ``isError: true``                -> deny iff ``is_error_is_deny``
      6. otherwise                        -> allow (the tool ran and returned data)

    ``deny_status`` items take the same forms as ``ResponseMatcher.allow_status``
    (an exact code, a range, or a class). It applies to Streamable HTTP only —
    stdio has no status — and defaults to every HTTP error class, because a
    non-2xx response means the tool-call was never delivered, whatever the
    reason. Set it to ``[]`` for a server that reports denials in-band under a
    non-2xx status of its own.
    """

    model_config = ConfigDict(extra="forbid")  # see ResponseMatcher

    is_error_is_deny: bool = True
    jsonrpc_error_is_deny: bool = True
    deny_content_regex: Optional[str] = None
    allow_content_regex: Optional[str] = None
    deny_status: List[Union[int, str]] = Field(default_factory=lambda: ["4xx", "5xx"])


class McpInvocation(BaseModel):
    """A fully-resolved MCP request carried on a test case for the executor."""

    kind: Literal["http", "stdio"] = "http"
    # http transport
    url: str = ""
    headers: Dict[str, str] = Field(default_factory=dict)
    # stdio transport (argv + resolved environment carrying this subject's identity)
    command: List[str] = Field(default_factory=list)
    env: Dict[str, str] = Field(default_factory=dict)
    protocol_version: str = DEFAULT_PROTOCOL_VERSION
    # The JSON-RPC method to send. Almost always ``tools/call``; the audience
    # probe uses ``tools/list``, which needs authorization, takes no arguments and
    # changes nothing, so it answers "was this credential accepted at all"
    # without invoking anybody's tool.
    method: str = "tools/call"
    # The tool being called. Empty for a method that names none (``tools/list``).
    tool: str = ""
    arguments: Dict[str, Any] = Field(default_factory=dict)
    # The fully-resolved resource URI for ``resources/read`` — ownership already
    # substituted, so this is the object the caller is actually reaching for.
    uri: str = ""
    matcher: McpMatcher = Field(default_factory=McpMatcher)
    mutating: bool = False
    # Send the request itself with no identity: no subject headers, no bearer,
    # no Authorization inherited from the server. Used by the session probe,
    # whose whole question is what the connection alone is worth.
    anonymous: bool = False
    # Identity for the ``initialize`` handshake when it differs from the request
    # that follows. Merged over the request headers, so it need only carry the
    # difference. Set together with ``anonymous`` to open a session as one
    # identity and then use it as nobody.
    handshake_headers: Optional[Dict[str, str]] = None
    # Follow ``nextCursor`` until the listing is exhausted. Only the enumeration
    # probe needs it — that one reasons about the contents, and a restricted tool
    # on page two would otherwise be invisible and read as nothing to report. The
    # probes that only need allow/deny stop at the first page.
    paginate: bool = False


class AuthProvider(BaseModel):
    """How to obtain a token before the run.

    ``http`` sends an arbitrary login ``request`` and pulls the token out of the
    JSON response at ``token_path``. The ``oauth2_*`` types build the standard
    token-endpoint form for you. Values may contain ``{{var}}`` placeholders that
    are filled from each subject's ``auth.vars`` at login time.
    """

    model_config = ConfigDict(extra="forbid")

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
    # MCP OAuth 2.1: discover the token endpoint from an MCP server (by server name
    # or URL) via Protected Resource Metadata (RFC 9728) + Authorization Server
    # Metadata (RFC 8414), instead of hardcoding token_url.
    discover_from: Optional[str] = None
    # The authorization server these credentials were registered with. Client
    # identifiers are unique to the issuer that minted them, so discovery landing
    # on a different one is refused rather than followed — the MCP server drives
    # that discovery, and it is the host under test.
    issuer: Optional[str] = None
    # RFC 8707 resource indicator sent with the token request so the token is
    # audience-bound to the MCP server. Defaults to the discovered resource, and
    # doubles as the identifier discovery is allowed to come back with when the
    # server is legitimately known by something other than its URL.
    resource: Optional[str] = None

    # How to read and place the resulting token.
    token_path: str = "$.access_token"       # dotted path into the JSON response
    token_header: str = "Authorization"
    token_format: str = "Bearer {token}"     # {token} is the extracted value


class AuthConfig(BaseModel):

    model_config = ConfigDict(extra="forbid")
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

    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    name: str = ""
    run_as: Optional[str] = Field(default=None, alias="as")
    request: Optional[Request] = None
    call: Optional[McpCall] = None
    extract: Dict[str, str] = Field(default_factory=dict)
    expect_status: Optional[List[int]] = None


class OwnershipLocation(str, Enum):
    """Where in a request the identifier of the accessed object lives.

    The object identifier is the BOLA/BOPLA surface: overstep fills it with the
    caller's own object (SELF) or a victim's (OTHER). It is not always a path
    parameter — real APIs carry it in a query string, a header, a cookie, a form
    field, a JSON body, GraphQL variables, or an MCP tool argument.
    """

    PATH = "path"
    QUERY = "query"
    HEADER = "header"
    COOKIE = "cookie"
    FORM = "form"
    JSON = "json"
    GRAPHQL_VARIABLES = "graphql_variables"
    MCP_ARGUMENT = "mcp_argument"
    MCP_RESOURCE_URI = "mcp_resource_uri"


class OwnershipInjection(BaseModel):
    """One place to write the accessed object's identifier.

    ``selector`` is interpreted per ``location``: a path parameter name
    (``path``), a query/header/cookie/form key, a JSONPath into the JSON body
    (``json``, e.g. ``$.order.id``), a variable name or ``$.path`` under
    ``variables`` (``graphql_variables``), a tool-argument key / ``$.path``
    (``mcp_argument``), or a ``{placeholder}`` in the resource URI template
    (``mcp_resource_uri``). ``owner_attr`` overrides which subject attribute supplies
    the value for this injection (default: the resource's ``owner_attr``), so one
    injection can carry the object id while another carries, say, a tenant.
    """

    model_config = ConfigDict(extra="forbid")

    location: OwnershipLocation
    selector: str
    owner_attr: Optional[str] = None


class Ownership(BaseModel):
    """The generalized object-identifier model for a resource.

    Lists every place the accessed object's id must be written. When set it
    supersedes ``owner``, which is the shorthand for the single common case.
    Multiple injections are written together, so an object addressed by both a
    header and a path is exercised in one probe.
    """

    model_config = ConfigDict(extra="forbid")

    injections: List[OwnershipInjection] = Field(default_factory=list)


class Resource(BaseModel):
    """A named API operation the matrix makes assertions about."""

    model_config = ConfigDict(extra="forbid")

    name: str
    # The HTTP request template (transport: http). Optional so an MCP resource can
    # supply a `call` instead.
    request: Optional[Request] = None
    # The MCP tool-call template (transport: mcp).
    call: Optional[McpCall] = None
    # The MCP resource-read template (transport: mcp). Mutually exclusive with
    # `call` — an MCP resource invokes a tool or reads a resource, not both.
    read: Optional[McpResourceRead] = None
    # Which module — and therefore which delivery mechanism — carries this
    # resource. Derived from the body rather than declared: a `request` is REST,
    # a `call` or a `read` is MCP. It was a separate field, which meant a
    # resource could contradict itself and the matrix validator had to check for
    # it; a derived value makes that state unrepresentable.
    type: ResourceType = ResourceType.FUNCTION
    # For an object resource: what identifies the owned object, in whichever place
    # this resource naturally carries it — a path parameter for a `request`, a
    # tool argument for a `call`, the URI placeholder for a `read`.
    #
    # This was three keys, one per place, each named for its transport:
    # `owner_param`, `owner_arg`, `owner_uri`. They expressed one idea — "the id
    # is here" — and made the author restate what the body already said, with a
    # name that could contradict it. `ownership.injections` remains the general
    # model for an id that lives somewhere unusual, or in more than one place.
    owner: Optional[str] = None
    # Which subject attribute supplies the value. Orthogonal to where it goes:
    # a resource may key on a tenant rather than on the object id.
    owner_attr: str = "user_id"
    # Generalized object-identifier injection (path/query/header/cookie/form/json/
    # graphql_variables/mcp_argument). Supersedes `owner` when set.
    ownership: Optional[Ownership] = None
    description: str = ""
    # Optional per-resource override of its module's default matcher. One key in
    # the matrix file; which model it parses into follows from the body, so a
    # REST resource cannot accidentally be given an MCP matcher or the reverse.
    access: Optional[ResponseMatcher] = None
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
    # Per-resource override of the matrix-level probe_victims: how many distinct
    # objects each subject reaches for. Unset inherits the matrix default.
    probe_victims: Optional[Literal["one", "all"]] = None

    @model_validator(mode="before")
    @classmethod
    def _route_access_to_its_module(cls, data):
        """Send the single `access:` key to the matcher its module uses.

        The matrix file has one override key per resource. Its schema is the
        module's, so the body decides which model parses it: a call or a read is
        MCP, anything else is REST. Written as a before-validator so an MCP
        matcher's keys are never offered to `ResponseMatcher`, which would reject
        them field by field with an error naming the wrong model.

        The same pass turns the two removed keys into instructions. `extra=forbid`
        already refuses them, but "extra inputs are not permitted" does not tell
        somebody with a matrix from last release what to write instead — and for
        `transport:` in particular, the wrong reaction (delete the line) happens
        to be the right one, which is worth saying rather than leaving to luck.
        """
        if not isinstance(data, dict):
            return data
        if "transport" in data:
            raise ValueError(
                f"resource '{data.get('name', '?')}' sets 'transport'; a resource's "
                f"module is now read off its body — a 'request' is rest, a 'call' or "
                f"a 'read' is mcp — so the key has no meaning and should be deleted"
            )
        for legacy in ("owner_param", "owner_arg", "owner_uri"):
            if legacy in data:
                raise ValueError(
                    f"resource '{data.get('name', '?')}' sets '{legacy}'; the object "
                    f"identifier is spelled 'owner' on every resource now, and where "
                    f"it goes follows from the body — a 'request' puts it in the path, "
                    f"a 'call' in a tool argument, a 'read' in the URI placeholder"
                )
        if "mcp_access" in data:
            raise ValueError(
                f"resource '{data.get('name', '?')}' sets 'mcp_access'; the override "
                f"is spelled 'access' on every resource now, and which matcher parses "
                f"it follows from the body"
            )
        if "access" in data and (data.get("call") is not None or data.get("read") is not None):
            data = dict(data)
            data["mcp_access"] = data.pop("access")
        return data

    @property
    def transport(self) -> str:
        """The module that delivers this resource, read off its body.

        A resource states what it sends, and that is already unambiguous: a
        `request` goes over HTTP, a `call` or a `read` speaks MCP. Deriving it
        removes the possibility of a resource whose declared transport and body
        disagree.
        """
        if self.call is not None or self.read is not None:
            return "mcp"
        return "http"

    # Where a resource carries an object identifier by default, given what it
    # sends. The body already determines this, which is why `owner` does not
    # restate it.
    _OWNER_LOCATION: ClassVar[dict] = {
        "read": OwnershipLocation.MCP_RESOURCE_URI,
        "call": OwnershipLocation.MCP_ARGUMENT,
        "request": OwnershipLocation.PATH,
    }

    def effective_injections(self) -> List["OwnershipInjection"]:
        """Where this resource's object identifier goes.

        `ownership.injections` is the general model and wins when set: an id that
        travels in a query string, a header, a cookie or several places at once
        needs to say so. `owner` is the shorthand for the common case, and the
        place it names follows from the body rather than from its own spelling.
        """
        if self.ownership and self.ownership.injections:
            return list(self.ownership.injections)
        if not self.owner:
            return []
        for body, location in self._OWNER_LOCATION.items():
            if getattr(self, body) is not None:
                return [OwnershipInjection(location=location, selector=self.owner)]
        return []

    @property
    def is_object_locatable(self) -> bool:
        """True when this resource declares any way to locate the owned object."""
        return bool(self.effective_injections())


class AllowRule(BaseModel):
    """A single "this role may do this" entry in a resource's policy."""

    model_config = ConfigDict(extra="forbid")

    role: str
    scope: Literal["own", "any"] = "any"
    # Optional safe expression, ANDed with the scope check, evaluated over
    # {subject, target} attribute dicts (see overstep.expressions).
    condition: Optional[str] = None


class ResourcePolicy(BaseModel):
    """The allow-list for one resource. Anything not listed is denied."""

    model_config = ConfigDict(extra="forbid")

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
    # For a cross-owner (OTHER) probe: the subject whose object is being reached
    # for. ``None`` on SELF and NA cases, and also on an OTHER case that has no
    # victim — one generated for a resource where nobody could resolve an object,
    # which exercises the endpoint but tests nothing about ownership.
    victim: Optional[str] = None
    expected: Effect
    resource_type: ResourceType
    required_roles: List[str] = Field(default_factory=list)
    query: Dict[str, Any] = Field(default_factory=dict)
    body: Optional[Any] = None
    # An application/x-www-form-urlencoded body. When non-empty the executor sends
    # this instead of ``body`` (JSON). Target of a ``form`` ownership injection.
    form: Dict[str, Any] = Field(default_factory=dict)
    headers: Dict[str, str] = Field(default_factory=dict)
    # The resolved response matcher for this request (resource override or the
    # matrix-level default), used to turn the response into allow/deny.
    matcher: ResponseMatcher = Field(default_factory=ResponseMatcher)
    # For OTHER-variant object probes: the victim subject's marker(s). If the
    # response body contains one of these, a slipped-through probe is a *confirmed*
    # data leak, not merely a permissive status code.
    expect_markers: List[str] = Field(default_factory=list)
    # The resource's BOPLA keys, carried so a transport can tell whether this
    # case's response body has to survive truncation (see Observation.full_body).
    forbidden_fields: List[str] = Field(default_factory=list)
    # For transport: mcp — the fully-resolved tool-call to deliver. None for HTTP.
    mcp: Optional[McpInvocation] = None
    # For an AUDIENCE-variant probe: the audience the credential being replayed
    # was issued for, so the finding can name it. None on every other case.
    audience: Optional[str] = None

    @property
    def is_negative(self) -> bool:
        return self.expected == Effect.DENY

    # The verbs that change state over HTTP. MCP has no verb, so an MCP case
    # says so on its invocation instead; `is_mutating` is what asks either one.
    MUTATING_METHODS: ClassVar[frozenset] = frozenset({"POST", "PUT", "PATCH", "DELETE"})

    @property
    def is_mutating(self) -> bool:
        """Whether `--read-only` must skip this case.

        Both modules answer this, and they answered it in different places and
        different ways: the REST executor compared the verb against a constant it
        owned, the MCP transport read a flag off the invocation, and `preflight`
        reached into the REST executor for the constant in order to prefer a safe
        probe. One question asked of the case settles all three, and stops a core
        module importing a module's private knowledge to ask it.
        """
        if self.mcp is not None:
            return self.mcp.mutating
        return self.method.upper() in self.MUTATING_METHODS

    @property
    def is_positive_control(self) -> bool:
        """Whether an allowed result here proves this subject's credential works.

        Not every expected-allow case is evidence of that. An enumeration probe
        expects allow because listing is normally permitted, not because the
        matrix grants this subject anything — and a server whose ``tools/list``
        is public answers it with no credential at all. Counting one as a
        positive control would let a public listing vouch for expired tokens: the
        real calls would all fail, the health check would see one allowed
        positive and stay quiet, and a run that authenticated nobody would report
        a conclusive ``Vulnerabilities 0``. That is precisely the fail-open the
        check exists to catch.
        """
        return self.expected == Effect.ALLOW and self.variant != Variant.ENUMERATE


# How much of a retained response body a report may carry. The classifier reads
# the untruncated value, so this bounds the artifact, never the check: a leak
# past this point is still found, still named in `leaked_fields`, and still
# reported — only the long-form quotation behind it is clipped.
EVIDENCE_BODY_LIMIT = 65536


class Observation(BaseModel):
    """What actually came back from the target for a test case."""

    test_id: str
    status: int
    effect: Effect
    latency_ms: float = 0.0
    headers: Dict[str, str] = Field(default_factory=dict)
    body_snippet: str = ""
    # The body the BOPLA check reads, retained only when the case declares
    # forbidden_fields. ``body_snippet`` is a fixed head-of-body budget and the
    # check needs the whole thing, so the two are separate: the snippet stays the
    # short quotation every finding carries, and this is the long-form evidence
    # behind a property-level one. Capped at EVIDENCE_BODY_LIMIT on the way into
    # a report — a run that writes megabytes of response body into a CI artifact
    # is not evidence anyone reads — while the in-memory value the classifier
    # sees is never truncated, so the cap can never hide a leak.
    full_body: str = Field(default="")
    error: Optional[str] = None
    # Which of the test case's expected victim markers actually appeared in the
    # response body (empty when none were configured or none matched).
    matched_markers: List[str] = Field(default_factory=list)
    # Tool names returned by a ``tools/list`` request, recorded separately rather
    # than parsed back out of the body: the snippet is truncated, and a catalogue
    # is exactly the kind of result long enough to lose its tail.
    listed_tools: List[str] = Field(default_factory=list)
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
    # For a BOPLA finding: the forbidden keys actually present in the response.
    # The detail sentence names them for a human; this is the same answer for a
    # dashboard, and it survives the evidence cap when the body does not.
    leaked_fields: List[str] = Field(default_factory=list)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def group(self) -> str:
        """Identifies the *defect*, as opposed to one probe that revealed it.

        Every subject that reaches a broken endpoint produces its own finding, so
        one missing check can surface a dozen times and triage cost scales with
        the matrix rather than with the bug count. Findings sharing a group are
        the same defect seen from different identities; the method is part of the
        key because a resource can be sound on GET and broken on DELETE.
        """
        return f"{self.resource}::{self.method}::{self.vuln_class.value}"


class RunHealth(BaseModel):
    """Whether a run's results are worth drawing conclusions from.

    A run only means something if the requests reached the target and the
    credentials were accepted; see :mod:`overstep.health` for how the verdict is
    reached. The defaults describe an empty but trustworthy run, so a
    ``RunResult`` built without health data behaves exactly as before.
    """

    executed: int = 0
    transport_errors: int = 0
    positive_tests: int = 0
    positive_allowed: int = 0
    # Human-readable explanations; non-empty means the run proved nothing.
    reasons: List[str] = Field(default_factory=list)

    @property
    def inconclusive(self) -> bool:
        return bool(self.reasons)


class ProbeCoverage(BaseModel):
    """How much of the BOLA surface a run actually reached.

    Every object resource is a place where object-level access control can be
    missing, but only a *cross-owner* probe can show it: one subject reaching
    for another subject's object. The planner drops that probe when no two
    subjects resolve to different objects, because re-sending a subject's own
    request under the OTHER label would prove nothing — so a matrix can declare
    an object resource, run it, and never test the thing it was declared for.

    Nothing about that is visible in the finding count, which is exactly the
    gap: ``Vulnerabilities 0`` reads the same whether the probe ran and found
    nothing or was never generated. Reporting the absence of a finding is only
    worth something if the run could have seen it, so the run says how many of
    its object resources it was actually able to probe.

    The defaults describe a run with no object resources, so a ``RunResult``
    built without coverage data behaves exactly as before.
    """

    object_resources: int = 0
    # Object resources for which at least one real cross-owner probe was planned.
    probed: int = 0
    # The ones that were not, by name, so the report can say which to fix.
    unprobed: List[str] = Field(default_factory=list)

    @property
    def complete(self) -> bool:
        return not self.unprobed

    @property
    def ratio(self) -> float:
        """Probed share of the object resources; 1.0 when there are none."""
        if not self.object_resources:
            return 1.0
        return self.probed / self.object_resources


class RunResult(BaseModel):
    """The full outcome of a run: what we planned, what we saw, what was wrong.

    This is the single object the pipeline hands back to callers (the CLI, tests,
    or an embedding application) so nothing has to re-thread the individual lists.
    """

    base_url: str
    # The matrix file this run came from, if known. Used to anchor SARIF findings
    # to a physical location (GitHub code scanning requires one); authorization
    # findings have no source line of their own, so they point at the matrix that
    # declares the policy.
    source: Optional[str] = None
    cases: List[TestCase] = Field(default_factory=list)
    observations: List[Observation] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    # Findings suppressed by a matching, non-expired waiver. Kept out of gating
    # but recorded so accepted risk stays visible in reports.
    waived: List[Finding] = Field(default_factory=list)
    # Non-fatal warnings raised during the run (e.g. an expired waiver).
    warnings: List[str] = Field(default_factory=list)
    # Whether the run reached the target and was authenticated at all. An
    # inconclusive run has no findings for the wrong reason, so callers must not
    # read "no vulnerabilities" as "no vulnerabilities exist". Defaults to a
    # healthy, empty verdict so existing callers are unaffected.
    health: RunHealth = Field(default_factory=RunHealth)
    # How much of the declared BOLA surface the run was able to probe. "No
    # findings" over an unprobed resource is not evidence of anything.
    coverage: ProbeCoverage = Field(default_factory=ProbeCoverage)

    @property
    def vulnerabilities(self) -> List[Finding]:
        vuln = {
            VulnClass.BOLA,
            VulnClass.BFLA,
            VulnClass.BOPLA,
            VulnClass.PRIVILEGE_ESCALATION,
            VulnClass.TOKEN_AUDIENCE,
            VulnClass.SESSION_HIJACK,
            VulnClass.TOOL_ENUMERATION,
        }
        return [f for f in self.findings if f.vuln_class in vuln]

    @property
    def drift(self) -> List[Finding]:
        return [f for f in self.findings if f.vuln_class == VulnClass.AUTHORIZATION_DRIFT]
