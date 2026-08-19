"""Loading and validating the authorization matrix.

The matrix file is the single source of truth for a run. It declares the
subjects (identities), the resources (API operations) and the policy (which role
may reach which resource, and with what scope). Everything downstream — test
generation, classification, drift — is derived from it.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

from overstep.documents import DocumentError, read_yaml
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


class Severity(str, Enum):
    """How much a validation problem matters.

    The distinction exists because the two kinds need opposite handling. An
    ``ERROR`` means the matrix cannot produce a trustworthy run — a reference
    that goes nowhere, a resource the transport cannot deliver — so continuing
    only buys a result nobody should read. A ``WARNING`` means the run will
    happen and its findings will be real, but it tests less than its size
    suggests: a dropped BOLA probe still leaves every other probe valid.

    Without the split, one of the two has to be mishandled. Failing on
    warnings turns a deliberate deny-by-default scaffold into a broken build;
    passing on errors is the fail-open a security gate cannot have.
    """

    ERROR = "error"
    WARNING = "warning"


@dataclass(frozen=True)
class Problem:
    """One thing wrong with a matrix, and how much it matters.

    ``line`` is set only for problems found by reading the matrix file itself
    (see :mod:`overstep.placeholders`); the structural checks run against the
    parsed model, which no longer knows where anything was written.
    """

    message: str
    severity: Severity = Severity.ERROR
    line: Optional[int] = None

    def __str__(self) -> str:
        return f"line {self.line}: {self.message}" if self.line else self.message


class RestModule(BaseModel):
    """Configuration that belongs to the REST surface and nowhere else."""

    model_config = ConfigDict(extra="forbid")

    base_url: Optional[str] = None
    # Default response matcher applied to every REST resource that doesn't
    # override it.
    access: ResponseMatcher = Field(default_factory=ResponseMatcher)


class McpProbes(BaseModel):
    """The three checks that ask about the credential and the connection.

    They belong to the MCP module rather than to the matrix as a whole: each is
    a question about an MCP server, and a matrix with no MCP module has nothing
    for any of them to probe.
    """

    # Replay each subject's credential at the MCP servers it was not issued for
    # (see overstep.planner). On by default, but it only produces probes where
    # an audience is actually known — declared on the subject, or inferred from
    # an auth provider that discovers its token endpoint from a server. Turn it
    # off for a deployment where one token is legitimately valid at several of
    # the declared servers, which is the one case where a refusal is not
    # required and a probe would report a finding that isn't one.
    token_audience: bool = True
    # Check that an MCP session id cannot stand in for a credential (see
    # overstep.planner). On by default: the probe is read-only, carries its own
    # control, and skips a server that issues no session, so it costs nothing
    # where there is nothing to find.
    session_binding: bool = True
    # Check what each server is willing to *list* to each subject. Off by
    # default, unlike the other two: advertising every tool and enforcing at
    # call time is a defensible design, so this reports a policy opinion the
    # matrix has to opt into rather than a violation of the protocol.
    tool_enumeration: bool = False

    # A typo here is the most expensive one in the file: `tool_enumeraton: true`
    # would leave the probe off, and the run would report clean without ever
    # having asked the question. Silently dropping it is not an option a security
    # tool has.
    model_config = ConfigDict(extra="forbid")


class McpModule(BaseModel):
    """Configuration that belongs to the MCP surface and nowhere else."""

    model_config = ConfigDict(extra="forbid")

    # MCP servers reachable by the resources whose body is a call or a read.
    servers: List[McpServer] = Field(default_factory=list)
    # Default MCP matcher applied to every MCP resource that doesn't override it.
    access: McpMatcher = Field(default_factory=McpMatcher)
    probes: McpProbes = Field(default_factory=McpProbes)


class Modules(BaseModel):
    """Per-module configuration, one block per surface.

    The matrix has two levels. Everything a run needs regardless of how a
    request is delivered — subjects, resources, policy, credentials, fixtures —
    is declared once at the top. Everything that only means something to one
    surface lives under that surface's name here.

    Before this split, five of the fifteen top-level keys were MCP-only while
    reading as global: `servers`, `mcp_access` and the three `probe_*` switches.
    A REST-only matrix carried settings that could never apply to it, and a
    reader had no way to tell which of the two the next key belonged to.
    """

    model_config = ConfigDict(extra="forbid")

    rest: RestModule = Field(default_factory=RestModule)
    mcp: McpModule = Field(default_factory=McpModule)


# Where each key that used to sit at the top level lives now. Read by the loader
# to turn a stale matrix into an instruction rather than a silently ignored key.
RELOCATED_KEYS = {
    "base_url": "modules.rest.base_url",
    "access": "modules.rest.access",
    "servers": "modules.mcp.servers",
    "mcp_access": "modules.mcp.access",
    "probe_token_audience": "modules.mcp.probes.token_audience",
    "probe_session_binding": "modules.mcp.probes.session_binding",
    "probe_tool_enumeration": "modules.mcp.probes.tool_enumeration",
}


class Matrix(BaseModel):
    # A key this model does not know is a mistake, not a comment. Pydantic's
    # default is to ignore one, which is the worst available outcome here: a
    # matrix still declaring `servers:` at the top level would load, generate no
    # MCP cases, and report a clean run against a server it never contacted.
    # `load_matrix` names the relocated keys specifically; this catches the rest,
    # including a typo and a programmatic caller passing the old keyword.
    model_config = ConfigDict(extra="forbid")

    # Roles from least to most privileged; used to classify privilege escalation.
    roles: List[str] = Field(default_factory=list)
    subjects: List[Subject]
    resources: List[Resource]
    policy: Dict[str, ResourcePolicy] = Field(default_factory=dict)
    # Per-surface configuration; see Modules.
    modules: Modules = Field(default_factory=Modules)
    # Providers used to obtain subject tokens dynamically before a run.
    auth: AuthConfig = Field(default_factory=AuthConfig)
    # Requests run once before the suite to create fixtures / capture object ids.
    setup: List[SetupStep] = Field(default_factory=list)
    # Requests run once after the suite (best-effort) to clean up fixtures the
    # setup steps created. Can reference {{captures}} from setup.
    teardown: List[SetupStep] = Field(default_factory=list)
    # How many victims each subject probes on an object resource. "one" (the
    # default) sends a single cross-owner probe per subject — cheap, and enough
    # to catch a check that is missing outright. "all" probes every distinct
    # object, which is what finds a check that holds for some owners and not
    # others, at a cost that grows with the number of subjects. A resource may
    # override it.
    probe_victims: Literal["one", "all"] = "one"

    # Read accessors for the module-scoped settings. The call sites that use
    # them are being moved module by module; until then these keep one concept
    # in one place rather than spreading `matrix.modules.mcp.probes.x` through
    # code that is about to be relocated anyway.
    @property
    def base_url(self) -> Optional[str]:
        return self.modules.rest.base_url

    @property
    def access(self) -> ResponseMatcher:
        return self.modules.rest.access

    @property
    def servers(self) -> List[McpServer]:
        return self.modules.mcp.servers

    @property
    def mcp_access(self) -> McpMatcher:
        return self.modules.mcp.access

    @property
    def probe_token_audience(self) -> bool:
        return self.modules.mcp.probes.token_audience

    @property
    def probe_session_binding(self) -> bool:
        return self.modules.mcp.probes.session_binding

    @property
    def probe_tool_enumeration(self) -> bool:
        return self.modules.mcp.probes.tool_enumeration

    def victims_for(self, resource: Resource) -> str:
        """The effective probe_victims setting for one resource."""
        return resource.probe_victims or self.probe_victims

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

    def _validate_injections(self, res: Resource) -> List[Problem]:
        """Check a resource's object-identifier injections for coherence.

        Ensures MCP resources use ``mcp_argument`` (and HTTP resources don't),
        that path injections name a real path parameter, and that ownership can
        actually be resolved — an unresolvable default object would make the probe
        silently skip rather than fall back to a placeholder.

        The coherence checks are errors: an injection pointing at a path
        parameter that does not exist cannot be delivered. The two ownership
        checks are warnings — the resource is still tested, it just loses its
        cross-owner probe, which is a smaller matrix rather than a wrong one.
        """
        problems: List[Problem] = []
        injections = res.effective_injections()
        path_params = (
            set(_PATH_PARAM_RE.findall(res.request.path)) if res.request else set()
        )
        uri_params = (
            set(_PATH_PARAM_RE.findall(res.read.uri)) if res.read else set()
        )
        # Which location the object identifier may live in follows from what the
        # resource actually sends: a tool-call has arguments, a resource-read has
        # a URI, and an HTTP request has neither.
        mcp_locations = {
            OwnershipLocation.MCP_ARGUMENT,
            OwnershipLocation.MCP_RESOURCE_URI,
        }
        for inj in injections:
            is_mcp = inj.location in mcp_locations
            if res.transport == "mcp" and not is_mcp:
                expected = "mcp_resource_uri" if res.read is not None else "mcp_argument"
                problems.append(Problem(
                    f"mcp resource '{res.name}' injection must use location "
                    f"'{expected}', not '{inj.location.value}'"
                ))
            elif res.transport != "mcp" and is_mcp:
                problems.append(Problem(
                    f"http resource '{res.name}' cannot use an '{inj.location.value}' injection"
                ))
            elif inj.location == OwnershipLocation.MCP_ARGUMENT and res.read is not None:
                problems.append(Problem(
                    f"resource '{res.name}' reads a resource, so its object identifier "
                    f"lives in the URI: use location 'mcp_resource_uri', not "
                    f"'mcp_argument'"
                ))
            elif inj.location == OwnershipLocation.MCP_RESOURCE_URI and res.call is not None:
                problems.append(Problem(
                    f"resource '{res.name}' calls a tool, so its object identifier "
                    f"lives in an argument: use location 'mcp_argument', not "
                    f"'mcp_resource_uri'"
                ))
            if inj.location == OwnershipLocation.PATH and res.request and inj.selector not in path_params:
                problems.append(Problem(
                    f"resource '{res.name}' path injection '{inj.selector}' is not a "
                    f"parameter in path '{res.request.path}'"
                ))
            if (
                inj.location == OwnershipLocation.MCP_RESOURCE_URI
                and res.read is not None
                and inj.selector not in uri_params
            ):
                # Without the placeholder nothing is substituted, so every subject
                # would read the same fixed URI — a cross-owner probe in name only.
                problems.append(Problem(
                    f"resource '{res.name}' uri injection '{inj.selector}' is not a "
                    f"placeholder in uri '{res.read.uri}'"
                ))

        # No placeholder for ownership: warn when no subject can supply a value for
        # every injection (whether it reads the default object or an override
        # attribute), so probes are never silently skipped or half-populated.
        def _object_values(subject) -> Optional[tuple]:
            """What this subject writes to identify its object, or None."""
            values = []
            for inj in injections:
                if inj.owner_attr is not None:
                    value = subject.attributes.get(inj.owner_attr)
                else:
                    value = res.objects.get(
                        subject.name, subject.attributes.get(res.owner_attr)
                    )
                if value is None:
                    return None
                values.append(str(value))
            return tuple(values)

        if injections:
            resolved = [v for v in map(_object_values, self.subjects) if v is not None]
            if not resolved:
                attrs = sorted({inj.owner_attr or res.owner_attr for inj in injections})
                problems.append(Problem(
                    f"object resource '{res.name}' has no subject with a resolvable "
                    f"object (add an 'objects:' entry or attribute(s): {', '.join(attrs)}); "
                    f"ownership probes will be skipped",
                    Severity.WARNING,
                ))
            elif len(set(resolved)) < 2:
                # Every subject that can reach this resource points at the same
                # object, so an "other" probe would re-send the subject's own
                # request and prove nothing. The planner drops it; say why.
                shared = ", ".join(resolved[0])
                problems.append(Problem(
                    f"object resource '{res.name}' has no two subjects with different "
                    f"objects (all resolve to {shared}), so no cross-owner BOLA probe "
                    f"can be generated; give at least two subjects distinct objects",
                    Severity.WARNING,
                ))
        return problems

    def validate_refs(self) -> List[str]:
        """Every problem as a plain string, worst first; empty means the matrix is ok.

        Kept as the stable, severity-free view for callers that only want to
        know whether anything is wrong. Use :meth:`diagnose` to tell an error
        from a warning.
        """
        return [str(p) for p in self.diagnose()]

    def diagnose(self) -> List[Problem]:
        """Every structural problem with the matrix, errors first.

        Ordering puts errors ahead of warnings so the thing that has to be
        fixed is the first thing printed, however long the list is.
        """
        problems = self._collect_problems()
        return sorted(problems, key=lambda p: p.severity is not Severity.ERROR)

    def _collect_problems(self) -> List[Problem]:
        problems: List[Problem] = []

        def error(message: str) -> None:
            problems.append(Problem(message, Severity.ERROR))

        def warn(message: str) -> None:
            problems.append(Problem(message, Severity.WARNING))

        rmap = self.resource_map()
        subject_names = [s.name for s in self.subjects]

        if len(subject_names) != len(set(subject_names)):
            error("duplicate subject names are not allowed")
        if len(rmap) != len(self.resources):
            error("duplicate resource names are not allowed")

        for name in self.policy:
            if name not in rmap:
                error(f"policy references unknown resource '{name}'")

        # A resource's module is read off its body, so it can no longer name a
        # transport that does not exist, nor declare one that disagrees with what
        # it sends. What remains is a body that says nothing, or two that
        # contradict each other.
        server_names = {s.name for s in self.servers}
        for srv in self.servers:
            if not srv.url and not srv.command:
                error(f"server '{srv.name}' must set a url (http) or a command (stdio)")
        for res in self.resources:
            bodies = [k for k in ("request", "call", "read") if getattr(res, k) is not None]
            if not bodies:
                error(
                    f"resource '{res.name}' declares no request: set a 'request' "
                    f"(rest), or a 'call' or 'read' (mcp)"
                )
                continue
            if len(bodies) > 1:
                error(
                    f"resource '{res.name}' sets {' and '.join(bodies)}; a resource "
                    f"makes one kind of request, and which one decides its module"
                )
                continue
            if res.transport == "mcp":
                referenced = res.call.server if res.call else res.read.server
                if referenced not in server_names:
                    error(
                        f"mcp resource '{res.name}' references unknown server "
                        f"'{referenced}'"
                    )
                if res.type == ResourceType.OBJECT and not res.is_object_locatable:
                    place = "URI placeholder" if res.read is not None else "tool argument"
                    error(
                        f"mcp object resource '{res.name}' must set 'owner' (the "
                        f"{place} carrying the object id) or ownership.injections"
                    )
            else:
                if res.type == ResourceType.OBJECT and not res.is_object_locatable:
                    error(
                        f"object resource '{res.name}' must set 'owner' (the path "
                        f"parameter carrying the object id) or ownership.injections"
                    )
            problems.extend(self._validate_injections(res))
            if res.name not in self.policy:
                # Deny-by-default is a legitimate stance — the OpenAPI scaffold
                # takes it deliberately for specs that describe no auth — so an
                # absent entry over-reports rather than mistests. Worth saying,
                # not worth failing on.
                warn(
                    f"resource '{res.name}' has no policy entry (everything will be denied)"
                )

        known_roles = set(self.role_order())
        for name, pol in self.policy.items():
            for rule in pol.allow:
                if rule.role not in known_roles:
                    error(
                        f"policy for '{name}' allows unknown role '{rule.role}'"
                    )

        provider_names = {p.name for p in self.auth.providers}
        for provider in self.auth.providers:
            if provider.type.startswith("oauth2") and not provider.token_url and not provider.discover_from:
                error(
                    f"auth provider '{provider.name}' needs a token_url or discover_from"
                )
            if provider.discover_from and "://" not in provider.discover_from \
                    and provider.discover_from not in server_names:
                error(
                    f"auth provider '{provider.name}' discover_from references unknown "
                    f"server '{provider.discover_from}'"
                )
            if provider.discover_from and not provider.issuer \
                    and (provider.client_secret or provider.password):
                # Discovery is driven by the server under test: it names the
                # authorization server, whose metadata names the URL this secret
                # is posted to. Validating that metadata catches an authorization
                # server impersonating another, but not one the target simply
                # owns and names honestly. Only a pinned issuer refuses that, so
                # a run without one is weaker than it looks — which is what a
                # warning is for.
                warn(
                    f"auth provider '{provider.name}' discovers its token endpoint from "
                    f"'{provider.discover_from}' and sends a secret, but pins no issuer — "
                    f"set 'issuer' to the authorization server these credentials were "
                    f"registered with, or that server chooses where they are sent"
                )
        for subject in self.subjects:
            if subject.auth and subject.auth.provider not in provider_names:
                error(
                    f"subject '{subject.name}' uses unknown auth provider "
                    f"'{subject.auth.provider}'"
                )
            audience = subject.token_audience
            if (
                audience
                and "://" not in audience
                and audience not in server_names
            ):
                # A bare word is meant to be a server name. Typoed, it silently
                # matches no server, so the credential is replayed at every one
                # of them — including the server it was actually issued for,
                # which reports a finding for a token doing its job.
                error(
                    f"subject '{subject.name}' has token_audience '{audience}', which is "
                    f"neither a declared server nor a URI; use a name from 'servers:' "
                    f"or the audience URI the token was issued for"
                )

        subject_set = set(subject_names)
        for phase, steps in (("setup", self.setup), ("teardown", self.teardown)):
            for step in steps:
                label = step.name or (step.call.tool if step.call else (step.request.path if step.request else "?"))
                if step.run_as and step.run_as not in subject_set:
                    error(
                        f"{phase} step '{label}' runs as unknown subject '{step.run_as}'"
                    )
                if step.call is None and step.request is None:
                    error(f"{phase} step '{label}' must set a 'request' or a 'call'")
                if step.call is not None and step.call.server not in server_names:
                    error(
                        f"{phase} step '{label}' references unknown server '{step.call.server}'"
                    )
        for res in self.resources:
            for sub_name in res.objects:
                if sub_name not in subject_set:
                    error(
                        f"resource '{res.name}' declares an object for unknown "
                        f"subject '{sub_name}'"
                    )
        return problems


def load_matrix(path: str, env=None) -> Matrix:
    try:
        data = read_yaml(path, "matrix") or {}
    except DocumentError as exc:
        raise MatrixError(str(exc)) from exc
    # Resolve ${ENV} references before building the model so secrets stay out of
    # the committed file.
    try:
        data = interpolate(data, env)
    except InterpolationError as exc:
        raise MatrixError(f"could not load matrix '{path}': {exc}") from exc
    _reject_relocated_keys(path, data)
    try:
        return Matrix(**data)
    except Exception as exc:  # pydantic ValidationError, etc.
        raise MatrixError(f"could not parse matrix '{path}': {exc}") from exc


def _reject_relocated_keys(path: str, data: dict) -> None:
    """Refuse a matrix written against the flat layout, and say where each key went.

    Pydantic ignores keys it does not know, which is the worst possible outcome
    here: a matrix still declaring `servers:` would load, generate no MCP cases,
    and report a clean run against a server it never contacted. Every relocated
    key is therefore an error naming its new home, so an out-of-date file is a
    two-minute edit rather than a silent false negative.
    """
    if not isinstance(data, dict):
        return
    stale = [key for key in RELOCATED_KEYS if key in data]
    if not stale:
        return
    moves = "\n".join(f"  {key}: -> {RELOCATED_KEYS[key]}" for key in stale)
    raise MatrixError(
        f"matrix '{path}' uses the flat layout; these keys are now per-module:\n"
        f"{moves}\n"
        f"Configuration that applies to one surface lives under 'modules:'; "
        f"subjects, resources and policy stay at the top level."
    )
