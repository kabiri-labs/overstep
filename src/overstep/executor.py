"""Execute test cases against a live target and record what happened.

The executor is deliberately dumb: it fires each request with the right subject's
credentials and records the status/effect. It makes no judgements — deciding
whether an observation is a problem is the classifier's job. Requests run
concurrently with a bounded semaphore so a large matrix stays fast without
hammering the target.
"""
from __future__ import annotations

import asyncio
import random
import time
from typing import Dict, List, Optional
from urllib.parse import urljoin

import httpx

from overstep.matching import evaluate
from overstep.models import Effect, Observation, Subject, TestCase

# Verbs that change server state; skipped under read-only mode.
MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
# Statuses worth retrying: rate limiting and transient upstream unavailability.
RETRY_STATUSES = frozenset({429, 503})


def _retry_delay(resp: httpx.Response, attempt: int, backoff_base: float) -> float:
    """Seconds to wait before the next attempt, honouring Retry-After if present."""
    retry_after = resp.headers.get("Retry-After")
    if retry_after is not None:
        try:
            return max(0.0, float(retry_after))
        except ValueError:
            pass
    # Exponential backoff with full jitter.
    return backoff_base * (2 ** attempt) * (0.5 + random.random())


def _find_header(headers: Dict[str, str], name: str) -> Optional[str]:
    """The value of a header matched case-insensitively, or None."""
    for key, value in headers.items():
        if key.lower() == name:
            return value
    return None


def _merge_cookie_values(*values: Optional[str]) -> str:
    """Merge one or more Cookie header strings into a single value."""
    jar: Dict[str, str] = {}
    for value in values:
        if not value:
            continue
        for part in value.split(";"):
            part = part.strip()
            if not part:
                continue
            key, _, val = part.partition("=")
            jar[key.strip()] = val.strip()
    return "; ".join(f"{k}={v}" for k, v in jar.items())


def build_headers(subject: Subject, case: TestCase) -> Dict[str, str]:
    """Assemble the headers for one request.

    Precedence, lowest to highest:
      1. the resource's own headers (carried on the test case),
      2. the subject's headers (override per identity),
      3. a bearer ``Authorization`` derived from the subject's token — but only
         if neither of the above already set an ``Authorization`` header, so a
         custom auth scheme is never clobbered.

    The ``Cookie`` header is the exception to (2): the case's cookie (e.g. an
    object-id ownership injection) is *merged* with the subject's session cookie
    rather than overwritten, so a BOLA probe still carries the injected id when
    the subject authenticates with a cookie.
    """
    case_cookie = _find_header(case.headers, "cookie")
    subject_cookie = _find_header(subject.headers, "cookie")

    headers: Dict[str, str] = {}
    headers.update(case.headers)
    headers.update(subject.headers)

    if case_cookie and subject_cookie:
        for key in [k for k in list(headers) if k.lower() == "cookie"]:
            del headers[key]
        headers["Cookie"] = _merge_cookie_values(case_cookie, subject_cookie)

    has_auth = any(k.lower() == "authorization" for k in headers)
    if subject.token and not has_auth:
        headers["Authorization"] = f"Bearer {subject.token}"
    return headers


async def _fire(
    client: httpx.AsyncClient,
    base_url: str,
    subject: Subject,
    case: TestCase,
    semaphore: asyncio.Semaphore,
    *,
    read_only: bool = False,
    max_retries: int = 0,
    backoff_base: float = 0.5,
) -> Observation:
    # Read-only mode never sends a state-changing request against a live target.
    if read_only and case.method.upper() in MUTATING_METHODS:
        return Observation(
            test_id=case.id,
            status=0,
            effect=Effect.DENY,
            skipped=True,
            error=f"skipped {case.method} under --read-only",
        )

    url = urljoin(base_url if base_url.endswith("/") else base_url + "/", case.path.lstrip("/"))
    async with semaphore:
        started = time.perf_counter()
        resp = None
        for attempt in range(max_retries + 1):
            try:
                # A form body (application/x-www-form-urlencoded) takes precedence
                # over a JSON body; a resource sets one or the other.
                request_kwargs = (
                    {"data": case.form} if case.form else {"json": case.body}
                )
                resp = await client.request(
                    case.method,
                    url,
                    headers=build_headers(subject, case) or None,
                    params=case.query or None,
                    **request_kwargs,
                )
            except httpx.HTTPError as exc:
                elapsed = (time.perf_counter() - started) * 1000
                # A transport error means the subject did not get through -> denied.
                return Observation(
                    test_id=case.id,
                    status=0,
                    effect=Effect.DENY,
                    latency_ms=round(elapsed, 1),
                    error=str(exc),
                )
            # Back off and retry on rate-limit / transient-unavailable statuses.
            if resp.status_code in RETRY_STATUSES and attempt < max_retries:
                await asyncio.sleep(_retry_delay(resp, attempt, backoff_base))
                continue
            break

        elapsed = (time.perf_counter() - started) * 1000
        full_body = resp.text
        # Match against the full body (error markers may be anywhere) but only
        # keep a snippet as evidence.
        effect = evaluate(case.matcher, resp.status_code, full_body)
        # Content-aware oracle: did the victim's data actually come back?
        matched = [m for m in case.expect_markers if m and m in full_body]
        return Observation(
            test_id=case.id,
            status=resp.status_code,
            effect=effect,
            latency_ms=round(elapsed, 1),
            headers=dict(resp.headers),
            body_snippet=full_body[:2048],
            matched_markers=matched,
        )


async def execute(
    base_url: str,
    subjects: List[Subject],
    cases: List[TestCase],
    *,
    concurrency: int = 10,
    timeout: float = 15.0,
    verify_tls: bool = True,
    read_only: bool = False,
    max_retries: int = 0,
    backoff_base: float = 0.5,
) -> List[Observation]:
    """Run every test case and return one observation per case."""
    subject_map: Dict[str, Subject] = {s.name: s for s in subjects}
    semaphore = asyncio.Semaphore(concurrency)

    async with httpx.AsyncClient(timeout=timeout, verify=verify_tls, follow_redirects=False) as client:
        tasks = [
            _fire(
                client,
                base_url,
                subject_map[c.subject],
                c,
                semaphore,
                read_only=read_only,
                max_retries=max_retries,
                backoff_base=backoff_base,
            )
            for c in cases
        ]
        return await asyncio.gather(*tasks)


def run(
    base_url: str,
    subjects: List[Subject],
    cases: List[TestCase],
    *,
    concurrency: int = 10,
    timeout: float = 15.0,
    verify_tls: bool = True,
    read_only: bool = False,
    max_retries: int = 0,
    backoff_base: float = 0.5,
) -> List[Observation]:
    """Synchronous wrapper around :func:`execute`."""
    return asyncio.run(
        execute(
            base_url,
            subjects,
            cases,
            concurrency=concurrency,
            timeout=timeout,
            verify_tls=verify_tls,
            read_only=read_only,
            max_retries=max_retries,
            backoff_base=backoff_base,
        )
    )
