"""Execute test cases against a live target and record what happened.

The executor is deliberately dumb: it fires each request with the right subject's
credentials and records the status/effect. It makes no judgements — deciding
whether an observation is a problem is the classifier's job. Requests run
concurrently with a bounded semaphore so a large matrix stays fast without
hammering the target.
"""
from __future__ import annotations

import asyncio
import time
from typing import Dict, List, Optional
from urllib.parse import urljoin

import httpx

from overstep.models import ALLOW_STATUSES, Effect, Observation, Subject, TestCase


def _effect_for(status: int) -> Effect:
    return Effect.ALLOW if status in ALLOW_STATUSES else Effect.DENY


def build_headers(subject: Subject, case: TestCase) -> Dict[str, str]:
    """Assemble the headers for one request.

    Precedence, lowest to highest:
      1. the resource's own headers (carried on the test case),
      2. the subject's headers (override per identity),
      3. a bearer ``Authorization`` derived from the subject's token — but only
         if neither of the above already set an ``Authorization`` header, so a
         custom auth scheme is never clobbered.
    """
    headers: Dict[str, str] = {}
    headers.update(case.headers)
    headers.update(subject.headers)

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
) -> Observation:
    url = urljoin(base_url if base_url.endswith("/") else base_url + "/", case.path.lstrip("/"))
    async with semaphore:
        started = time.perf_counter()
        try:
            resp = await client.request(
                case.method,
                url,
                headers=build_headers(subject, case) or None,
                params=case.query or None,
                json=case.body,
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

        elapsed = (time.perf_counter() - started) * 1000
        body = resp.text[:2048]
        return Observation(
            test_id=case.id,
            status=resp.status_code,
            effect=_effect_for(resp.status_code),
            latency_ms=round(elapsed, 1),
            headers=dict(resp.headers),
            body_snippet=body,
        )


async def execute(
    base_url: str,
    subjects: List[Subject],
    cases: List[TestCase],
    *,
    concurrency: int = 10,
    timeout: float = 15.0,
    verify_tls: bool = True,
) -> List[Observation]:
    """Run every test case and return one observation per case."""
    subject_map: Dict[str, Subject] = {s.name: s for s in subjects}
    semaphore = asyncio.Semaphore(concurrency)

    async with httpx.AsyncClient(timeout=timeout, verify=verify_tls, follow_redirects=False) as client:
        tasks = [
            _fire(client, base_url, subject_map[c.subject], c, semaphore)
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
        )
    )
