"""Waivers: accept known findings without turning off CI gating.

A real security programme has to record *accepted risk* — a finding a team has
reviewed and consciously chosen to live with — without either failing the
pipeline forever or silencing the whole tool. A waiver names a finding (by its
stable ``test_id``, optionally narrowed to a vulnerability class), a mandatory
``reason``, and an optional ``expires`` date. Matching findings are moved out of
the gating set and into a separate "waived" list that still shows in reports.

Waivers deliberately *expire*: an expired waiver stops suppressing its finding
and emits a warning, so accepted risk is re-reviewed instead of rotting silently.
This is kept distinct from a drift baseline (which pins the whole decision
surface) — a waiver is a per-finding, human-authored exception.
"""
from __future__ import annotations

import datetime
from typing import List, Optional, Set, Tuple

from pydantic import BaseModel, ValidationError, field_validator

from overstep.documents import DocumentError, read_yaml
from overstep.models import Finding


class WaiverError(ValueError):
    """Raised when a waivers file is structurally invalid."""


class Waiver(BaseModel):
    """One accepted-risk exception."""

    id: str                              # the finding's test_id
    reason: str                          # why this is accepted (mandatory)
    vuln_class: Optional[str] = None     # narrow to a single VulnClass value
    expires: Optional[str] = None        # ISO date (YYYY-MM-DD); None = permanent

    @field_validator("expires", mode="before")
    @classmethod
    def _coerce_date(cls, value):
        # YAML parses an unquoted ISO date into a datetime.date; normalize to str.
        if isinstance(value, (datetime.date, datetime.datetime)):
            return value.isoformat()
        return value

    def is_expired(self, today: Optional[datetime.date] = None) -> bool:
        if not self.expires:
            return False
        today = today or datetime.date.today()
        try:
            return datetime.date.fromisoformat(self.expires) < today
        except ValueError as exc:
            raise WaiverError(f"waiver for '{self.id}' has an invalid expires date: {self.expires}") from exc

    def matches(self, finding: Finding) -> bool:
        if finding.test_id != self.id:
            return False
        if self.vuln_class and finding.vuln_class.value != self.vuln_class:
            return False
        return True


def load_waivers(path: str) -> List[Waiver]:
    """Parse a waivers YAML file into a list of :class:`Waiver`."""
    try:
        doc = read_yaml(path, "waivers file") or {}
    except DocumentError as exc:
        raise WaiverError(str(exc)) from exc
    raw = doc.get("waivers", doc if isinstance(doc, list) else [])
    if not isinstance(raw, list):
        raise WaiverError("waivers file must contain a 'waivers:' list")
    waivers: List[Waiver] = []
    for i, entry in enumerate(raw):
        try:
            waivers.append(Waiver(**entry))
        except (ValidationError, TypeError) as exc:
            raise WaiverError(f"waiver #{i + 1} is invalid: {exc}") from exc
    return waivers


def apply_waivers(
    findings: List[Finding],
    waivers: List[Waiver],
    *,
    today: Optional[datetime.date] = None,
    report_unmatched: bool = True,
) -> Tuple[List[Finding], List[Finding], List[str]]:
    """Split findings into (active, waived) and collect warnings.

    A finding is waived only by a *matching, non-expired* waiver. Expired waivers
    leave their finding active and produce a warning so the acceptance is renewed.

    A waiver that matches *nothing* is warned about too. It is not dangerous —
    the finding it was aimed at stays active and still fails the gate, which is
    the safe direction — but it is silent, and silence is the wrong answer to
    either of the two things it means. Either the ``id`` is a typo and the risk
    somebody accepted is not actually accepted, or the finding was fixed and the
    waiver is now an accepted risk with nothing behind it, sitting in version
    control until somebody re-reads it and believes it.

    ``report_unmatched`` exists for the run that proved nothing. When the target
    was unreachable there are no findings for any waiver to match, and saying
    each one may be fixed would be the tool asserting something it did not
    observe — on top of a verdict that already says so plainly.
    """
    active: List[Finding] = []
    waived: List[Finding] = []
    warnings: List[str] = []
    # Deduplicated on the message, since that is what a reader would see twice.
    seen_expired: Set[str] = set()
    # Positions, not ids. Two entries can share an `id` and differ by
    # `vuln_class` — one test_id really can carry two findings, a BOLA and the
    # authorization-drift on the same case — so keying by id would let a
    # matching entry vouch for a mistyped one beside it, which is the exact
    # silence this function was extended to remove.
    matched: Set[int] = set()

    for finding in findings:
        suppressor: Optional[Waiver] = None
        for index, waiver in enumerate(waivers):
            if not waiver.matches(finding):
                continue
            # Recorded for every match, not just the one that suppresses: an
            # entry that matched and was passed over — because it expired, or
            # because an earlier one already covered the finding — did find its
            # finding, and calling it unmatched would be false.
            matched.add(index)
            if waiver.is_expired(today):
                message = (
                    f"waiver for '{waiver.id}' expired on {waiver.expires}; "
                    f"the finding is active again — review and renew it."
                )
                if message not in seen_expired:
                    warnings.append(message)
                    seen_expired.add(message)
                continue
            if suppressor is None:
                suppressor = waiver
        if suppressor is not None:
            waived.append(finding)
        else:
            active.append(finding)

    for index, waiver in enumerate(waivers if report_unmatched else ()):
        if index in matched:
            continue
        # Name the scope when there is one: two entries can share an id, and a
        # message identifying only the id would not say which is wrong.
        scope = f" (vuln_class: {waiver.vuln_class})" if waiver.vuln_class else ""
        warnings.append(
            f"waiver for '{waiver.id}'{scope} matched no finding — either the id "
            f"is wrong and the risk is not actually waived, or the finding is "
            f"fixed and the waiver should be removed."
        )

    return active, waived, warnings
