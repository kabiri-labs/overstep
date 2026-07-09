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
from typing import Dict, List, Optional, Tuple

import yaml
from pydantic import BaseModel, ValidationError, field_validator

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
    with open(path, "r", encoding="utf-8") as f:
        doc = yaml.safe_load(f) or {}
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
) -> Tuple[List[Finding], List[Finding], List[str]]:
    """Split findings into (active, waived) and collect warnings.

    A finding is waived only by a *matching, non-expired* waiver. Expired waivers
    leave their finding active and produce a warning so the acceptance is renewed.
    """
    active: List[Finding] = []
    waived: List[Finding] = []
    warnings: List[str] = []
    seen_expired: Dict[str, bool] = {}

    for finding in findings:
        suppressor: Optional[Waiver] = None
        for waiver in waivers:
            if not waiver.matches(finding):
                continue
            if waiver.is_expired(today):
                if not seen_expired.get(waiver.id):
                    warnings.append(
                        f"waiver for '{waiver.id}' expired on {waiver.expires}; "
                        f"the finding is active again — review and renew it."
                    )
                    seen_expired[waiver.id] = True
                continue
            suppressor = waiver
            break
        if suppressor is not None:
            waived.append(finding)
        else:
            active.append(finding)

    return active, waived, warnings
