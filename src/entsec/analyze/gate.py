"""The gate: every model claim is checked against the declared intake.

A language model asked to review a design will, on a bad day, warn about an
integration nobody mentioned, cite a control identifier that does not exist, and
write both in the same register as its correct findings. In a design review that
is worse than in a code review, because the reader is often not a security
engineer and has no way to tell -- and the finding goes to another team as a
condition they must satisfy.

So the model may only cite two things: intake facts that a requester actually
declared, and control ids that exist in the catalog. Anything else is dropped
before a human sees it, and the drop is counted.

Two further checks exist to stop inflation rather than invention, because a real
finding with an exaggerated rating loses trust just as fast as a fabricated one:
exposure cannot exceed the widest user population declared, and data at risk
cannot exceed the most sensitive class declared. A model cannot make a system
scarier than its own intake says it is.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..controls.catalog import CONTROLS_BY_ID, known_control_ids
from ..models import DataClass, Finding, Framework, Intake, Severity, UserPopulation
from ..validation import safe_text
from .severity import rate

_MAX_CHAIN = 10
_MAX_PRECONDITIONS = 6


@dataclass(frozen=True, slots=True)
class Rejection:
    """A finding the gate refused, and why. Shown by --explain-drops."""

    title: str
    reason: str


def _as_list(value: object) -> list[Any]:
    """Coerce a model-supplied field without trusting its type.

    Slicing a dict raises TypeError and calling .get on a string raises
    AttributeError. Either crashed the gate, and a crash that the CLI reports as
    "found something" is indistinguishable from a real finding.
    """
    return list(value) if isinstance(value, list) else []


def _coerce_population(value: object, ceiling: UserPopulation) -> UserPopulation:
    try:
        claimed = UserPopulation(str(value).strip().casefold())
    except ValueError:
        # Unrecognised means unknown, and unknown must not default to the most
        # alarming option. The declared ceiling can only lower it further.
        claimed = UserPopulation.EMPLOYEES
    return claimed if claimed.rank <= ceiling.rank else ceiling


def _coerce_data(value: object, ceiling: DataClass) -> DataClass:
    try:
        claimed = DataClass(str(value).strip().casefold())
    except ValueError:
        claimed = DataClass.INTERNAL
    return claimed if claimed.rank <= ceiling.rank else ceiling


def validate(
    raw: dict[str, Any], intake: Intake, index: int
) -> tuple[Finding | None, Rejection | None]:
    """Turn one model-supplied dict into a trusted Finding, or reject it."""
    title = safe_text(raw.get("title") or "", limit=160)
    if not title:
        return None, Rejection("(untitled)", "no title")

    fact_ids = tuple(
        safe_text(f, limit=80) for f in _as_list(raw.get("fact_ids")) if str(f).strip()
    )
    if not fact_ids:
        return None, Rejection(title, "cited no intake facts, so nothing about it can be checked")

    known_facts = intake.fact_ids()
    unknown = [f for f in fact_ids if f not in known_facts]
    if unknown:
        # The core check. A finding resting on something the requester never
        # declared is a finding about a different system.
        return None, Rejection(
            title,
            f"cites intake fact(s) that were never declared: {', '.join(unknown[:4])}",
        )

    control_ids = tuple(
        safe_text(c, limit=40) for c in _as_list(raw.get("control_ids")) if str(c).strip()
    )
    valid_controls = known_control_ids()
    bad_controls = [c for c in control_ids if c not in valid_controls]
    if bad_controls:
        # An invented control reference is the most damaging kind of error here:
        # it survives into a ticket, into a GRC tracker, and into an audit
        # conversation where somebody looks it up and finds nothing.
        return None, Rejection(
            title,
            f"cites control id(s) that are not in the catalog: {', '.join(bad_controls[:4])}",
        )

    chain = tuple(
        safe_text(step, limit=200)
        for step in _as_list(raw.get("chain"))[:_MAX_CHAIN]
        if str(step).strip()
    )
    if not chain:
        return None, Rejection(title, "described no chain, so it is a label rather than a risk")

    preconditions = tuple(
        safe_text(p, limit=200)
        for p in _as_list(raw.get("preconditions"))[:_MAX_PRECONDITIONS]
        if str(p).strip()
    )

    exposed = _coerce_population(raw.get("exposed_to"), intake.max_population())
    data = _coerce_data(raw.get("data_at_risk"), intake.max_data_class())

    frameworks: list[Framework] = []
    for control_id in control_ids:
        entry = CONTROLS_BY_ID.get(control_id)
        if entry:
            frameworks.extend(entry.frameworks)

    return (
        Finding(
            id=f"F-{index:02d}",
            title=title,
            chain=chain,
            severity=rate(exposed, data, len(preconditions)),
            data_at_risk=data,
            exposed_to=exposed,
            fact_ids=fact_ids,
            control_ids=control_ids,
            frameworks=tuple(dict.fromkeys(frameworks)),
            preconditions=preconditions,
            condition=safe_text(raw.get("condition") or "", limit=600),
            because=safe_text(raw.get("because") or "", limit=400),
        ),
        None,
    )


def apply(raw_findings: object, intake: Intake) -> tuple[list[Finding], list[Rejection]]:
    """Validate everything the model returned. Returns (kept, rejected)."""
    kept: list[Finding] = []
    rejected: list[Rejection] = []
    seen: set[str] = set()

    for raw in _as_list(raw_findings):
        if not isinstance(raw, dict):
            rejected.append(Rejection("(malformed)", "not an object"))
            continue
        finding, rejection = validate(raw, intake, len(kept) + 1)
        if rejection or finding is None:
            rejected.append(rejection or Rejection("(unknown)", "failed validation"))
            continue
        key = finding.dedup_key()
        if key in seen:
            rejected.append(Rejection(finding.title, "duplicate of an earlier finding"))
            continue
        seen.add(key)
        kept.append(finding)

    kept.sort(key=lambda f: (-f.severity.rank, f.title))
    return [_renumber(f, i + 1) for i, f in enumerate(kept)], rejected


def _renumber(finding: Finding, index: int) -> Finding:
    """Renumber after sorting, so F-01 is the worst thing in the review."""
    return Finding(
        id=f"F-{index:02d}",
        title=finding.title,
        chain=finding.chain,
        severity=finding.severity,
        data_at_risk=finding.data_at_risk,
        exposed_to=finding.exposed_to,
        fact_ids=finding.fact_ids,
        control_ids=finding.control_ids,
        frameworks=finding.frameworks,
        preconditions=finding.preconditions,
        condition=finding.condition,
        because=finding.because,
    )


def worst(findings: list[Finding]) -> Severity | None:
    return max((f.severity for f in findings), default=None)
