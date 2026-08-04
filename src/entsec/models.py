"""The review model: what was declared, what applies, and what was decided.

An enterprise design review is not a code review. Marketing wants a webinar
platform, IT wants a new MDM, Finance wants a SaaS vendor wired into the ERP --
and in most of those cases there is no repository to read. What there is, is an
intake form somebody filled in and a design document somebody wrote.

That changes where certainty comes from. A code scanner earns its authority by
parsing what is actually there. Here, the authority comes from the *questionnaire*:
a structured set of declared facts, each with an id, that the analysis may cite
and nothing else. The model cannot invent an integration that was never declared
any more than it could invent a function that was never written.

Three layers, in decreasing order of how much you should trust them:

1. **Declared facts** (:class:`Intake`) -- what the requesting team said. Not
   verified, but attributable: every one carries the question it answered, so a
   wrong answer is the requester's to correct rather than a mystery.
2. **Computed applicability and gaps** (:mod:`entsec.controls`) -- which control
   objectives are in scope given those facts, and which the answers do not
   satisfy. Pure functions over the intake; no model involved.
3. **Reasoned findings** (:class:`Finding`) -- attack paths and residual risk. The
   model's contribution, constrained to citing facts and controls that exist.

The decision is computed from 2 and 3 together. It is never the model's to make.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class _RankOrdered:
    """Comparison by ``rank`` for the ordered enums below.

    These are ``str`` enums, so without explicit operators they order
    alphabetically -- ``CRITICAL < HIGH`` would be True because "critical" sorts
    first, and ``min()`` over severities would return the worst one.
    ``functools.total_ordering`` cannot help: it only fills in operators a class
    lacks, and ``str`` supplies all four, so it silently adds nothing.
    """

    @property
    def rank(self) -> int:  # pragma: no cover - overridden by each enum
        raise NotImplementedError

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, type(self)):
            return NotImplemented
        return self.rank < other.rank

    def __le__(self, other: object) -> bool:
        if not isinstance(other, type(self)):
            return NotImplemented
        return self.rank <= other.rank

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, type(self)):
            return NotImplemented
        return self.rank > other.rank

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, type(self)):
            return NotImplemented
        return self.rank >= other.rank


class Severity(_RankOrdered, str, Enum):
    """How much a finding matters. Computed, never chosen by the model."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class DataClass(_RankOrdered, str, Enum):
    """What the system handles. The single biggest driver of what applies.

    Ordered by consequence of loss, not by how the business talks about it.
    """

    REGULATED = "regulated"
    """Health, payment card, or anything under a named regime. Drags in
    obligations that are not negotiable by the review."""

    PII = "pii"
    """Identifies a person. Employee data counts, and teams routinely forget
    that when the users are internal."""

    CREDENTIALS = "credentials"
    """Secrets, keys, tokens. Reaching these turns one incident into several."""

    CONFIDENTIAL = "confidential"
    """Commercially sensitive: contracts, pricing, roadmap, source."""

    INTERNAL = "internal"
    PUBLIC = "public"

    @property
    def rank(self) -> int:
        return _DATA_RANK[self]


_DATA_RANK = {
    DataClass.PUBLIC: 0,
    DataClass.INTERNAL: 1,
    DataClass.CONFIDENTIAL: 2,
    DataClass.CREDENTIALS: 3,
    DataClass.PII: 3,
    DataClass.REGULATED: 4,
}


class UserPopulation(_RankOrdered, str, Enum):
    """Who can reach it. The other half of the risk equation.

    An internal-only tool and a customer-facing portal holding the same data are
    not the same review, and treating them alike is why generic checklists get
    ignored.
    """

    PUBLIC = "public"
    """Anyone on the internet, unauthenticated."""

    CUSTOMERS = "customers"
    PARTNERS = "partners"
    CONTRACTORS = "contractors"
    EMPLOYEES = "employees"
    ADMINS = "admins"
    """Operators only."""

    @property
    def rank(self) -> int:
        return _POPULATION_RANK[self]


_POPULATION_RANK = {
    UserPopulation.ADMINS: 0,
    UserPopulation.EMPLOYEES: 1,
    UserPopulation.CONTRACTORS: 2,
    UserPopulation.PARTNERS: 3,
    UserPopulation.CUSTOMERS: 4,
    UserPopulation.PUBLIC: 5,
}


class Hosting(str, Enum):
    """Where it runs, which decides who your controls have to reach."""

    SAAS = "saas"
    """A vendor runs it. Most of your controls become contract terms and
    configuration, not engineering."""

    CLOUD = "cloud"
    """Your cloud account. You own the configuration."""

    ON_PREM = "on_prem"
    HYBRID = "hybrid"
    ENDPOINT = "endpoint"
    """Software installed on employee machines."""


class Decision(str, Enum):
    """The output of a design review.

    A findings list is not a review. Somebody has to say whether this can
    proceed, and under what conditions -- otherwise the requesting team reads a
    document, learns nothing actionable, and ships anyway.
    """

    APPROVED = "approved"
    APPROVED_WITH_CONDITIONS = "approved_with_conditions"
    CHANGES_REQUIRED = "changes_required"
    """The design cannot proceed as described."""

    INSUFFICIENT_INFORMATION = "insufficient_information"
    """Not a rejection. The intake left something material blank, and answering
    it changes the outcome -- so the honest response is to ask rather than to
    guess in either direction."""


class Confidence(str, Enum):
    """How much the review itself should be trusted.

    Surfaced because a review built on a half-filled form and one that had a
    complete design document behind it should not look identical on the page.
    """

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True, slots=True)
class Framework:
    """A control reference in one framework.

    Stored as separate identifier and title so the report can print
    ``ISO 27001 A.5.23 — Information security for use of cloud services``
    without anyone hand-typing it into a finding.
    """

    name: str
    identifier: str
    title: str = ""

    def __str__(self) -> str:
        return f"{self.name} {self.identifier}" + (f" — {self.title}" if self.title else "")

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "identifier": self.identifier, "title": self.title}


@dataclass(frozen=True, slots=True)
class Fact:
    """One declared answer from the intake questionnaire.

    The unit the analysis is allowed to cite. ``source`` records where it came
    from -- the form or a line of the design document -- because a review whose
    conclusions cannot be traced back to what the requester actually said is a
    review nobody can argue with, and one nobody can correct.
    """

    id: str
    question: str
    value: str
    source: str = "intake"
    line: int = 0

    def __str__(self) -> str:
        return f"{self.id}={self.value}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "question": self.question,
            "value": self.value,
            "source": self.source,
            "line": self.line,
        }


@dataclass(frozen=True, slots=True)
class Integration:
    """A connection to another system. Where enterprise risk concentrates.

    Most breaches that reach a corporate environment arrive through something
    that was legitimately connected to something else. An integration is the
    review's most important single fact, which is why it is modelled rather than
    left as free text.
    """

    name: str
    direction: str
    """inbound, outbound, or bidirectional."""

    data_shared: tuple[DataClass, ...] = ()
    auth_method: str = ""
    internal: bool = True
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "direction": self.direction,
            "data_shared": [d.value for d in self.data_shared],
            "auth_method": self.auth_method,
            "internal": self.internal,
            "notes": self.notes,
        }


@dataclass(slots=True)
class Intake:
    """Everything the requesting team declared. The fact base for the review.

    Deliberately shallow and answerable. A questionnaire nobody completes
    produces no reviews at all, which is worse than a questionnaire that misses
    a nuance -- and the unanswered fields are themselves an output, because
    "you did not tell us where the logs go" is a finding.
    """

    system: str = ""
    requesting_team: str = ""
    owner: str = ""
    purpose: str = ""
    stage: str = "proposed"

    data_classes: tuple[DataClass, ...] = ()
    record_volume: str = ""
    data_residency: str = ""
    retention: str = ""

    users: tuple[UserPopulation, ...] = ()
    user_count: str = ""

    hosting: Hosting | None = None
    vendor: str = ""
    vendor_attestations: tuple[str, ...] = ()
    subprocessors: str = ""
    dpa_in_place: bool | None = None

    sso: bool | None = None
    mfa: bool | None = None
    privileged_roles: str = ""
    offboarding: str = ""

    internet_facing: bool | None = None
    network_notes: str = ""

    logging: str = ""
    log_destination: str = ""
    log_retention: str = ""

    integrations: tuple[Integration, ...] = ()

    regulated_regimes: tuple[str, ...] = ()
    exit_plan: str = ""

    facts: list[Fact] = field(default_factory=list)
    unanswered: list[str] = field(default_factory=list)
    """Questions left blank. Each becomes a candidate finding, because in a
    design review an unanswered question is a real gap and not a formatting
    problem -- somebody has to go and find out."""

    document_lines: list[str] = field(default_factory=list)
    source_name: str = ""

    def fact_ids(self) -> set[str]:
        return {f.id for f in self.facts}

    def fact(self, fact_id: str) -> Fact | None:
        for candidate in self.facts:
            if candidate.id == fact_id:
                return candidate
        return None

    def max_data_class(self) -> DataClass:
        return max(self.data_classes, default=DataClass.INTERNAL)

    def max_population(self) -> UserPopulation:
        return max(self.users, default=UserPopulation.EMPLOYEES)

    def is_empty(self) -> bool:
        """True when there is not enough here to review.

        Callers must treat this as could-not-run. A review of an empty form that
        returns no findings is a clean bill of health for a system nobody looked
        at, which is the most dangerous document this tool could produce.
        """
        return not self.system or not self.facts

    def fingerprint(self) -> str:
        """Stable hash of the declared design.

        Prose fields are excluded on purpose: rewording a purpose statement is
        not a design change, and treating it as one would make every re-review
        look like a new system and train the reader to ignore the diff.
        """
        parts = [
            f"system={self.system.casefold()}",
            f"stage={self.stage}",
            f"hosting={self.hosting.value if self.hosting else ''}",
            f"vendor={self.vendor.casefold()}",
            f"data={','.join(sorted(d.value for d in self.data_classes))}",
            f"users={','.join(sorted(u.value for u in self.users))}",
            f"sso={self.sso}",
            f"mfa={self.mfa}",
            f"internet={self.internet_facing}",
            f"dpa={self.dpa_in_place}",
            f"regimes={','.join(sorted(self.regulated_regimes))}",
        ]
        parts += sorted(
            f"integration={i.name.casefold()}|{i.direction}|{i.internal}|"
            f"{','.join(sorted(d.value for d in i.data_shared))}"
            for i in self.integrations
        )
        return hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return {
            "system": self.system,
            "requesting_team": self.requesting_team,
            "owner": self.owner,
            "purpose": self.purpose,
            "stage": self.stage,
            "fingerprint": self.fingerprint(),
            "data_classes": [d.value for d in self.data_classes],
            "record_volume": self.record_volume,
            "data_residency": self.data_residency,
            "retention": self.retention,
            "users": [u.value for u in self.users],
            "user_count": self.user_count,
            "hosting": self.hosting.value if self.hosting else None,
            "vendor": self.vendor,
            "vendor_attestations": list(self.vendor_attestations),
            "subprocessors": self.subprocessors,
            "dpa_in_place": self.dpa_in_place,
            "sso": self.sso,
            "mfa": self.mfa,
            "privileged_roles": self.privileged_roles,
            "offboarding": self.offboarding,
            "internet_facing": self.internet_facing,
            "network_notes": self.network_notes,
            "logging": self.logging,
            "log_destination": self.log_destination,
            "log_retention": self.log_retention,
            "integrations": [i.to_dict() for i in self.integrations],
            "regulated_regimes": list(self.regulated_regimes),
            "exit_plan": self.exit_plan,
            "facts": [f.to_dict() for f in self.facts],
            "unanswered": self.unanswered,
        }


@dataclass(frozen=True, slots=True)
class ControlGap:
    """An applicable control the declared design does not satisfy.

    Produced by pure functions over the intake -- no model involved -- which is
    why these can be stated flatly rather than hedged. "You told us there is no
    MFA on an internet-facing system holding personal data" is not an opinion.
    """

    control_id: str
    title: str
    why_applicable: str
    what_is_missing: str
    severity: Severity
    frameworks: tuple[Framework, ...] = ()
    evidence_facts: tuple[str, ...] = ()
    remediation: str = ""
    blocking: bool = False
    """A gap that cannot be carried as a condition. Sets the decision to
    changes-required regardless of anything else in the review."""

    def to_dict(self) -> dict[str, Any]:
        return {
            "control_id": self.control_id,
            "title": self.title,
            "why_applicable": self.why_applicable,
            "what_is_missing": self.what_is_missing,
            "severity": self.severity.value,
            "frameworks": [f.to_dict() for f in self.frameworks],
            "evidence_facts": list(self.evidence_facts),
            "remediation": self.remediation,
            "blocking": self.blocking,
        }


@dataclass(frozen=True, slots=True)
class Finding:
    """A reasoned risk the control checks did not already state.

    The model's contribution, and deliberately the smaller half of the report.
    Anything a rule can decide is decided by a rule; this is for the things that
    only emerge from how a particular set of declared facts fit together --
    "contractors reach this through a shared account and it writes to the
    finance system" is not a control gap, it is a chain.
    """

    id: str
    title: str
    chain: tuple[str, ...]
    """The path, one link per entry. A chain a reviewer can break at one link
    beats a category label they have read a hundred times."""

    severity: Severity
    data_at_risk: DataClass
    exposed_to: UserPopulation
    fact_ids: tuple[str, ...] = ()
    control_ids: tuple[str, ...] = ()
    frameworks: tuple[Framework, ...] = ()
    preconditions: tuple[str, ...] = ()
    condition: str = ""
    """What the requesting team must do. Written for them, not for security."""

    because: str = ""

    def key(self) -> str:
        """Identity for re-review comparison.

        Structural -- which facts, which controls, what is at risk -- and blind
        to the title, because model wording varies between runs and a reworded
        description of a known risk must not resurface as newly introduced.
        """
        material = "|".join(
            [
                ",".join(sorted(self.fact_ids)),
                ",".join(sorted(self.control_ids)),
                self.data_at_risk.value,
                self.exposed_to.value,
            ]
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]

    def dedup_key(self) -> str:
        """Identity for collapsing duplicates within one review.

        Looser than :meth:`key`, and deliberately so: two genuinely different
        risks can share the same facts and controls, and de-duplicating on
        structure alone would silently drop one of them from the report.
        """
        words = sorted(set(re.findall(r"[a-z0-9]{4,}", self.title.casefold())))
        return hashlib.sha256(f"{self.key()}|{','.join(words)}".encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "key": self.key(),
            "title": self.title,
            "chain": list(self.chain),
            "severity": self.severity.value,
            "data_at_risk": self.data_at_risk.value,
            "exposed_to": self.exposed_to.value,
            "fact_ids": list(self.fact_ids),
            "control_ids": list(self.control_ids),
            "frameworks": [f.to_dict() for f in self.frameworks],
            "preconditions": list(self.preconditions),
            "condition": self.condition,
            "because": self.because,
        }


@dataclass(frozen=True, slots=True)
class Question:
    """Something the reviewer needs answered before the design can be settled.

    Distinct from a finding. A finding says what is wrong; this says what nobody
    knows yet. Keeping them apart is what stops a review reading as more certain
    than it is, and it gives the requesting team a short list of things to go
    and find out rather than a vague sense of unease.
    """

    text: str
    why_it_matters: str = ""
    blocks_decision: bool = False
    """True when the answer would change the outcome. These are why the decision
    can come back as insufficient-information rather than a guess."""

    def to_dict(self) -> dict[str, Any]:
        return {
            "text": self.text,
            "why_it_matters": self.why_it_matters,
            "blocks_decision": self.blocks_decision,
        }


@dataclass(slots=True)
class Review:
    """One completed design review."""

    intake: Intake
    decision: Decision = Decision.INSUFFICIENT_INFORMATION
    decision_rationale: str = ""
    confidence: Confidence = Confidence.MEDIUM

    gaps: list[ControlGap] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    questions: list[Question] = field(default_factory=list)
    applicable_controls: list[str] = field(default_factory=list)
    satisfied_controls: list[str] = field(default_factory=list)

    new_finding_keys: set[str] = field(default_factory=set)
    baseline_available: bool = False
    baseline_fingerprint: str = ""

    dropped_findings: int = 0
    rejections: list[tuple[str, str]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    tool_version: str = ""
    model_id: str = ""
    reviewed_at: str = ""

    def counts_by_severity(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for gap in self.gaps:
            counts[gap.severity.value] += 1
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def worst_severity(self) -> Severity | None:
        severities = [g.severity for g in self.gaps] + [f.severity for f in self.findings]
        return max(severities, default=None)

    def blocking_gaps(self) -> list[ControlGap]:
        return [g for g in self.gaps if g.blocking]

    def blocking_questions(self) -> list[Question]:
        return [q for q in self.questions if q.blocks_decision]

    def conditions(self) -> list[tuple[str, str, bool]]:
        r"""Everything the requesting team has to do, as (what, why, trusted).

        Gaps and findings merged into one list on purpose: the requester does
        not care which of the two internal machines produced an item, they care
        what is on their plate.

        ``trusted`` carries provenance through the merge, and it has to. Gap
        remediation is written in this repository and reviewed in pull
        requests; finding conditions come from the model and are derived from
        intake text another team wrote. Escaping both renders every
        ``(SAML or OIDC)`` as ``\(SAML or OIDC\)``, which makes the document
        look broken; escaping neither lets an intake-derived string carry a
        link into a ticket. The renderer needs to know which is which.
        """
        items: list[tuple[str, str, bool]] = []
        for gap in sorted(self.gaps, key=lambda g: -g.severity.rank):
            if gap.remediation:
                items.append((gap.remediation, gap.title, True))
        for finding in sorted(self.findings, key=lambda f: -f.severity.rank):
            if finding.condition:
                items.append((finding.condition, finding.title, False))
        return items

    def new_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.key() in self.new_finding_keys]

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_version": self.tool_version,
            "model_id": self.model_id,
            "reviewed_at": self.reviewed_at,
            "decision": self.decision.value,
            "decision_rationale": self.decision_rationale,
            "confidence": self.confidence.value,
            "intake": self.intake.to_dict(),
            "counts": self.counts_by_severity(),
            "applicable_controls": self.applicable_controls,
            "satisfied_controls": self.satisfied_controls,
            "gaps": [g.to_dict() for g in self.gaps],
            "findings": [f.to_dict() for f in self.findings],
            "questions": [q.to_dict() for q in self.questions],
            "conditions": [{"do": d, "for": w} for d, w, _ in self.conditions()],
            "baseline_available": self.baseline_available,
            "baseline_fingerprint": self.baseline_fingerprint,
            "new_finding_keys": sorted(self.new_finding_keys),
            "dropped_findings": self.dropped_findings,
            "rejections": [{"title": t, "reason": r} for t, r in self.rejections],
            "notes": self.notes,
        }
