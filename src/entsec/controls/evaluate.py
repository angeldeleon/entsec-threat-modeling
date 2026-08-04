"""Applicability, gaps and the decision. All of it computed, none of it reasoned.

This module is why entsec can be trusted with the parts that matter. Everything
here is a pure function of the declared intake: which controls are in scope,
which the answers satisfy, which they do not, and what the review therefore
decides. Run it twice on the same form and you get the same answer, and if you
disagree with the answer you can point at the line that produced it.

The language model never touches any of this. It contributes attack chains and
residual risk on top, which is the part a rule genuinely cannot do -- but the
verdict a requesting team is held to is arithmetic over what they told us.

Three distinctions carry most of the weight:

**Applicable is not the same as failed.** A control that does not apply is
absent from the review entirely, rather than present and marked N/A. A review
that lists thirty irrelevant controls to demonstrate thoroughness is a review
that gets skimmed.

**Unknown is not the same as absent.** ``satisfied`` returning None produces a
question, not a gap. Automated assessment tools lose the trust of engineering
teams faster through false accusation than through anything else.

**Blocking is not the same as severe.** A CRITICAL gap can often be carried as a
condition with a date. A blocking gap cannot, because proceeding would mean an
obligation is already being breached -- sending personal data to a vendor with
no processing agreement, for instance. Severity says how bad; blocking says
whether it can wait.
"""

from __future__ import annotations

from ..models import (
    Confidence,
    ControlGap,
    Decision,
    Intake,
    Question,
    Severity,
)
from .catalog import BUILTIN_CONTROLS, Control


def applicable_controls(intake: Intake) -> list[Control]:
    """Controls in scope for this design, in catalog order.

    A predicate that raises is treated as not applicable and is not allowed to
    take the review down with it: one malformed answer should cost one control,
    not the entire assessment.
    """
    in_scope: list[Control] = []
    for entry in BUILTIN_CONTROLS:
        try:
            if entry.applies(intake):
                in_scope.append(entry)
        except (AttributeError, TypeError, ValueError):
            continue
    return in_scope


def evaluate(
    intake: Intake,
) -> tuple[list[ControlGap], list[Question], list[str], list[str]]:
    """Evaluate every applicable control.

    Returns (gaps, questions, applicable ids, satisfied ids).
    """
    gaps: list[ControlGap] = []
    questions: list[Question] = []
    applicable: list[str] = []
    satisfied: list[str] = []

    for entry in applicable_controls(intake):
        applicable.append(entry.id)
        try:
            result = entry.satisfied(intake)
        except (AttributeError, TypeError, ValueError):
            result = None

        if result is True:
            satisfied.append(entry.id)
            continue

        if result is None:
            # Unknown. A question, never a gap -- see the module docstring.
            questions.append(
                Question(
                    text=f"{entry.title}: {entry.objective}",
                    why_it_matters=(
                        f"Applies because {entry.why_template}. "
                        f"Until it is answered, {entry.id} cannot be signed off."
                    ),
                    # A blocking control that nobody has answered is exactly the
                    # case where guessing in either direction is worse than
                    # asking, so it holds the decision rather than resolving it.
                    blocks_decision=entry.blocking or entry.severity.rank >= Severity.HIGH.rank,
                )
            )
            continue

        gaps.append(
            ControlGap(
                control_id=entry.id,
                title=entry.title,
                why_applicable=f"Applies because {entry.why_template}.",
                what_is_missing=entry.objective,
                severity=entry.severity,
                frameworks=entry.frameworks,
                evidence_facts=entry.evidence_facts,
                remediation=entry.remediation,
                blocking=entry.blocking,
            )
        )

    gaps.sort(key=lambda g: (not g.blocking, -g.severity.rank, g.control_id))
    questions.sort(key=lambda q: (not q.blocks_decision, q.text))
    return gaps, questions, applicable, satisfied


def decide(
    gaps: list[ControlGap],
    questions: list[Question],
    finding_severities: list[Severity],
) -> tuple[Decision, str]:
    """Derive the review decision and the sentence explaining it.

    Deliberately not the model's call. A design review's output is a verdict
    somebody will be held to, and a verdict that shifts between runs on the same
    inputs is worth nothing -- to the requesting team, who cannot plan against
    it, or to the security team, who cannot defend it.

    The order of the checks is the policy, and it is short enough to argue with:

    1. A blocking gap means the design cannot proceed as described.
    2. An unanswered question that would change the outcome means we ask rather
       than guess. Guessing generously waves through real risk; guessing
       harshly blocks a project on something that may already be handled.
    3. Anything outstanding becomes conditions.
    4. Otherwise, approved.
    """
    blocking = [g for g in gaps if g.blocking]
    if blocking:
        names = ", ".join(g.control_id for g in blocking[:3])
        return (
            Decision.CHANGES_REQUIRED,
            f"{len(blocking)} blocking control gap(s) ({names}) mean this cannot proceed "
            "as described. These are not conditions that can be carried with a date: "
            "proceeding would breach an obligation that is already in force.",
        )

    blockers = [q for q in questions if q.blocks_decision]
    if blockers:
        return (
            Decision.INSUFFICIENT_INFORMATION,
            f"{len(blockers)} question(s) material to the outcome are unanswered. This is "
            "not a rejection — answering them may well clear the review. It is recorded "
            "this way because guessing generously would wave through real risk, and "
            "guessing harshly would block a project on something already handled.",
        )

    worst_finding = max(finding_severities, default=Severity.INFO)
    outstanding = len(gaps) + sum(1 for s in finding_severities if s.rank >= Severity.MEDIUM.rank)
    if outstanding:
        worst = max([g.severity for g in gaps] + [worst_finding], default=Severity.INFO)
        return (
            Decision.APPROVED_WITH_CONDITIONS,
            f"{outstanding} item(s) to address, the most serious rated {worst.value}. "
            "The design is sound enough to proceed provided the conditions below are "
            "met on the timeline agreed with the security team.",
        )

    return (
        Decision.APPROVED,
        "Every applicable control is satisfied by the design as described, and no "
        "additional risk was identified. This approval rests on the accuracy of the "
        "intake; a material change to the design warrants a re-review.",
    )


def assess_confidence(intake: Intake, dropped_findings: int = 0) -> tuple[Confidence, str]:
    """How much the review itself should be trusted.

    Surfaced because a review built on a third of a form and one built on a
    complete intake plus a design document should not look identical on the
    page. The reader is entitled to know which they are holding.
    """
    answered = len(intake.facts)
    total = answered + len(intake.unanswered)
    ratio = answered / total if total else 0.0

    reasons: list[str] = []
    if ratio < 0.5:
        reasons.append(f"only {answered} of {total} intake questions were answered")
    if not intake.document_lines:
        reasons.append("no design document was supplied")
    if dropped_findings:
        reasons.append(f"{dropped_findings} proposed finding(s) failed validation")

    if ratio < 0.5 or dropped_findings > 2:
        level = Confidence.LOW
    elif ratio < 0.8 or not intake.document_lines:
        level = Confidence.MEDIUM
    else:
        level = Confidence.HIGH

    if not reasons:
        return (
            level,
            "The intake was substantially complete and a design document was supplied.",
        )
    return level, "Based on: " + "; ".join(reasons) + "."


def unanswered_questions(intake: Intake) -> list[Question]:
    """Turn blank intake fields into questions.

    Separate from the control evaluation because these are gaps in the *form*
    rather than in the design. A requester who left a field blank has not
    necessarily built anything wrong; they have left something for us to ask.
    """
    # Capped at eight. Every blank is a real gap in the form, but a review that
    # opens with thirty questions reads as a rejection of the requester rather
    # than a list they can work through -- and the ones that actually matter are
    # already surfaced as blocking questions by the control evaluation. The
    # remainder are counted rather than listed, so nothing is hidden.
    listed = intake.unanswered[:8]
    questions = [
        Question(
            text=text,
            why_it_matters="Left blank on the intake form.",
            blocks_decision=False,
        )
        for text in listed
    ]
    remaining = len(intake.unanswered) - len(listed)
    if remaining > 0:
        questions.append(
            Question(
                text=f"{remaining} further intake question(s) were left blank.",
                why_it_matters=(
                    "Not listed individually to keep this section readable. Run "
                    "`entsec questions` for the full form."
                ),
                blocks_decision=False,
            )
        )
    return questions
