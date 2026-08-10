"""Assembles one review from the deterministic and reasoned halves.

Kept separate from both so the ordering is visible in one place: controls are
evaluated first, the decision is computed from their gaps, and the model runs
afterwards over a picture that is already settled. The reasoning layer can add
findings and raise the severity floor; it cannot overturn a blocking gap or
talk the decision into approval.

That ordering is the point. A design review's verdict has to be defensible
months later to somebody who was not in the room, and "the model decided" is not
a defence.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone

from .analyze.engine import Analyzer
from .controls.evaluate import assess_confidence, decide, evaluate, unanswered_questions
from .models import Intake, Question, Review, Severity


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def check(intake: Intake, *, tool_version: str = "") -> Review:
    """The deterministic half: applicability, gaps, questions and the decision.

    No API key, no network. Exposed as its own command because a security team
    should be able to see what the rules concluded before deciding whether to
    send an intake to a third-party API — and because it is genuinely useful on
    its own for teams that would rather not send one at all.
    """
    gaps, control_questions, applicable, satisfied = evaluate(intake)
    questions = control_questions + unanswered_questions(intake)
    decision, rationale = decide(gaps, questions, [])
    confidence, confidence_reason = assess_confidence(intake)

    review = Review(
        intake=intake,
        decision=decision,
        decision_rationale=rationale,
        confidence=confidence,
        gaps=gaps,
        questions=questions,
        applicable_controls=applicable,
        satisfied_controls=satisfied,
        tool_version=tool_version,
        reviewed_at=_now(),
    )
    review.notes.append(confidence_reason)
    return review


def full(intake: Intake, analyzer: Analyzer, *, tool_version: str = "") -> Review:
    """The complete review: control evaluation plus reasoned findings.

    The decision is recomputed after the model returns, because a finding rated
    HIGH is a reason to attach conditions even when every control was satisfied.
    It is recomputed by the same function on the same rules -- not adjusted by
    the model, which never sees the decision at all.
    """
    review = check(intake, tool_version=tool_version)

    findings, model_questions, rejections, model_id = analyzer.analyze(
        intake, review.gaps, review.applicable_controls
    )
    review.findings = findings
    review.model_id = model_id
    review.dropped_findings = len(rejections)
    review.rejections = [(r.title, r.reason) for r in rejections]
    review.questions = _merge_questions(review.questions, model_questions)

    decision, rationale = decide(review.gaps, review.questions, [f.severity for f in findings])
    review.decision = decision
    review.decision_rationale = rationale

    confidence, confidence_reason = assess_confidence(intake, dropped_findings=len(rejections))
    review.confidence = confidence
    review.notes = [confidence_reason]

    if rejections:
        # Surfaced rather than swallowed. A review where several proposed
        # findings failed validation is one whose survivors deserve more
        # scepticism, and the reader should be the one deciding that.
        review.notes.append(
            f"{len(rejections)} proposed finding(s) were rejected before reaching this "
            "review, for citing intake facts or control identifiers that do not exist."
        )
    if not findings:
        review.notes.append(
            "The analysis added no findings beyond the control evaluation. For a simple "
            "design that is a reasonable outcome; check the control gaps above rather "
            "than reading this as a clean result."
        )
    return review


def _merge_questions(existing: list[Question], incoming: list[Question]) -> list[Question]:
    """Add questions from the analysis layer, skipping anything already asked.

    Matched on a normalised prefix rather than exact text, because the model
    will reliably reword a question the form already asked, and a review that
    asks the same thing twice in different words reads as though nobody
    proof-read it.

    Nothing arriving here blocks. A blocking question is what turns an approval
    into insufficient-information and what makes the exit code 1, so it is part
    of the verdict — and the verdict is computed from the intake, which is the
    claim this tool rests on. This is the boundary where analysis-layer
    questions enter a review, so it is where that is enforced rather than in the
    code that happens to produce them today.
    """
    seen = {q.text.casefold()[:60] for q in existing}
    merged = list(existing)
    for question in incoming:
        key = question.text.casefold()[:60]
        if key in seen:
            continue
        seen.add(key)
        merged.append(replace(question, blocks_decision=False))
    merged.sort(key=lambda q: (not q.blocks_decision, q.text))
    return merged


def exit_code(review: Review, fail_on: str) -> int:
    """Map a review onto the exit-code contract.

    0 clean, 1 findings at or above the threshold, 2 could-not-run. A blocking
    gap or an unanswered material question is always at least 1, regardless of
    severity: the whole point of blocking is that it does not pass.
    """
    if review.blocking_gaps() or review.blocking_questions():
        return 1
    threshold = Severity(fail_on)
    worst = review.worst_severity()
    return 1 if worst is not None and worst.rank >= threshold.rank else 0
