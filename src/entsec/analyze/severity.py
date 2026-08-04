"""Finding severity, computed from the declared design rather than chosen.

Ask a model for a rating and it anchors on the drama of its own prose: a vividly
described theoretical risk outranks a dull real one, and the ratings move
between runs on identical input. For a tool whose output is a verdict a project
is held to, that is disqualifying -- the cut line has to sit still.

So the model supplies three things it can ground in the intake -- who is exposed,
what data is at risk, and what has to be true for the risk to materialise -- and
the band is derived here, by arithmetic anyone can check and disagree with
specifically.
"""

from __future__ import annotations

from ..models import DataClass, Severity, UserPopulation

# Data outranks reach. An employees-only system holding health records is a
# worse day than a public page holding the press release, and a scheme that
# weighted reach first would sort the report the wrong way round.
_DATA_WEIGHT = 1.5

# Each unverified precondition costs the finding some standing: a chain needing
# four unproven things is a worse bet than one needing none.
_PRECONDITION_PENALTY = 0.75

# ...but the penalty is capped. Uncapped, the model set its own band by choosing
# how many preconditions to list -- six moved everything from critical to medium
# while each individual claim still passed the gate. That is the suppression
# half of prompt injection, and it is free to attempt.
_MAX_PENALISED = 3

_THRESHOLDS: tuple[tuple[float, Severity], ...] = (
    (8.0, Severity.CRITICAL),
    (6.0, Severity.HIGH),
    (3.5, Severity.MEDIUM),
    (1.5, Severity.LOW),
)


def score(exposed_to: UserPopulation, data: DataClass, preconditions: int = 0) -> float:
    """Raw score. Exposed so tests and readers can check the arithmetic."""
    raw = exposed_to.rank + data.rank * _DATA_WEIGHT
    raw -= min(max(0, preconditions), _MAX_PENALISED) * _PRECONDITION_PENALTY
    return max(0.0, raw)


def rate(exposed_to: UserPopulation, data: DataClass, preconditions: int = 0) -> Severity:
    """Derive the band.

    Public data is capped at LOW however reachable it is: there is no
    confidentiality consequence to reaching what is already published, and
    letting reach alone push it upward is how a report ends up leading with the
    marketing site.
    """
    value = score(exposed_to, data, preconditions)
    for threshold, severity in _THRESHOLDS:
        if value >= threshold:
            rating = severity
            break
    else:
        rating = Severity.INFO
    if data is DataClass.PUBLIC and rating.rank > Severity.LOW.rank:
        return Severity.LOW
    return rating


def explain(exposed_to: UserPopulation, data: DataClass, preconditions: int = 0) -> str:
    """One line stating why a finding scored what it did.

    Printed beside every rating, so a reader who thinks it is overblown can name
    the input they disagree with rather than concluding the tool is noisy.
    """
    parts = [f"reachable by {exposed_to.value}", f"puts {data.value} data at risk"]
    if preconditions:
        counted = min(preconditions, _MAX_PENALISED)
        note = f"{preconditions} unverified precondition{'s' if preconditions > 1 else ''}"
        if preconditions > counted:
            note += f" ({counted} counted)"
        parts.append(note)
    if data is DataClass.PUBLIC:
        parts.append("capped at low: no confidentiality impact")
    return ", ".join(parts)
