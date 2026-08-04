"""The intake questionnaire: the fact base a review is built on.

This file is the equivalent of a code extractor in a source-scanning tool. It is
where certainty comes from, and everything downstream is only as good as what a
requesting team typed in here.

Two design constraints pulled against each other, and both mattered.

**It has to be answerable in ten minutes by someone who is not in security.**
A form that takes an afternoon does not get filled in; the project ships without
a review, and the tool has made things worse than the wiki page it replaced.
So the fields are short, the vocabulary is the requester's rather than the
framework's, and free-text answers are accepted where a taxonomy would force a
guess.

**Blank has to mean blank.** Every unanswered field is recorded rather than
defaulted, because the difference between "there is no MFA" and "nobody asked
about MFA" is the difference between a finding and a question. Collapsing the
two is how automated assessment tools end up accusing teams of things they were
never asked about, and it is the fastest way to lose the goodwill this process
depends on.

The parser is strict about structure and forgiving about content: unknown keys
are rejected outright, but a field it cannot interpret becomes an unanswered
question rather than an error, so one odd answer never blocks a whole review.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from ..models import DataClass, Fact, Hosting, Intake, Integration, UserPopulation
from ..validation import ValidationError, redact, safe_text

_MAX_INTAKE_BYTES = 512 * 1024

# The questions, in the order they appear on the form. Kept here rather than
# scattered through the parser so `entsec questions` can print the blank form
# and a requester can see what will be asked before they start.
QUESTIONS: dict[str, str] = {
    "system": "What is the system or service called?",
    "requesting_team": "Which team is requesting this?",
    "owner": "Who will own this system once it is live?",
    "purpose": "What is it for, in one or two sentences?",
    "stage": "Where is this in its life: proposed, design, in_build, live, or contracted?",
    "data_classes": "What kinds of data will it hold?",
    "record_volume": "Roughly how many records or people are involved?",
    "data_residency": "Which countries is the data stored and processed in?",
    "retention": "How long is data kept, and what happens at the end?",
    "users": "Who will use it?",
    "user_count": "Roughly how many users?",
    "hosting": "Where does it run: saas, cloud, on_prem, hybrid, or endpoint?",
    "vendor": "If a vendor provides it, who?",
    "vendor_attestations": "What security attestations does the vendor hold?",
    "subprocessors": "Which other companies does the vendor share the data with?",
    "dpa_in_place": "Is a data processing agreement signed?",
    "sso": "Will people sign in with their corporate account (SSO)?",
    "mfa": "Is multi-factor authentication required?",
    "privileged_roles": "Who will have administrative access, and how many people?",
    "offboarding": "How is access removed when someone leaves?",
    "internet_facing": "Is it reachable from the internet?",
    "network_notes": "Who needs to reach it, and from where?",
    "logging": "What security events does it record?",
    "log_destination": "Where do the logs go?",
    "log_retention": "How long are logs kept?",
    "integrations": "What other systems does it connect to?",
    "regulated_regimes": "Does any regulation apply (GDPR, HIPAA, PCI DSS, other)?",
    "exit_plan": "How would you get the data out and shut it down?",
}

_ALLOWED_KEYS = set(QUESTIONS)

_STAGES = ("proposed", "design", "in_build", "live", "contracted")

# Synonyms a requester will plausibly type. Accepting these is not laxity: the
# alternative is a validation error on a form that a marketing manager filled in
# correctly in every way that matters, and that error is how a review does not
# happen.
_DATA_SYNONYMS: dict[str, DataClass] = {
    "pii": DataClass.PII,
    "personal": DataClass.PII,
    "personal data": DataClass.PII,
    "customer data": DataClass.PII,
    "employee data": DataClass.PII,
    "hr data": DataClass.PII,
    "regulated": DataClass.REGULATED,
    "health": DataClass.REGULATED,
    "phi": DataClass.REGULATED,
    "medical": DataClass.REGULATED,
    "payment": DataClass.REGULATED,
    "card": DataClass.REGULATED,
    "pci": DataClass.REGULATED,
    "financial": DataClass.REGULATED,
    "credentials": DataClass.CREDENTIALS,
    "secrets": DataClass.CREDENTIALS,
    "passwords": DataClass.CREDENTIALS,
    "keys": DataClass.CREDENTIALS,
    "confidential": DataClass.CONFIDENTIAL,
    "commercial": DataClass.CONFIDENTIAL,
    "contracts": DataClass.CONFIDENTIAL,
    "source code": DataClass.CONFIDENTIAL,
    "ip": DataClass.CONFIDENTIAL,
    "internal": DataClass.INTERNAL,
    "public": DataClass.PUBLIC,
    "none": DataClass.PUBLIC,
}

_USER_SYNONYMS: dict[str, UserPopulation] = {
    "public": UserPopulation.PUBLIC,
    "anyone": UserPopulation.PUBLIC,
    "anonymous": UserPopulation.PUBLIC,
    "customers": UserPopulation.CUSTOMERS,
    "clients": UserPopulation.CUSTOMERS,
    "partners": UserPopulation.PARTNERS,
    "suppliers": UserPopulation.PARTNERS,
    "vendors": UserPopulation.PARTNERS,
    "contractors": UserPopulation.CONTRACTORS,
    "temps": UserPopulation.CONTRACTORS,
    "employees": UserPopulation.EMPLOYEES,
    "staff": UserPopulation.EMPLOYEES,
    "internal": UserPopulation.EMPLOYEES,
    "admins": UserPopulation.ADMINS,
    "administrators": UserPopulation.ADMINS,
    "it": UserPopulation.ADMINS,
}

_HOSTING_SYNONYMS: dict[str, Hosting] = {
    "saas": Hosting.SAAS,
    "vendor": Hosting.SAAS,
    "vendor hosted": Hosting.SAAS,
    "third party": Hosting.SAAS,
    "cloud": Hosting.CLOUD,
    "aws": Hosting.CLOUD,
    "azure": Hosting.CLOUD,
    "gcp": Hosting.CLOUD,
    "on_prem": Hosting.ON_PREM,
    "on prem": Hosting.ON_PREM,
    "on-premise": Hosting.ON_PREM,
    "datacenter": Hosting.ON_PREM,
    "hybrid": Hosting.HYBRID,
    "endpoint": Hosting.ENDPOINT,
    "desktop": Hosting.ENDPOINT,
    "laptop": Hosting.ENDPOINT,
    "installed": Hosting.ENDPOINT,
}

_TRUE = {"yes", "y", "true", "1", "required", "enforced", "enabled"}
_FALSE = {"no", "n", "false", "0", "none", "not required", "disabled"}


def clean(value: object, *, limit: int = 600) -> str:
    """Sanitise and redact one intake answer.

    Every free-text field goes through this, not just the ones that look
    risky. Requesters paste connection strings into "how does it authenticate",
    service-account keys into "who has admin", and Slack webhook URLs into
    "where do the logs go" -- routinely, and without thinking, because the form
    asks a technical question and they answer it with the technical detail.

    Redaction happens here rather than at the renderers for the same reason it
    happens at extraction in the sibling tools: there are four sinks (the API
    payload, the Markdown report, the HTML report, the review database) and
    doing it at each means eventually forgetting one. Doing it once, at the
    boundary where untrusted text enters, means no downstream code has to know.
    """
    return safe_text(redact(str(value)), limit=limit)


def _tri_bool(value: Any) -> bool | None:
    """Parse a yes/no answer, returning None for anything unrecognised.

    None is a first-class result, not a fallback. A requester who wrote
    "planned for phase 2" has not said yes and has not said no, and forcing that
    into a boolean would either invent a finding or hide one.
    """
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    text = str(value).strip().casefold()
    if not text:
        return None
    if text in _TRUE:
        return True
    if text in _FALSE:
        return False
    return None


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [part.strip() for part in value.replace(";", ",").split(",") if part.strip()]
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return []


def _map_terms(values: list[str], synonyms: dict[str, Any]) -> tuple[list[Any], list[str]]:
    """Map free-text answers onto the taxonomy, reporting what did not map."""
    mapped: list[Any] = []
    unmapped: list[str] = []
    for raw in values:
        key = raw.strip().casefold()
        hit = synonyms.get(key)
        if hit is None:
            hit = next(
                (value for term, value in synonyms.items() if term in key),
                None,
            )
        if hit is None:
            unmapped.append(raw)
        elif hit not in mapped:
            mapped.append(hit)
    return mapped, unmapped


def _parse_integrations(value: Any) -> tuple[list[Integration], list[str]]:
    integrations: list[Integration] = []
    problems: list[str] = []
    if not isinstance(value, list):
        if value:
            problems.append("integrations should be a list; the value given was ignored")
        return integrations, problems

    for entry in value[:60]:
        if isinstance(entry, str):
            # Bare name. Everything about it is unknown, which the controls
            # layer will notice -- better than dropping the connection entirely.
            integrations.append(Integration(name=safe_text(entry, limit=120), direction="unknown"))
            continue
        if not isinstance(entry, dict):
            problems.append("an integration entry was not a name or a mapping and was ignored")
            continue
        name = clean(entry.get("name") or "", limit=120)
        if not name:
            problems.append("an integration entry had no name and was ignored")
            continue
        direction = str(entry.get("direction") or "unknown").strip().casefold()
        if direction not in {"inbound", "outbound", "bidirectional", "unknown"}:
            direction = "unknown"
        shared, _ = _map_terms(_as_list(entry.get("data_shared")), _DATA_SYNONYMS)
        internal = _tri_bool(entry.get("internal"))
        integrations.append(
            Integration(
                name=name,
                direction=direction,
                data_shared=tuple(shared),
                auth_method=clean(entry.get("auth_method") or "", limit=160),
                internal=True if internal is None else internal,
                notes=clean(entry.get("notes") or "", limit=300),
            )
        )
    return integrations, problems


def parse_intake(raw: Any, *, source: str = "intake") -> Intake:
    """Build an :class:`Intake` from parsed YAML.

    Unknown keys are rejected. A misspelled ``mfa:`` silently doing nothing
    would produce a review that says multi-factor was never mentioned, against a
    team that answered the question.
    """
    if not isinstance(raw, dict):
        raise ValidationError("the intake file must be a mapping of question keys to answers")

    unknown = sorted(set(raw) - _ALLOWED_KEYS)
    if unknown:
        raise ValidationError(
            f"unknown key(s) in the intake: {', '.join(unknown)}. "
            f"Run `entsec questions` for the blank form. Valid keys: "
            f"{', '.join(sorted(_ALLOWED_KEYS))}"
        )

    intake = Intake(source_name=source)
    facts: list[Fact] = []
    unanswered: list[str] = []

    def record(key: str, value: object, *, present: bool) -> None:
        if present:
            facts.append(
                Fact(id=key, question=QUESTIONS[key], value=clean(value, limit=400), source=source)
            )
        else:
            unanswered.append(QUESTIONS[key])

    # -- plain text fields ------------------------------------------------
    for key in (
        "system",
        "requesting_team",
        "owner",
        "purpose",
        "record_volume",
        "data_residency",
        "retention",
        "user_count",
        "vendor",
        "subprocessors",
        "privileged_roles",
        "offboarding",
        "network_notes",
        "logging",
        "log_destination",
        "log_retention",
        "exit_plan",
    ):
        text = clean(raw.get(key) or "", limit=600)
        setattr(intake, key, text)
        record(key, text, present=bool(text))

    # -- stage ------------------------------------------------------------
    stage = str(raw.get("stage") or "").strip().casefold().replace(" ", "_").replace("-", "_")
    if stage in _STAGES:
        intake.stage = stage
        record("stage", stage, present=True)
    else:
        intake.stage = "proposed"
        # Recorded as unanswered even though a default was applied, so the
        # review never claims the requester told us where the project stands.
        unanswered.append(QUESTIONS["stage"])

    # -- taxonomies -------------------------------------------------------
    data_values = _as_list(raw.get("data_classes"))
    data_classes, unmapped_data = _map_terms(data_values, _DATA_SYNONYMS)
    intake.data_classes = tuple(data_classes)
    record(
        "data_classes",
        ", ".join(d.value for d in data_classes),
        present=bool(data_classes),
    )

    user_values = _as_list(raw.get("users"))
    users, unmapped_users = _map_terms(user_values, _USER_SYNONYMS)
    intake.users = tuple(users)
    record("users", ", ".join(u.value for u in users), present=bool(users))

    hosting_values = _as_list(raw.get("hosting"))
    hostings, _ = _map_terms(hosting_values, _HOSTING_SYNONYMS)
    intake.hosting = hostings[0] if hostings else None
    record(
        "hosting",
        intake.hosting.value if intake.hosting else "",
        present=bool(hostings),
    )

    attestations = _as_list(raw.get("vendor_attestations"))
    intake.vendor_attestations = tuple(clean(a, limit=120) for a in attestations)
    record(
        "vendor_attestations",
        ", ".join(intake.vendor_attestations),
        present=bool(attestations),
    )

    regimes = _as_list(raw.get("regulated_regimes"))
    intake.regulated_regimes = tuple(clean(r, limit=120) for r in regimes)
    record("regulated_regimes", ", ".join(intake.regulated_regimes), present=bool(regimes))

    # -- tri-state booleans ----------------------------------------------
    for key in ("dpa_in_place", "sso", "mfa", "internet_facing"):
        parsed = _tri_bool(raw.get(key))
        setattr(intake, key, parsed)
        record(key, "yes" if parsed else "no", present=parsed is not None)

    # -- integrations -----------------------------------------------------
    integrations, integration_problems = _parse_integrations(raw.get("integrations"))
    intake.integrations = tuple(integrations)
    record(
        "integrations",
        "; ".join(f"{a.name} ({a.direction})" for a in integrations),
        present=bool(integrations),
    )

    intake.facts = facts
    intake.unanswered = unanswered

    # Unrecognised vocabulary is reported, not silently dropped. A requester who
    # wrote "biometric data" deserves to be told it was not understood rather
    # than to receive a review that quietly ignored it.
    for label, leftovers in (
        ("data type", unmapped_data),
        ("user group", unmapped_users),
    ):
        for value in leftovers:
            unanswered.append(
                f"The {label} '{value}' was not recognised. Confirm what it maps to, "
                "because the controls that apply depend on it."
            )
    unanswered.extend(integration_problems)

    return intake


def load_intake(path: str | Path) -> Intake:
    """Read and validate an intake file."""
    file_path = Path(path).expanduser()
    if not file_path.is_file():
        raise ValidationError(f"intake file not found: {file_path}")
    size = file_path.stat().st_size
    if size > _MAX_INTAKE_BYTES:
        raise ValidationError(f"intake file is {size} bytes, above the {_MAX_INTAKE_BYTES} limit")
    try:
        # safe_load only: full load constructs arbitrary Python objects, which
        # would turn a form filled in by another team into code execution here.
        raw = yaml.safe_load(file_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ValidationError(f"the intake file is not valid YAML: {exc}") from exc
    return parse_intake(raw or {}, source=file_path.name)


def blank_form() -> str:
    """The empty questionnaire, printed by ``entsec questions``.

    Handing this to a requesting team is the point. Security teams that publish
    what they will ask get better answers than teams that ask in a meeting,
    because the requester can go and find out rather than guess in the room.
    """
    lines = [
        "# entsec intake — security design review",
        "#",
        "# Answer what you can. Leave anything you do not know blank rather than",
        "# guessing: a blank becomes a question we will ask, whereas a wrong answer",
        "# becomes a conclusion we get wrong.",
        "",
    ]
    hints = {
        "data_classes": "  # e.g. personal data, confidential, credentials, internal, public",
        "users": "  # e.g. employees, contractors, partners, customers, public, admins",
        "hosting": "  # saas | cloud | on_prem | hybrid | endpoint",
        "stage": "  # proposed | design | in_build | live | contracted",
        "dpa_in_place": "  # yes | no",
        "sso": "  # yes | no",
        "mfa": "  # yes | no",
        "internet_facing": "  # yes | no",
        "vendor_attestations": "  # e.g. SOC 2 Type II, ISO 27001",
        "regulated_regimes": "  # e.g. GDPR, HIPAA, PCI DSS",
    }
    for key, question in QUESTIONS.items():
        lines.append(f"# {question}")
        if key == "integrations":
            lines += [
                "integrations:",
                "  - name: ",
                "    direction:    # inbound | outbound | bidirectional",
                "    internal:     # yes if the other system is ours, no if external",
                "    data_shared:  # what is sent or received",
                "    auth_method:  # how it authenticates",
                "",
            ]
            continue
        lines.append(f"{key}:{hints.get(key, '')}")
        lines.append("")
    return "\n".join(lines)
