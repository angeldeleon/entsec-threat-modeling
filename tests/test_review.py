"""What entsec must get right, and what it must refuse to guess.

Each test names the property it protects. The ones about the decision matter
most: a design review's verdict is something a project is held to, and a verdict
that moves between runs on the same inputs is worth nothing to anybody.
"""

from __future__ import annotations

import pytest

from entsec.analyze import gate
from entsec.analyze.severity import rate
from entsec.controls.catalog import BUILTIN_CONTROLS, known_control_ids
from entsec.controls.evaluate import decide, evaluate
from entsec.intake import parse_intake
from entsec.models import (
    Confidence,
    DataClass,
    Decision,
    Intake,
    Review,
    Severity,
    UserPopulation,
)
from entsec.report import _code, _md, render_check, render_markdown
from entsec.review import check, exit_code
from entsec.validation import ValidationError, redact

BASE = {
    "system": "Test System",
    "requesting_team": "IT",
    "users": ["employees"],
    "data_classes": ["internal"],
}


def _intake(**overrides) -> Intake:
    return parse_intake({**BASE, **overrides})


class TestUnknownIsNotAbsent:
    """The single most important property. Automated assessment loses the
    goodwill of engineering teams faster through false accusation than through
    anything else, and that goodwill is the entire process."""

    def test_a_blank_answer_produces_a_question_not_a_gap(self) -> None:
        intake = _intake(mfa=None)
        gaps, questions, _, _ = evaluate(intake)
        assert not [g for g in gaps if g.control_id == "IAM-02"]
        assert any("Multi-factor" in q.text for q in questions)

    def test_an_explicit_no_produces_a_gap(self) -> None:
        gaps, _, _, _ = evaluate(_intake(mfa="no"))
        assert [g for g in gaps if g.control_id == "IAM-02"]

    def test_an_uninterpretable_answer_is_unknown_not_false(self) -> None:
        """'planned for phase 2' is neither yes nor no, and forcing it into a
        boolean either invents a finding or hides one."""
        intake = _intake(mfa="planned for phase 2")
        assert intake.mfa is None
        gaps, _, _, _ = evaluate(intake)
        assert not [g for g in gaps if g.control_id == "IAM-02"]

    def test_a_short_free_text_answer_is_unknown_not_failed(self) -> None:
        """This layer cannot judge adequacy, and inventing a failure from
        brevity puts a finding on a team that answered honestly."""
        gaps, _, _, _ = evaluate(_intake(offboarding="tbd"))
        assert not [g for g in gaps if g.control_id == "IAM-05"]


class TestApplicability:
    """A control that is not in scope is absent, not listed and marked N/A."""

    def test_cloud_controls_do_not_fire_on_prem(self) -> None:
        _, _, applicable, _ = evaluate(_intake(hosting="on_prem"))
        assert "TPR-05" not in applicable

    def test_privacy_controls_do_not_fire_without_personal_data(self) -> None:
        _, _, applicable, _ = evaluate(_intake(data_classes=["internal"]))
        assert "DAT-03" not in applicable
        assert "TPR-02" not in applicable

    def test_privacy_controls_fire_with_personal_data_and_a_vendor(self) -> None:
        _, _, applicable, _ = evaluate(
            _intake(data_classes=["personal data"], hosting="saas", vendor="Acme")
        )
        assert "DAT-03" in applicable and "TPR-02" in applicable

    def test_a_simple_internal_system_gets_a_short_review(self) -> None:
        """A checklist that asks forty questions of a wiki is why nobody fills
        checklists in."""
        _, _, applicable, _ = evaluate(_intake())
        assert len(applicable) < len(BUILTIN_CONTROLS) / 2


class TestDecision:
    """Computed, never reasoned. A verdict that shifts between runs on the same
    inputs cannot be planned against or defended."""

    def test_a_blocking_gap_forces_changes_required(self) -> None:
        intake = _intake(data_classes=["personal data"], users=["public"], internet_facing="yes")
        gaps, questions, _, _ = evaluate(intake)
        decision, _ = decide(gaps, questions, [])
        assert decision is Decision.CHANGES_REQUIRED

    def test_an_unanswered_material_question_asks_rather_than_guesses(self) -> None:
        """Guessing generously waves through real risk; guessing harshly blocks
        a project on something that may already be handled."""
        gaps, questions, _, _ = evaluate(_intake(data_classes=["personal data"]))
        decision, _ = decide(gaps, questions, [])
        assert decision is Decision.INSUFFICIENT_INFORMATION

    def test_a_complete_clean_design_is_approved(self) -> None:
        intake = parse_intake(
            {
                "system": "Runbook Wiki",
                "requesting_team": "Platform",
                "owner": "Dana Okafor",
                "stage": "design",
                "data_classes": ["internal"],
                "users": ["employees"],
                "hosting": "cloud",
                "sso": "yes",
                "mfa": "yes",
                "internet_facing": "no",
                "privileged_roles": "Four named platform engineers, reviewed quarterly.",
                "offboarding": "Standard leaver process through Okta deprovisioning.",
                "logging": "Sign-ins, edits, permission changes and admin actions.",
                "network_notes": "Corporate VPN only, from managed devices.",
            }
        )
        review = check(intake)
        assert review.decision is Decision.APPROVED
        assert review.gaps == []

    def test_the_decision_is_reproducible(self) -> None:
        intake = _intake(data_classes=["personal data"], hosting="saas", vendor="Acme")
        assert check(intake).decision is check(intake).decision

    def test_findings_alone_can_attach_conditions(self) -> None:
        decision, _ = decide([], [], [Severity.HIGH])
        assert decision is Decision.APPROVED_WITH_CONDITIONS


class TestGate:
    """The model may only cite what exists."""

    def test_an_undeclared_fact_is_rejected(self) -> None:
        intake = _intake()
        kept, rejected = gate.apply(
            [
                {
                    "title": "Invented",
                    "chain": ["x"],
                    "fact_ids": ["saml_config"],
                    "control_ids": ["IAM-01"],
                }
            ],
            intake,
        )
        assert kept == []
        assert "never declared" in rejected[0].reason

    def test_an_invented_control_id_is_rejected(self) -> None:
        """The most damaging error available: an invented control reference
        survives into a ticket, a GRC tracker, and an audit conversation."""
        kept, rejected = gate.apply(
            [
                {
                    "title": "Cites nothing real",
                    "chain": ["x"],
                    "fact_ids": ["system"],
                    "control_ids": ["ZZZ-99"],
                }
            ],
            _intake(),
        )
        assert kept == []
        assert "not in the catalog" in rejected[0].reason

    def test_data_class_cannot_exceed_what_was_declared(self) -> None:
        kept, _ = gate.apply(
            [
                {
                    "title": "Inflated",
                    "chain": ["x"],
                    "fact_ids": ["data_classes"],
                    "control_ids": ["DAT-01"],
                    "exposed_to": "public",
                    "data_at_risk": "regulated",
                }
            ],
            _intake(data_classes=["internal"]),
        )
        assert kept[0].data_at_risk is DataClass.INTERNAL

    def test_exposure_cannot_exceed_the_declared_population(self) -> None:
        kept, _ = gate.apply(
            [
                {
                    "title": "Inflated reach",
                    "chain": ["x"],
                    "fact_ids": ["users"],
                    "control_ids": ["IAM-01"],
                    "exposed_to": "public",
                    "data_at_risk": "internal",
                }
            ],
            _intake(users=["employees"]),
        )
        assert kept[0].exposed_to is UserPopulation.EMPLOYEES

    def test_a_valid_finding_survives_with_framework_references(self) -> None:
        kept, rejected = gate.apply(
            [
                {
                    "title": "Real finding",
                    "chain": ["a", "b"],
                    "fact_ids": ["users", "data_classes"],
                    "control_ids": ["IAM-01"],
                    "exposed_to": "employees",
                    "data_at_risk": "internal",
                    "condition": "Do the thing.",
                }
            ],
            _intake(),
        )
        assert rejected == [] and len(kept) == 1
        assert {f.name for f in kept[0].frameworks} == {
            "NIST CSF 2.0",
            "ISO 27001:2022",
            "SOC 2 TSC",
            "CIS v8",
        }

    @pytest.mark.parametrize(
        "raw", ["abc", {"a": 1}, [None], 5, [{"title": "t", "fact_ids": {"a": 1}}]]
    )
    def test_malformed_model_output_does_not_crash(self, raw: object) -> None:
        gate.apply(raw, _intake())


class TestSeverity:
    def test_the_ladder(self) -> None:
        assert rate(UserPopulation.PUBLIC, DataClass.REGULATED) is Severity.CRITICAL
        assert rate(UserPopulation.CUSTOMERS, DataClass.PII) is Severity.CRITICAL
        assert rate(UserPopulation.EMPLOYEES, DataClass.PII) is Severity.MEDIUM
        # The baseline case for almost any internal tool. If this rated MEDIUM
        # then every wiki and every ticket system would carry a medium finding,
        # and the band would stop distinguishing anything.
        assert rate(UserPopulation.EMPLOYEES, DataClass.INTERNAL) is Severity.LOW
        assert rate(UserPopulation.ADMINS, DataClass.PUBLIC) is Severity.INFO

    def test_public_data_is_capped(self) -> None:
        assert rate(UserPopulation.PUBLIC, DataClass.PUBLIC) is Severity.LOW

    def test_the_precondition_penalty_is_capped(self) -> None:
        """Uncapped, the model sets its own band by listing preconditions --
        the suppression half of prompt injection, and free to attempt."""
        assert rate(UserPopulation.PUBLIC, DataClass.REGULATED, 12) is not Severity.LOW
        assert rate(UserPopulation.PUBLIC, DataClass.REGULATED, 12).rank >= Severity.HIGH.rank

    def test_ordering_is_by_rank_not_alphabet(self) -> None:
        assert Severity.CRITICAL > Severity.HIGH
        assert not Severity.CRITICAL < Severity.HIGH
        assert min([Severity.CRITICAL, Severity.INFO]) is Severity.INFO


class TestIntakeParsing:
    def test_unknown_keys_are_rejected(self) -> None:
        """A misspelled mfa: silently doing nothing would produce a review
        saying it was never mentioned, against a team that answered."""
        with pytest.raises(ValidationError):
            parse_intake({**BASE, "mfa_enabled": "yes"})

    def test_requester_vocabulary_is_accepted(self) -> None:
        intake = parse_intake({**BASE, "data_classes": ["customer data", "HR data"]})
        assert DataClass.PII in intake.data_classes

    def test_unrecognised_vocabulary_is_reported_not_dropped(self) -> None:
        intake = parse_intake({**BASE, "data_classes": ["biometric templates"]})
        assert any("biometric" in q for q in intake.unanswered)

    def test_a_blank_form_is_empty_not_clean(self) -> None:
        assert parse_intake({}).is_empty()

    def test_the_fingerprint_ignores_prose(self) -> None:
        """Rewording a purpose statement is not a design change, and treating
        it as one would make every re-review look like a new system."""
        a = parse_intake({**BASE, "purpose": "One wording"})
        b = parse_intake({**BASE, "purpose": "Entirely different wording"})
        assert a.fingerprint() == b.fingerprint()

    def test_the_fingerprint_changes_with_the_design(self) -> None:
        a = parse_intake({**BASE, "data_classes": ["internal"]})
        b = parse_intake({**BASE, "data_classes": ["personal data"]})
        assert a.fingerprint() != b.fingerprint()


class TestFrameworkReferences:
    """These reach GRC trackers, where somebody looks them up."""

    def test_every_control_maps_to_all_four_frameworks(self) -> None:
        for entry in BUILTIN_CONTROLS:
            names = {f.name for f in entry.frameworks}
            assert names == {"NIST CSF 2.0", "ISO 27001:2022", "SOC 2 TSC", "CIS v8"}, entry.id

    def test_no_framework_reference_is_blank(self) -> None:
        for entry in BUILTIN_CONTROLS:
            for framework in entry.frameworks:
                assert framework.identifier.strip(), f"{entry.id} has a blank identifier"

    def test_control_ids_are_unique(self) -> None:
        ids = [c.id for c in BUILTIN_CONTROLS]
        assert len(ids) == len(set(ids))
        assert len(known_control_ids()) == len(ids)

    def test_every_control_has_actionable_remediation(self) -> None:
        """'Apply least privilege' is a sentence, not a condition."""
        for entry in BUILTIN_CONTROLS:
            assert len(entry.remediation) > 40, entry.id


class TestReportEscaping:
    """Intake answers are written by another team and reach tickets and chat."""

    def test_a_hostile_system_name_cannot_inject_a_link(self) -> None:
        intake = _intake(system="Portal ![](https://evil.example/px.png)")
        rendered = render_markdown(check(intake))
        assert "](https://evil.example" not in rendered

    def test_tool_authored_prose_is_not_over_escaped(self) -> None:
        """Escaping our own text renders every gap(s) as gap\\(s\\), which makes
        the document look broken and teaches the reader the tool is careless."""
        rendered = render_check(check(_intake(mfa="no", users=["employees"])))
        assert "\\(" not in rendered

    def test_code_spans_stay_readable(self) -> None:
        assert _code("A.5.23 (cloud)") == "A.5.23 (cloud)"
        assert "`" not in _code("weird`name")
        assert "<img" not in _code("<img src=x>")

    def test_untrusted_prose_is_escaped(self) -> None:
        assert "](https://evil" not in _md("x [link](https://evil.example)")


class TestNoSilentPass:
    def test_an_empty_intake_is_flagged(self) -> None:
        assert Intake().is_empty()

    def test_confidence_falls_with_a_sparse_form(self) -> None:
        """A review built on a third of a form and one built on a complete
        intake should not look identical on the page."""
        sparse = check(_intake())
        assert sparse.confidence in {Confidence.LOW, Confidence.MEDIUM}

    def test_blocking_items_always_fail_the_exit_code(self) -> None:
        intake = _intake(data_classes=["personal data"], users=["public"], internet_facing="yes")
        assert exit_code(check(intake), "critical") == 1

    def test_a_clean_review_exits_zero(self) -> None:
        review = Review(intake=_intake(), decision=Decision.APPROVED)
        assert exit_code(review, "high") == 0


class TestRedaction:
    """Intake answers are free text, and free text contains credentials."""

    @pytest.mark.parametrize(
        "line",
        [
            "service account key AKIAIOSFODNN7EXAMPLE",
            "connects with token ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "db is postgres://svc:hunter2@db.internal:5432/app",
        ],
    )
    def test_credentials_pasted_into_the_form_are_redacted(self, line: str) -> None:
        cleaned = redact(line)
        assert "<redacted:" in cleaned
        for secret in ("AKIAIOSFODNN7EXAMPLE", "ghp_aaaa", "hunter2"):
            assert secret not in cleaned


class TestSecretsNeverLeaveTheBoundary:
    """Found by verification before release: redact() existed in validation.py
    but was never wired into intake parsing, so credentials pasted into
    free-text answers reached the API payload verbatim -- while README and
    SECURITY.md both claimed they did not. A false claim in a security document
    is its own defect."""

    def test_credentials_in_a_free_text_answer_do_not_reach_the_api(self) -> None:
        from entsec.analyze.prompt import build_user_message

        intake = parse_intake(
            {
                **BASE,
                "privileged_roles": "svc key AKIAIOSFODNN7EXAMPLE, token "
                "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "network_notes": "db at postgres://svc:hunter2@db.internal:5432/app",
            }
        )
        gaps, _, applicable, _ = evaluate(intake)
        payload = build_user_message(intake, gaps, applicable)
        for secret in ("AKIAIOSFODNN7EXAMPLE", "ghp_aaaa", "hunter2"):
            assert secret not in payload

    def test_credentials_are_redacted_at_the_boundary_not_at_a_sink(self) -> None:
        """Stored redacted, so every downstream consumer inherits it and none
        has to remember."""
        intake = parse_intake({**BASE, "privileged_roles": "key AKIAIOSFODNN7EXAMPLE"})
        assert "AKIAIOSFODNN7EXAMPLE" not in intake.privileged_roles
        assert "<redacted:" in intake.privileged_roles
        assert all("AKIAIOSFODNN7EXAMPLE" not in f.value for f in intake.facts)

    def test_credentials_do_not_reach_the_report(self) -> None:
        intake = parse_intake({**BASE, "network_notes": "postgres://svc:hunter2@db:5432/app"})
        assert "hunter2" not in render_markdown(check(intake))

    def test_ordinary_answers_survive_intact(self) -> None:
        intake = parse_intake({**BASE, "offboarding": "Okta deprovisioning, verified monthly."})
        assert intake.offboarding == "Okta deprovisioning, verified monthly."


class TestConditionProvenance:
    """Also found by verification: conditions lost provenance when gap
    remediation and model findings were merged, so catalog text written in this
    repository was escaped as untrusted and rendered '\\(SAML or OIDC\\)'."""

    def test_catalog_remediation_is_not_escaped(self) -> None:
        intake = _intake(sso="no", users=["employees"])
        rendered = render_markdown(check(intake))
        assert "(SAML or OIDC)" in rendered
        assert "\\(SAML or OIDC\\)" not in rendered

    def test_conditions_carry_a_trusted_flag(self) -> None:
        review = check(_intake(sso="no"))
        assert all(len(item) == 3 for item in review.conditions())
        assert all(trusted for _, _, trusted in review.conditions())

    def test_a_model_condition_is_escaped(self) -> None:
        review = check(_intake())
        kept, _ = gate.apply(
            [
                {
                    "title": "t",
                    "chain": ["a"],
                    "fact_ids": ["system"],
                    "control_ids": ["GOV-01"],
                    "exposed_to": "employees",
                    "data_at_risk": "internal",
                    "condition": "Visit [the vendor page](https://evil.example) to fix.",
                }
            ],
            review.intake,
        )
        review.findings = kept
        rendered = render_markdown(review)
        assert "](https://evil.example)" not in rendered
