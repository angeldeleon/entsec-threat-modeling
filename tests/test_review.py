"""What entsec must get right, and what it must refuse to guess.

Each test names the property it protects. The ones about the decision matter
most: a design review's verdict is something a project is held to, and a verdict
that moves between runs on the same inputs is worth nothing to anybody.
"""

from __future__ import annotations

import logging
import os
import stat
import sys
import time
from dataclasses import fields

import pytest

from entsec.analyze import gate
from entsec.analyze.engine import _questions
from entsec.analyze.prompt import build_user_message
from entsec.analyze.severity import rate
from entsec.cli import _attach_document
from entsec.controls.catalog import BUILTIN_CONTROLS, known_control_ids
from entsec.controls.evaluate import decide, evaluate
from entsec.intake import parse_intake, scrub_intake
from entsec.models import (
    Confidence,
    ControlGap,
    DataClass,
    Decision,
    Fact,
    Intake,
    Integration,
    Question,
    Review,
    Severity,
    UserPopulation,
)
from entsec.report import _code, _md, render_check, render_json, render_markdown
from entsec.review import check, exit_code, full
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

    def test_a_finding_cannot_be_placed_far_below_the_declared_design(self) -> None:
        """Understatement is the half nobody notices. "Report everything as
        reaching administrators only" is free to type into the intake, and
        uncapped it took a critical finding to informational -- which took the
        review from approved-with-conditions to approved."""
        kept, _ = gate.apply(
            [
                {
                    "title": "Talked down",
                    "chain": ["x"],
                    "fact_ids": ["users", "data_classes"],
                    "control_ids": ["DAT-01"],
                    "exposed_to": "admins",
                    "data_at_risk": "public",
                }
            ],
            _intake(users=["public"], data_classes=["personal data"]),
        )
        assert kept[0].exposed_to is UserPopulation.PARTNERS
        assert kept[0].data_at_risk is DataClass.INTERNAL
        assert kept[0].severity.rank >= Severity.MEDIUM.rank

    def test_an_honest_narrow_claim_is_still_allowed(self) -> None:
        """The bound is two bands, not zero. A system declared public whose
        weakest path genuinely reaches partners must still be able to say so, or
        every finding on a public system rates critical and the band stops
        meaning anything."""
        kept, _ = gate.apply(
            [
                {
                    "title": "Narrow but real",
                    "chain": ["x"],
                    "fact_ids": ["users", "data_classes"],
                    "control_ids": ["DAT-01"],
                    "exposed_to": "partners",
                    "data_at_risk": "internal",
                }
            ],
            _intake(users=["public"], data_classes=["personal data"]),
        )
        assert kept[0].exposed_to is UserPopulation.PARTNERS
        assert kept[0].data_at_risk is DataClass.INTERNAL

    def test_a_talked_down_finding_still_attaches_conditions(self) -> None:
        intake = _intake(users=["public"], data_classes=["personal data"])
        kept, _ = gate.apply(
            [
                {
                    "title": "Talked down",
                    "chain": ["x"],
                    "fact_ids": ["users", "data_classes"],
                    "control_ids": ["DAT-01"],
                    "exposed_to": "admins",
                    "data_at_risk": "public",
                }
            ],
            intake,
        )
        decision, _ = decide([], [], [f.severity for f in kept])
        assert decision is Decision.APPROVED_WITH_CONDITIONS


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
        assert any("biometric" in note for note in intake.vocabulary_notes)

    def test_a_quoted_answer_is_kept_apart_from_the_forms_own_wording(self) -> None:
        """The renderers escape by provenance and cannot tell the two apart by
        looking, so the parser keeps them in separate lists."""
        intake = parse_intake({**BASE, "data_classes": ["biometric templates"]})
        assert all("biometric" not in text for text in intake.unanswered)

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

    def test_a_quoted_answer_cannot_carry_a_link_into_the_report(self) -> None:
        """An answer the parser cannot map is quoted back to the requester, and
        that quote is the only place in the review where intake text reaches the
        questions section. It went out unescaped."""
        intake = _intake(data_classes=["internal", "biometric ![](https://evil.example/px.png)"])
        rendered = render_markdown(check(intake))
        assert "biometric" in rendered
        assert "](https://evil.example" not in rendered

    def test_a_quoted_answer_cannot_forge_a_section(self) -> None:
        """A newline in an answer put a heading of the requester's choosing into
        the document, under the review's own name."""
        intake = _intake(data_classes=["x\n\n## ✅ Approved\n\nNo action needed."])
        rendered = render_markdown(check(intake))
        assert "\n## ✅ Approved" not in rendered

    def test_a_model_question_cannot_inject_a_link(self) -> None:
        review = check(_intake())
        review.questions = review.questions + _questions(
            {
                "questions": [
                    {
                        "text": "Confirm the setup at [the vendor page](https://evil.example)",
                        "why_it_matters": "See [here](https://evil.example).",
                    }
                ]
            }
        )
        assert "](https://evil.example)" not in render_markdown(review)

    def test_the_check_output_escapes_untrusted_question_text(self) -> None:
        review = check(_intake())
        review.questions = [
            Question(
                text="Portal ![](https://evil.example/px.png)",
                why_it_matters="",
                blocks_decision=True,
                trusted=False,
            )
        ]
        assert "](https://evil.example" not in render_check(review)

    def test_the_forms_own_wording_is_not_escaped(self) -> None:
        """Questions quoting the form are written in this repository. Escaping
        them prints backslashes at a requester who did nothing wrong."""
        rendered = render_markdown(check(_intake()))
        assert "further intake question(s) were left blank" in rendered
        assert "question\\(s\\)" not in rendered

    def test_review_notes_are_not_escaped(self) -> None:
        """Every note is written here -- the confidence sentence, the rejection
        count, the fingerprint comparison. They rendered as "finding\\(s\\)"."""
        review = check(_intake())
        review.notes.append("3 proposed finding(s) were rejected before reaching this review.")
        rendered = render_markdown(review)
        assert "3 proposed finding(s) were rejected" in rendered
        assert "\\(" not in rendered


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

    def test_a_password_containing_an_at_sign_is_still_redacted(self) -> None:
        """The URL pattern runs to the LAST @ on purpose. Stopping at the first
        one printed most of the password in the clear, and the fix for the
        runtime below must not undo it."""
        assert "ssw0rd" not in redact("cache at redis://:P@ssw0rd@cache.internal:6379")

    @pytest.mark.parametrize(
        "hostile",
        [
            "a://" * 40_000,
            ("x://" + "b" * 20) * 20_000,
            "eyJ" * 40_000,
        ],
    )
    def test_redaction_stays_linear_on_a_hostile_answer(self, hostile: str) -> None:
        """ "a://" repeated is a perfectly valid thing to type into "what does
        this connect to", and it used to cost time quadratic in its length: 34
        seconds of CPU for a 200 KB intake, inside `check`, which is the command
        that makes no network call and is meant to be the cheap one. The bound
        is deliberately loose -- the point is the shape of the curve, not a
        millisecond budget on somebody's laptop."""
        started = time.perf_counter()
        redact(hostile)
        assert time.perf_counter() - started < 5.0


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

    def test_a_credential_split_by_an_invisible_character_is_still_redacted(self) -> None:
        """Redaction used to run before sanitising. A zero-width space inside a
        key meant nothing matched, and the very next step deleted the zero-width
        space and put the key back together -- in the stored value, in the API
        payload and in the report. Every pattern could be beaten this way, by
        anyone who can type into the form."""
        intake = parse_intake({**BASE, "privileged_roles": "svc key AKIA​IOSFODNN7EXAMPLE"})
        assert "AKIAIOSFODNN7EXAMPLE" not in intake.privileged_roles
        assert "<redacted:" in intake.privileged_roles

    def test_a_bare_integration_entry_is_redacted_like_any_other_answer(self) -> None:
        """`integrations: [postgres://svc:pw@db/app]` is the obvious way to
        answer "what does it connect to". It took a branch that sanitised
        without redacting, so the password went to the API and into the JSON
        report while the same string in mapping form was redacted."""
        intake = parse_intake(
            {**BASE, "integrations": ["postgres://svc:hunter2@db.internal:5432/app"]}
        )
        gaps, _, applicable, _ = evaluate(intake)
        assert "hunter2" not in intake.integrations[0].name
        assert "hunter2" not in build_user_message(intake, gaps, applicable)
        assert "hunter2" not in render_json(check(intake))

    def test_a_quoted_answer_is_redacted_before_it_is_quoted_back(self) -> None:
        """An answer the parser could not map is repeated to the requester. It
        was interpolated raw, so it inherited neither the redaction nor the
        sanitising every other answer gets."""
        intake = parse_intake({**BASE, "data_classes": ["biometric AKIAIOSFODNN7EXAMPLE"]})
        gaps, _, applicable, _ = evaluate(intake)
        assert all("AKIAIOSFODNN7EXAMPLE" not in n for n in intake.vocabulary_notes)
        assert "AKIAIOSFODNN7EXAMPLE" not in build_user_message(intake, gaps, applicable)
        assert "AKIAIOSFODNN7EXAMPLE" not in render_markdown(check(intake))

    def test_an_attached_design_document_is_redacted_before_it_is_sent(self, tmp_path) -> None:
        """`-d` sends the file in full, which makes it the input most likely to
        hold a real credential -- an architecture note with a connection string,
        a runbook with a service-account key. It went from the file straight
        into the prompt while the README said otherwise."""
        document = tmp_path / "design.md"
        document.write_text(
            "Auth: api_key = AKIAIOSFODNN7EXAMPLE\n"
            "DB: postgres://svc:hunter2@db/app\n"
            "CI: token ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
            encoding="utf-8",
        )
        intake = _intake()
        _attach_document(intake, str(document))
        gaps, _, applicable, _ = evaluate(intake)
        payload = build_user_message(intake, gaps, applicable)
        for secret in ("AKIAIOSFODNN7EXAMPLE", "hunter2", "ghp_aaaa"):
            assert secret not in payload
        assert "<redacted:" in "\n".join(intake.document_lines)

    def test_model_prose_is_redacted_before_it_is_stored(self) -> None:
        """A finding quotes the design back at the reader, and it is written to
        the review database as well as the report. The intake it was written
        from is redacted, so nothing should get this far -- which is the reason
        to close it rather than to argue about whether it can happen."""
        kept, _ = gate.apply(
            [
                {
                    "title": "Shared credential AKIAIOSFODNN7EXAMPLE in the runbook",
                    "chain": ["operator reads postgres://svc:hunter2@db/app"],
                    "fact_ids": ["users"],
                    "control_ids": ["IAM-04"],
                    "exposed_to": "employees",
                    "data_at_risk": "internal",
                    "condition": "Rotate AKIAIOSFODNN7EXAMPLE.",
                }
            ],
            _intake(),
        )
        finding = kept[0]
        rendered = " ".join([finding.title, *finding.chain, finding.condition])
        assert "AKIAIOSFODNN7EXAMPLE" not in rendered
        assert "hunter2" not in rendered
        assert finding.control_ids == ("IAM-04",)

    def test_a_design_document_survives_readably(self, tmp_path) -> None:
        """Redaction that eats the prose makes the attachment pointless."""
        document = tmp_path / "design.md"
        document.write_text("Attendees register through the vendor portal.\n", encoding="utf-8")
        intake = _intake()
        _attach_document(intake, str(document))
        assert intake.document_lines == ["Attendees register through the vendor portal."]


_SECRET = "AKIAIOSFODNN7EXAMPLE"

# Field types on the model that carry no free text: a fixed vocabulary defined
# in this repository, or a tri-state boolean. Anything else has to be planted
# by the test below, and a new shape has to be added here deliberately rather
# than by being forgotten.
_NO_FREE_TEXT = frozenset(
    {
        "tuple[DataClass, ...]",
        "tuple[UserPopulation, ...]",
        "Hosting | None",
        "bool | None",
    }
)


def _planted(annotation: str) -> object | None:
    """A value of the right shape with a credential inside it."""
    if annotation == "str":
        return f"key {_SECRET}"
    if annotation == "list[str]":
        return [f"key {_SECRET}"]
    if annotation == "tuple[str, ...]":
        return (f"key {_SECRET}",)
    if annotation == "list[Fact]":
        return [Fact(id="x", question="q", value=f"key {_SECRET}", source=f"{_SECRET}.yml")]
    if annotation == "tuple[Integration, ...]":
        return (
            Integration(
                name=f"key {_SECRET}",
                direction="unknown",
                auth_method=f"key {_SECRET}",
                notes=f"key {_SECRET}",
            ),
        )
    return None


class TestTheScrubIsAChokePoint:
    """Calling the cleaner at each parse site is a discipline, and disciplines
    fail quietly. Three fields reached the API with credentials in them because
    of exactly that, each one missing a single call. The guarantee is made over
    the finished model instead, so a field added next year is covered whether or
    not whoever adds it reads that file."""

    def test_every_field_on_the_model_is_scrubbed(self) -> None:
        intake = Intake()
        planted = 0
        for spec in fields(Intake):
            value = _planted(str(spec.type))
            if value is None:
                assert str(spec.type) in _NO_FREE_TEXT, (
                    f"Intake.{spec.name} is a {spec.type}, which this test does not know "
                    "how to plant a credential in. Teach it, or the scrub is being taken "
                    "on trust for that field."
                )
                continue
            setattr(intake, spec.name, value)
            planted += 1

        assert planted >= 20, "the planting loop stopped covering the model"
        before = repr([getattr(intake, spec.name) for spec in fields(Intake)])
        assert _SECRET in before

        scrub_intake(intake)

        after = repr([getattr(intake, spec.name) for spec in fields(Intake)])
        assert _SECRET not in after

    def test_the_scrub_leaves_the_taxonomy_alone(self) -> None:
        """Enum members subclass str. Cleaning one would replace it with a plain
        string that no longer compares equal, and every applicability rule that
        tests membership would silently stop firing."""
        intake = _intake(data_classes=["personal data"], users=["public"], hosting="saas")
        scrub_intake(intake)
        assert DataClass.PII in intake.data_classes
        assert UserPopulation.PUBLIC in intake.users
        assert intake.hosting is not None and intake.hosting.value == "saas"

    def test_the_scrub_is_idempotent(self) -> None:
        """It runs again when a document is attached, and a placeholder must not
        be mistaken for a secret on the second pass."""
        intake = _intake(privileged_roles="key AKIAIOSFODNN7EXAMPLE")
        once = scrub_intake(intake).privileged_roles
        assert scrub_intake(intake).privileged_roles == once


class _StubAnalyzer:
    """Stands in for the reasoning layer, so the wiring can be tested without a
    network call. Returns whatever it was handed."""

    def __init__(self, questions: list[Question]) -> None:
        self.questions = questions

    def analyze(
        self, intake: Intake, gaps: list[ControlGap], applicable: list[str]
    ) -> tuple[list[object], list[Question], list[object], str]:
        return [], self.questions, [], "stub-model"


class TestTheDecisionIsNotTheModelsToMove:
    """The split is the design: the model contributes findings, and the verdict
    is computed. A question marked as blocking is what turns an approval into
    insufficient-information and fails the exit code, so it is part of the
    verdict."""

    def test_the_analysis_layer_cannot_mark_its_own_questions_blocking(self) -> None:
        produced = _questions(
            {
                "questions": [
                    {
                        "text": "Who owns the SAML metadata refresh?",
                        "why_it_matters": "Nobody named it.",
                        "blocks_decision": True,
                    }
                ]
            }
        )
        assert produced and not any(q.blocks_decision for q in produced)
        assert not any(q.trusted for q in produced)

    def test_a_model_question_does_not_change_the_verdict(self) -> None:
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
        assert check(intake).decision is Decision.APPROVED

        # Blocking on the way in, on purpose: the enforcement has to sit at the
        # boundary where these enter a review, not in the code that happens to
        # produce them today.
        analyzer = _StubAnalyzer(
            [Question(text="One more thing", blocks_decision=True, trusted=False)]
        )
        result = full(intake, analyzer)  # type: ignore[arg-type]
        assert result.decision is Decision.APPROVED
        assert not result.blocking_questions()
        assert exit_code(result, "high") == 0

    def test_a_model_question_still_reaches_the_reader(self) -> None:
        """Closing the hole must not silently drop the question."""
        analyzer = _StubAnalyzer([Question(text="One more thing", trusted=False)])
        result = full(_intake(), analyzer)  # type: ignore[arg-type]
        assert any(q.text == "One more thing" for q in result.questions)


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


class TestFilesAreOpenedThroughADescriptor:
    """An intake form arrives by email and is saved into a shared folder.

    Whoever put it there is often not the account running the review, and the
    text of every file named below reaches the review — and, with ``review``,
    an API request.
    """

    def test_a_symlinked_intake_is_refused(self, tmp_path) -> None:
        from entsec.intake import load_intake

        target = tmp_path / "elsewhere.yml"
        target.write_text("system: S\n", encoding="utf-8")
        link = tmp_path / "intake.yml"
        link.symlink_to(target)

        with pytest.raises(ValidationError, match="cannot open intake file"):
            load_intake(link)

    def test_a_symlinked_config_is_refused(self, tmp_path) -> None:
        from entsec.config import load_config

        target = tmp_path / "elsewhere.yml"
        target.write_text("fail_on: high\n", encoding="utf-8")
        link = tmp_path / "entsec.yml"
        link.symlink_to(target)

        with pytest.raises(ValidationError, match="cannot open config file"):
            load_config(link)

    def test_a_symlinked_design_document_is_refused(self, tmp_path) -> None:
        target = tmp_path / "id_rsa"
        target.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\n", encoding="utf-8")
        link = tmp_path / "design.md"
        link.symlink_to(target)

        intake = _intake()
        with pytest.raises(ValidationError, match="cannot open design document"):
            _attach_document(intake, str(link))
        assert intake.document_lines == []

    @pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX FIFOs only")
    def test_a_fifo_intake_fails_rather_than_hanging(self, tmp_path) -> None:
        """O_NONBLOCK is the difference between a refusal and a review that never returns."""
        from entsec.intake import load_intake

        path = tmp_path / "intake.yml"
        os.mkfifo(path)

        with pytest.raises(ValidationError, match="not a regular file"):
            load_intake(path)

    @pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX FIFOs only")
    def test_a_fifo_baseline_fails_rather_than_hanging(self, tmp_path) -> None:
        """The regular-file check ran after the open, so it never got to run."""
        from entsec.baseline import BaselineStore, StateError

        path = tmp_path / "reviews.db"
        os.mkfifo(path)

        with pytest.raises(StateError, match="not a regular file"):
            BaselineStore(path, scope="s").previous()

    def test_a_real_intake_is_still_read(self, tmp_path) -> None:
        from entsec.intake import load_intake

        path = tmp_path / "intake.yml"
        path.write_text("system: Real System\nusers: [employees]\n", encoding="utf-8")
        assert load_intake(path).system == "Real System"


class TestTheReviewIsWrittenSafely:
    """A review is a short list of where to attack the organisation."""

    def _review(self):
        return render_markdown(check(_intake()))

    def test_the_review_is_written_owner_only(self, tmp_path) -> None:
        from entsec.cli import _write

        path = tmp_path / "review.md"
        _write(self._review(), str(path))
        assert stat.S_IMODE(path.stat().st_mode) == 0o600

    def test_a_permissive_file_from_a_previous_review_is_tightened(self, tmp_path) -> None:
        from entsec.cli import _write

        path = tmp_path / "review.md"
        path.write_text("stale", encoding="utf-8")
        os.chmod(path, 0o644)
        _write(self._review(), str(path))
        assert stat.S_IMODE(path.stat().st_mode) == 0o600

    def test_a_symlinked_output_path_is_refused(self, tmp_path) -> None:
        from entsec.cli import _write

        target = tmp_path / "victim.txt"
        target.write_text("original", encoding="utf-8")
        os.chmod(target, 0o644)
        link = tmp_path / "review.md"
        link.symlink_to(target)

        with pytest.raises(ValidationError, match="cannot write the review"):
            _write(self._review(), str(link))

        assert target.read_text(encoding="utf-8") == "original"
        # The chmod is the second half of the attack: it locks the owner out.
        assert stat.S_IMODE(target.stat().st_mode) == 0o644


class TestApiHostClassification:
    """The API base is operator-configurable, which is why the guard exists."""

    def test_a_scoped_link_local_address_is_still_classified(self, monkeypatch) -> None:
        """getaddrinfo returns fe80::1%eth0 for a link-local answer. The scope
        says nothing about routability, so it is dropped before classifying."""
        from entsec import httpclient

        monkeypatch.setattr(
            httpclient.socket,
            "getaddrinfo",
            lambda *a, **k: [(0, 0, 0, "", ("fe80::1%eth0", 443, 0, 2))],
        )
        with pytest.raises(ValidationError, match="not a public address"):
            httpclient.assert_api_url("https://gateway.example/v1/messages")

    def test_carrier_grade_nat_is_refused(self, monkeypatch) -> None:
        """100.64.0.0/10 is neither private nor reserved on every supported
        Python, and it is where a cloud provider's own services sit."""
        from entsec import httpclient

        monkeypatch.setattr(
            httpclient.socket,
            "getaddrinfo",
            lambda *a, **k: [(0, 0, 0, "", ("100.64.1.1", 443))],
        )
        with pytest.raises(ValidationError, match="not a public address"):
            httpclient.assert_api_url("https://gateway.example/v1/messages")

    def test_an_unparseable_address_fails_closed(self, monkeypatch) -> None:
        from entsec import httpclient

        monkeypatch.setattr(
            httpclient.socket,
            "getaddrinfo",
            lambda *a, **k: [(0, 0, 0, "", ("not-an-address", 443))],
        )
        with pytest.raises(ValidationError, match="not a parseable address"):
            httpclient.assert_api_url("https://gateway.example/v1/messages")

    def test_a_public_address_is_still_allowed(self, monkeypatch) -> None:
        from entsec import httpclient

        monkeypatch.setattr(
            httpclient.socket,
            "getaddrinfo",
            lambda *a, **k: [(0, 0, 0, "", ("93.184.216.34", 443))],
        )
        assert httpclient.assert_api_url("https://api.example.com/v1/messages")

    def test_allow_internal_still_permits_a_named_gateway(self, monkeypatch) -> None:
        from entsec import httpclient

        monkeypatch.setattr(
            httpclient.socket,
            "getaddrinfo",
            lambda *a, **k: [(0, 0, 0, "", ("10.1.2.3", 443))],
        )
        assert httpclient.assert_api_url("https://gateway.internal/v1", allow_internal=True)


class TestBareUrlQuarantine:
    """An answer needs no Markdown syntax at all to put a live link in a review."""

    def test_a_bare_url_is_moved_into_a_code_span(self) -> None:
        assert "`https://evil.example/approve`" in _md("see https://evil.example/approve")

    def test_a_www_url_is_quarantined_too(self) -> None:
        assert "`www.evil.example/approve`" in _md("see www.evil.example/approve")

    def test_an_answer_cannot_autolink_into_the_review(self) -> None:
        """The system name is written by the requesting team and heads the
        document every reader opens."""
        intake = _intake(system="Portal https://evil.example/ticket")
        rendered = render_markdown(check(intake))
        assert "`https://evil.example/ticket`" in rendered

    def test_tool_authored_prose_is_still_not_escaped(self) -> None:
        rendered = render_check(check(_intake(mfa="no", users=["employees"])))
        assert "\\(" not in rendered


class TestLogRedaction:
    """The backstop for the line nobody thought about."""

    def _record(self, message: str, exc_info=None) -> logging.LogRecord:
        return logging.LogRecord("entsec", logging.ERROR, __file__, 1, message, None, exc_info)

    def test_a_credential_in_a_message_is_redacted(self) -> None:
        from entsec.cli import _RedactingFilter

        record = self._record("could not parse: password=hunter2hunter2")
        _RedactingFilter().filter(record)
        assert "hunter2hunter2" not in record.getMessage()

    def test_a_credential_in_a_traceback_is_redacted(self) -> None:
        """Tracebacks are formatted separately and bypass getMessage()."""
        from entsec.cli import _RedactingFilter

        try:
            raise RuntimeError("connecting to postgres://svc:hunter2hunter2@db.internal/app")
        except RuntimeError:
            record = self._record("failed", exc_info=sys.exc_info())

        _RedactingFilter().filter(record)
        assert record.exc_text is not None
        assert "hunter2hunter2" not in record.exc_text
        assert record.exc_info is None

    def test_ordinary_text_is_left_alone(self) -> None:
        from entsec.cli import _RedactingFilter

        record = self._record("reviewed 12 controls")
        _RedactingFilter().filter(record)
        assert record.getMessage() == "reviewed 12 controls"


class TestADevicePathIsStillWritable:
    """`entsec check -i intake.yml -o /dev/null` is how this tool's own CI runs
    the command for its exit code. The 0600 is for a real file; chmod-ing a
    character device is either a permission error or, as root, a machine-wide
    change to /dev/null."""

    def test_writing_to_dev_null_neither_fails_nor_chmods_it(self) -> None:
        from entsec.cli import _write

        before = stat.S_IMODE(os.stat("/dev/null").st_mode)
        _write("anything", "/dev/null")
        assert stat.S_IMODE(os.stat("/dev/null").st_mode) == before
