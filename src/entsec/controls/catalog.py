"""The control catalog: what a design review checks, and why it applies.

One reviewable table, in one file, and printed in full by ``entsec controls``. A
security team adopting this needs to read what it will be held to before it
points the thing at a colleague's project, and "read the code" is not an
acceptable answer to that.

Three properties make this different from the checklist in a wiki:

**Applicability is computed, not assumed.** Every entry carries an ``applies``
predicate over the declared intake. A cloud-services control does not fire on an
on-prem deployment; a privacy control does not fire on a system holding no
personal data. A checklist that asks every question of every project is the
reason nobody fills checklists in.

**Satisfaction is computed too, where the intake can settle it.** If the form
says SSO is in place, the identity control is satisfied and says so. Only the
genuinely unsettled becomes a gap.

**Framework references are data, not prose.** Each entry carries its NIST CSF
2.0, ISO 27001:2022 Annex A, SOC 2 TSC and CIS v8 mappings, so a finding can
cite them without anyone typing a control number into a sentence and getting it
wrong. Control identifiers were taken from the published frameworks; the
mapping between them is editorial judgement and is meant to be argued with.

A word on what this is not. Mapping a finding to ISO A.5.23 does not make a
system ISO-certified, and this tool is not an audit. The mapping exists so a
design review lands in the language the rest of the organisation already uses --
so a condition can be traced to an obligation, and so the reviewer does not have
to re-explain from first principles why a thing matters.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from ..models import DataClass, Framework, Hosting, Intake, Severity, UserPopulation

# Framework names, spelled once. A typo in a framework label reaching a report
# that goes to GRC is a small embarrassment with a long half-life.
NIST = "NIST CSF 2.0"
ISO = "ISO 27001:2022"
SOC2 = "SOC 2 TSC"
CIS = "CIS v8"


def _nist(identifier: str, title: str) -> Framework:
    return Framework(NIST, identifier, title)


def _iso(identifier: str, title: str) -> Framework:
    return Framework(ISO, f"A.{identifier}", title)


def _soc2(identifier: str, title: str) -> Framework:
    return Framework(SOC2, identifier, title)


def _cis(identifier: str, title: str) -> Framework:
    return Framework(CIS, f"Control {identifier}", title)


@dataclass(frozen=True, slots=True)
class Control:
    """One control objective, with the conditions under which it is in scope."""

    id: str
    title: str
    objective: str
    """What good looks like, in one sentence a non-security reader can act on."""

    applies: Callable[[Intake], bool]
    """Pure predicate over declared facts. Returning False removes the control
    from the review entirely -- it is not asked, not reported, not counted."""

    satisfied: Callable[[Intake], bool | None]
    """True, False, or None for "the intake does not settle it". None becomes a
    question rather than a gap: a review that treats unknown as failure produces
    findings against teams that simply were not asked the right question."""

    severity: Severity
    remediation: str
    """The condition handed to the requesting team. Written as an instruction
    they can carry out, not as a principle they have to interpret."""

    frameworks: tuple[Framework, ...]
    evidence_facts: tuple[str, ...] = ()
    blocking: bool = False
    """Cannot be carried as a condition -- the design does not proceed until it
    is fixed. Reserved for cases where proceeding means an obligation is already
    being breached."""

    why_template: str = ""
    tags: tuple[str, ...] = field(default_factory=tuple)


# --------------------------------------------------------------------------
# Predicate helpers. Kept small and named so the table below reads as English.
# --------------------------------------------------------------------------


def _has_data(intake: Intake, *classes: DataClass) -> bool:
    return any(c in intake.data_classes for c in classes)


def _personal_data(intake: Intake) -> bool:
    return _has_data(intake, DataClass.PII, DataClass.REGULATED)


def _sensitive(intake: Intake) -> bool:
    return intake.max_data_class().rank >= DataClass.CONFIDENTIAL.rank


def _external_users(intake: Intake) -> bool:
    return intake.max_population().rank >= UserPopulation.PARTNERS.rank


def _third_party(intake: Intake) -> bool:
    return intake.hosting is Hosting.SAAS or bool(intake.vendor)


def _always(_: Intake) -> bool:
    return True


def _unknown(_: Intake) -> None:
    return None


def _bool_or_unknown(value: bool | None) -> bool | None:
    return value


def _answered(text: str) -> bool | None:
    """Treat a substantive free-text answer as satisfied, a blank as unknown.

    Never False. A short answer might be inadequate, but this layer cannot judge
    that, and inventing a failure from brevity would put a finding on a team
    that answered the question honestly.
    """
    return True if text and len(text.strip()) >= 12 else None


BUILTIN_CONTROLS: tuple[Control, ...] = (
    # ---------------------------------------------------------------- identity
    Control(
        id="IAM-01",
        title="Single sign-on through the corporate identity provider",
        objective=(
            "Staff sign in with their existing corporate account, so joiners and "
            "leavers are handled centrally rather than per system."
        ),
        applies=lambda i: (
            UserPopulation.EMPLOYEES in i.users
            or UserPopulation.CONTRACTORS in i.users
            or UserPopulation.ADMINS in i.users
        ),
        satisfied=lambda i: _bool_or_unknown(i.sso),
        severity=Severity.HIGH,
        remediation=(
            "Integrate the system with the corporate identity provider (SAML or OIDC) "
            "before go-live. If the vendor cannot support it, record who will remove "
            "accounts manually and how that is verified each quarter."
        ),
        frameworks=(
            _nist("PR.AA", "Identity Management, Authentication, and Access Control"),
            _iso("5.16", "Identity management"),
            _soc2("CC6.1", "Logical access security"),
            _cis("5", "Account Management"),
        ),
        evidence_facts=("sso", "users"),
        why_template="staff accounts exist on this system",
        tags=("identity",),
    ),
    Control(
        id="IAM-02",
        title="Multi-factor authentication",
        objective="A stolen password alone does not grant access.",
        applies=lambda i: bool(i.users),
        satisfied=lambda i: _bool_or_unknown(i.mfa),
        severity=Severity.HIGH,
        remediation=(
            "Require MFA for all users. Where the identity provider enforces it "
            "centrally, confirm this system is in scope of that policy rather than "
            "assuming it inherits."
        ),
        frameworks=(
            _nist("PR.AA", "Identity Management, Authentication, and Access Control"),
            _iso("5.17", "Authentication information"),
            _soc2("CC6.1", "Logical access security"),
            _cis("6", "Access Control Management"),
        ),
        evidence_facts=("mfa",),
        why_template="the system has authenticated users",
        tags=("identity",),
    ),
    Control(
        id="IAM-03",
        title="MFA on an internet-facing system holding sensitive data",
        objective=(
            "An internet-reachable system holding personal or confidential data "
            "requires a second factor without exception."
        ),
        applies=lambda i: bool(i.internet_facing) and (_personal_data(i) or _sensitive(i)),
        satisfied=lambda i: _bool_or_unknown(i.mfa),
        severity=Severity.CRITICAL,
        remediation=(
            "Enable MFA before this system is reachable from the internet. This is not "
            "a post-launch item: credential stuffing against a new internet-facing "
            "login begins within days of it appearing."
        ),
        frameworks=(
            _nist("PR.AA", "Identity Management, Authentication, and Access Control"),
            _iso("5.17", "Authentication information"),
            _soc2("CC6.6", "Boundary protection"),
            _cis("6", "Access Control Management"),
        ),
        evidence_facts=("mfa", "internet_facing", "data_classes"),
        blocking=True,
        why_template="the system is internet-facing and handles sensitive data",
        tags=("identity", "exposure"),
    ),
    Control(
        id="IAM-04",
        title="Privileged access is named and limited",
        objective="Administrative access is held by named individuals, not shared accounts.",
        applies=lambda i: bool(i.users),
        satisfied=lambda i: _answered(i.privileged_roles),
        severity=Severity.MEDIUM,
        remediation=(
            "List who holds administrative access and confirm each is a named account. "
            "Replace any shared administrator login with individual accounts, so an "
            "action in the audit log resolves to a person."
        ),
        frameworks=(
            _nist("PR.AA", "Identity Management, Authentication, and Access Control"),
            _iso("8.2", "Privileged access rights"),
            _soc2("CC6.3", "Role-based access"),
            _cis("5", "Account Management"),
        ),
        evidence_facts=("privileged_roles",),
        why_template="the system has user accounts",
        tags=("identity",),
    ),
    Control(
        id="IAM-05",
        title="Offboarding removes access",
        objective="Access ends when someone leaves or changes role, verifiably.",
        applies=lambda i: (
            UserPopulation.EMPLOYEES in i.users or UserPopulation.CONTRACTORS in i.users
        ),
        satisfied=lambda i: True if i.sso else _answered(i.offboarding),
        severity=Severity.HIGH,
        remediation=(
            "Confirm access is removed by the standard leaver process. If the system "
            "is outside SSO, name the person responsible for manual removal and how "
            "completion is evidenced — orphaned accounts on departed contractors are "
            "among the most common findings in a real assessment."
        ),
        frameworks=(
            _nist("PR.AA", "Identity Management, Authentication, and Access Control"),
            _iso("5.18", "Access rights"),
            _soc2("CC6.2", "Registration and authorisation"),
            _cis("5", "Account Management"),
        ),
        evidence_facts=("offboarding", "sso"),
        why_template="staff or contractors will hold accounts",
        tags=("identity", "lifecycle"),
    ),
    # ------------------------------------------------------------------- data
    Control(
        id="DAT-01",
        title="Data classification is declared",
        objective="Everyone agrees what this system holds before it holds it.",
        applies=_always,
        satisfied=lambda i: bool(i.data_classes) or None,
        severity=Severity.MEDIUM,
        remediation=(
            "State what categories of data this system will hold. Nearly every "
            "control below depends on the answer, and a system that turns out to "
            "hold personal data after launch is a much more expensive conversation."
        ),
        frameworks=(
            _nist("ID.AM", "Asset Management"),
            _iso("5.12", "Classification of information"),
            _soc2("CC3.2", "Risk identification"),
            _cis("3", "Data Protection"),
        ),
        evidence_facts=("data_classes",),
        why_template="every review needs to know what data is involved",
        tags=("data",),
    ),
    Control(
        id="DAT-02",
        title="Retention period is defined",
        objective="Data is deleted when it is no longer needed, on a stated schedule.",
        applies=lambda i: _personal_data(i) or _sensitive(i),
        satisfied=lambda i: _answered(i.retention),
        severity=Severity.MEDIUM,
        remediation=(
            "State how long records are kept and what happens at the end of that "
            "period. 'Indefinitely' is an answer, but it is one that grows the "
            "consequence of every future breach of this system."
        ),
        frameworks=(
            _nist("PR.DS", "Data Security"),
            _iso("8.10", "Information deletion"),
            _soc2("C1.2", "Confidential information disposal"),
            _cis("3", "Data Protection"),
        ),
        evidence_facts=("retention",),
        why_template="the system holds personal or confidential data",
        tags=("data", "privacy"),
    ),
    Control(
        id="DAT-03",
        title="Data residency is known",
        objective="You can say which countries the data is stored and processed in.",
        applies=lambda i: _personal_data(i),
        satisfied=lambda i: _answered(i.data_residency),
        severity=Severity.HIGH,
        remediation=(
            "Confirm with the vendor where data is stored and processed, including "
            "any support access from other regions. Cross-border transfer of personal "
            "data carries obligations that are far cheaper to satisfy before signing."
        ),
        frameworks=(
            _nist("GV.OC", "Organizational Context"),
            _iso("5.34", "Privacy and protection of PII"),
            _soc2("P6.1", "Privacy — disclosure to third parties"),
            _cis("3", "Data Protection"),
        ),
        evidence_facts=("data_residency", "data_classes"),
        why_template="the system holds personal data",
        tags=("data", "privacy"),
    ),
    Control(
        id="DAT-04",
        title="Regulated data obligations are identified",
        objective="A named regime brings requirements the review cannot waive.",
        applies=lambda i: DataClass.REGULATED in i.data_classes or bool(i.regulated_regimes),
        satisfied=lambda i: bool(i.regulated_regimes) or None,
        severity=Severity.CRITICAL,
        remediation=(
            "Name which regime applies (GDPR, HIPAA, PCI DSS, or other) and bring "
            "compliance or legal into this review. A design review cannot sign off "
            "regulated data on its own authority."
        ),
        frameworks=(
            _nist("GV.OC", "Organizational Context"),
            _iso("5.31", "Legal, statutory, regulatory and contractual requirements"),
            _soc2("CC2.3", "External communication of objectives"),
            _cis("3", "Data Protection"),
        ),
        evidence_facts=("data_classes", "regulated_regimes"),
        blocking=True,
        why_template="regulated data is involved",
        tags=("data", "compliance"),
    ),
    # -------------------------------------------------------------- suppliers
    Control(
        id="TPR-01",
        title="Vendor security attestation obtained",
        objective="An independent report exists on the vendor's controls.",
        applies=_third_party,
        satisfied=lambda i: bool(i.vendor_attestations) or None,
        severity=Severity.HIGH,
        remediation=(
            "Request the vendor's current SOC 2 Type II or ISO 27001 certificate and "
            "read the exceptions section rather than the cover page. Absence is not "
            "automatically disqualifying for a small vendor, but it moves the "
            "assurance burden onto contract terms and onto you."
        ),
        frameworks=(
            _nist("GV.SC", "Supply Chain Risk Management"),
            _iso("5.19", "Information security in supplier relationships"),
            _soc2("CC9.2", "Vendor and business partner risk"),
            _cis("15", "Service Provider Management"),
        ),
        evidence_facts=("vendor", "vendor_attestations"),
        why_template="a third-party vendor is involved",
        tags=("third-party",),
    ),
    Control(
        id="TPR-02",
        title="Data processing agreement in place",
        objective="The contract says what the vendor may do with your data.",
        applies=lambda i: _third_party(i) and _personal_data(i),
        satisfied=lambda i: _bool_or_unknown(i.dpa_in_place),
        severity=Severity.CRITICAL,
        remediation=(
            "Execute a data processing agreement before any personal data is sent. "
            "It must cover purpose limitation, subprocessors, breach notification "
            "timelines and deletion on termination."
        ),
        frameworks=(
            _nist("GV.SC", "Supply Chain Risk Management"),
            _iso("5.20", "Addressing information security within supplier agreements"),
            _soc2("CC9.2", "Vendor and business partner risk"),
            _cis("15", "Service Provider Management"),
        ),
        evidence_facts=("dpa_in_place", "vendor", "data_classes"),
        blocking=True,
        why_template="a vendor will process personal data",
        tags=("third-party", "privacy"),
    ),
    Control(
        id="TPR-03",
        title="Subprocessors are known",
        objective="You know who else touches the data behind the vendor.",
        applies=lambda i: _third_party(i) and _personal_data(i),
        satisfied=lambda i: _answered(i.subprocessors),
        severity=Severity.MEDIUM,
        remediation=(
            "Obtain the vendor's subprocessor list and their notification process for "
            "adding one. Your data reaches every name on that list, and the list "
            "changes without you unless the contract says otherwise."
        ),
        frameworks=(
            _nist("GV.SC", "Supply Chain Risk Management"),
            _iso("5.21", "Managing information security in the ICT supply chain"),
            _soc2("CC9.2", "Vendor and business partner risk"),
            _cis("15", "Service Provider Management"),
        ),
        evidence_facts=("subprocessors",),
        why_template="a vendor will process personal data",
        tags=("third-party",),
    ),
    Control(
        id="TPR-04",
        title="Exit plan exists",
        objective="You can get your data out and shut the service down.",
        applies=_third_party,
        satisfied=lambda i: _answered(i.exit_plan),
        severity=Severity.LOW,
        remediation=(
            "Confirm how data is exported and how deletion is evidenced on "
            "termination. Cheapest to negotiate before signature, and hardest to "
            "obtain at the point you actually need it."
        ),
        frameworks=(
            _nist("GV.SC", "Supply Chain Risk Management"),
            _iso("5.22", "Monitoring, review and change management of supplier services"),
            _soc2("CC9.2", "Vendor and business partner risk"),
            _cis("15", "Service Provider Management"),
        ),
        evidence_facts=("exit_plan",),
        why_template="a third-party vendor is involved",
        tags=("third-party", "lifecycle"),
    ),
    Control(
        id="TPR-05",
        title="Cloud service usage is governed",
        objective="The service is on the approved list and configured to standard.",
        applies=lambda i: i.hosting in {Hosting.SAAS, Hosting.CLOUD, Hosting.HYBRID},
        satisfied=_unknown,
        severity=Severity.MEDIUM,
        remediation=(
            "Confirm this service is registered in the software asset inventory and "
            "that its security configuration has been reviewed against the vendor's "
            "own hardening guidance."
        ),
        frameworks=(
            _nist("ID.AM", "Asset Management"),
            _iso("5.23", "Information security for use of cloud services"),
            _soc2("CC6.1", "Logical access security"),
            _cis("2", "Inventory and Control of Software Assets"),
        ),
        evidence_facts=("hosting",),
        why_template="the system runs on cloud or SaaS infrastructure",
        tags=("third-party", "governance"),
    ),
    # --------------------------------------------------------------- exposure
    Control(
        id="NET-01",
        title="Internet exposure is deliberate",
        objective="Anything reachable from the internet is meant to be.",
        applies=lambda i: bool(i.internet_facing),
        satisfied=lambda i: _answered(i.network_notes),
        severity=Severity.MEDIUM,
        remediation=(
            "State who needs to reach this from outside the corporate network. If the "
            "answer is only staff, put it behind the VPN or a zero-trust proxy and "
            "remove the public exposure entirely."
        ),
        frameworks=(
            _nist("PR.IR", "Technology Infrastructure Resilience"),
            _iso("8.20", "Networks security"),
            _soc2("CC6.6", "Boundary protection"),
            _cis("12", "Network Infrastructure Management"),
        ),
        evidence_facts=("internet_facing", "network_notes"),
        why_template="the system is reachable from the internet",
        tags=("exposure",),
    ),
    Control(
        id="NET-02",
        title="Public access to sensitive data is justified",
        objective="Unauthenticated public users do not reach sensitive data.",
        applies=lambda i: UserPopulation.PUBLIC in i.users and (_personal_data(i) or _sensitive(i)),
        satisfied=lambda _: False,
        severity=Severity.CRITICAL,
        remediation=(
            "Separate what the public needs from what is sensitive, and put "
            "authentication in front of the sensitive part. If public access to it is "
            "genuinely intended, this needs explicit sign-off from the data owner and "
            "from legal, not from a design review."
        ),
        frameworks=(
            _nist("PR.AA", "Identity Management, Authentication, and Access Control"),
            _iso("8.3", "Information access restriction"),
            _soc2("CC6.1", "Logical access security"),
            _cis("3", "Data Protection"),
        ),
        evidence_facts=("users", "data_classes"),
        blocking=True,
        why_template="unauthenticated public users are in scope alongside sensitive data",
        tags=("exposure", "data"),
    ),
    # ------------------------------------------------------------ integration
    Control(
        id="INT-01",
        title="Integrations authenticate with scoped credentials",
        objective="Each connection uses its own credential with only the access it needs.",
        applies=lambda i: bool(i.integrations),
        satisfied=lambda i: (
            True if i.integrations and all(a.auth_method for a in i.integrations) else None
        ),
        severity=Severity.HIGH,
        remediation=(
            "For each integration, state how it authenticates and what it can reach. "
            "A single credential shared across integrations means a compromise of the "
            "least important one reaches everything the most important one can."
        ),
        frameworks=(
            _nist("PR.AA", "Identity Management, Authentication, and Access Control"),
            _iso("8.2", "Privileged access rights"),
            _soc2("CC6.1", "Logical access security"),
            _cis("6", "Access Control Management"),
        ),
        evidence_facts=("integrations",),
        why_template="the system connects to other systems",
        tags=("integration",),
    ),
    Control(
        id="INT-02",
        title="Outbound data sharing is intended",
        objective="Data leaving your environment is data you meant to send.",
        applies=lambda i: any(
            a.direction in {"outbound", "bidirectional"} and not a.internal for a in i.integrations
        ),
        satisfied=_unknown,
        severity=Severity.HIGH,
        remediation=(
            "For each outbound connection to an external party, confirm the data "
            "owner has approved what is sent. Integrations tend to be scoped by what "
            "the API makes easy rather than by what the use case needs."
        ),
        frameworks=(
            _nist("PR.DS", "Data Security"),
            _iso("5.14", "Information transfer"),
            _soc2("C1.1", "Confidential information identification"),
            _cis("3", "Data Protection"),
        ),
        evidence_facts=("integrations",),
        why_template="data flows outbound to an external system",
        tags=("integration", "data"),
    ),
    # ---------------------------------------------------------------- logging
    Control(
        id="LOG-01",
        title="Security-relevant events are logged",
        objective="You can reconstruct who did what, after the fact.",
        applies=_always,
        satisfied=lambda i: _answered(i.logging),
        severity=Severity.MEDIUM,
        remediation=(
            "Confirm the system records authentication, administrative actions and "
            "access to sensitive records. Without these, an incident on this system "
            "cannot be investigated — only guessed at."
        ),
        frameworks=(
            _nist("DE.CM", "Continuous Monitoring"),
            _iso("8.15", "Logging"),
            _soc2("CC7.2", "System monitoring"),
            _cis("8", "Audit Log Management"),
        ),
        evidence_facts=("logging",),
        why_template="every system needs an audit trail",
        tags=("logging",),
    ),
    Control(
        id="LOG-02",
        title="Logs reach central monitoring",
        objective="Security operations can see events from this system.",
        applies=lambda i: _personal_data(i) or _sensitive(i) or bool(i.internet_facing),
        satisfied=lambda i: _answered(i.log_destination),
        severity=Severity.MEDIUM,
        remediation=(
            "Forward logs to the central SIEM. Logs that only exist inside the system "
            "being attacked are logs the attacker can reach, and nobody is watching "
            "a console nobody opens."
        ),
        frameworks=(
            _nist("DE.AE", "Adverse Event Analysis"),
            _iso("8.15", "Logging"),
            _soc2("CC7.2", "System monitoring"),
            _cis("8", "Audit Log Management"),
        ),
        evidence_facts=("log_destination",),
        why_template="the system is exposed or holds sensitive data",
        tags=("logging",),
    ),
    Control(
        id="LOG-03",
        title="Log retention is sufficient to investigate",
        objective="Logs outlive the time it takes to notice an incident.",
        applies=lambda i: _personal_data(i) or _sensitive(i),
        satisfied=lambda i: _answered(i.log_retention),
        severity=Severity.LOW,
        remediation=(
            "Confirm logs are retained long enough to investigate a breach discovered "
            "late — intrusions are typically found months after they begin, and "
            "thirty days of logs answers nothing at that point."
        ),
        frameworks=(
            _nist("DE.AE", "Adverse Event Analysis"),
            _iso("8.15", "Logging"),
            _soc2("CC7.3", "Security event evaluation"),
            _cis("8", "Audit Log Management"),
        ),
        evidence_facts=("log_retention",),
        why_template="the system holds sensitive data",
        tags=("logging",),
    ),
    # -------------------------------------------------------------- ownership
    Control(
        id="GOV-01",
        title="A named owner accountable for the system",
        objective="Someone is responsible for this after the project ends.",
        applies=_always,
        satisfied=lambda i: bool(i.owner) or None,
        severity=Severity.LOW,
        remediation=(
            "Name the individual accountable for this system once it is live. "
            "Unowned systems are the ones that miss patches, keep departed users, "
            "and surface in an assessment years later."
        ),
        frameworks=(
            _nist("GV.RR", "Roles, Responsibilities, and Authorities"),
            _iso("5.9", "Inventory of information and other associated assets"),
            _soc2("CC1.3", "Organisational structure and reporting"),
            _cis("1", "Inventory and Control of Enterprise Assets"),
        ),
        evidence_facts=("owner",),
        why_template="every system needs an accountable owner",
        tags=("governance",),
    ),
    Control(
        id="GOV-02",
        title="Endpoint software is managed",
        objective="Software installed on staff machines is deployed and updatable centrally.",
        applies=lambda i: i.hosting is Hosting.ENDPOINT,
        satisfied=_unknown,
        severity=Severity.HIGH,
        remediation=(
            "Deploy through the standard endpoint management tooling so it can be "
            "patched and removed centrally. Software installed outside it cannot be "
            "updated when a vulnerability is announced, and cannot be inventoried."
        ),
        frameworks=(
            _nist("PR.PS", "Platform Security"),
            _iso("8.19", "Installation of software on operational systems"),
            _soc2("CC7.1", "Configuration management"),
            _cis("2", "Inventory and Control of Software Assets"),
        ),
        evidence_facts=("hosting",),
        why_template="the system is software installed on employee endpoints",
        tags=("governance", "endpoint"),
    ),
    Control(
        id="GOV-03",
        title="Incident response covers this system",
        objective="If it is breached, somebody knows what to do.",
        applies=lambda i: _personal_data(i) or _sensitive(i) or _third_party(i),
        satisfied=_unknown,
        severity=Severity.MEDIUM,
        remediation=(
            "Confirm this system is in scope of the incident response plan, and that "
            "the vendor's breach notification timeline is short enough to meet your "
            "own regulatory obligations — many contracts default to far longer."
        ),
        frameworks=(
            _nist("RS.MA", "Incident Management"),
            _iso(
                "5.24",
                "Information security incident management planning and preparation",
            ),
            _soc2("CC7.4", "Incident response"),
            _cis("17", "Incident Response Management"),
        ),
        evidence_facts=("vendor", "data_classes"),
        why_template="the system holds sensitive data or involves a third party",
        tags=("governance", "incident"),
    ),
    Control(
        id="GOV-04",
        title="Review happened before commitment",
        objective="The design can still change when the review lands.",
        applies=_always,
        satisfied=lambda i: i.stage in {"proposed", "design", "in_build"} or None,
        severity=Severity.LOW,
        remediation=(
            "Note that this system is already live or contracted, so findings become "
            "remediation rather than design change. Worth recording — a pattern of "
            "reviews arriving after signature is a process problem, not a system one."
        ),
        frameworks=(
            _nist("ID.RA", "Risk Assessment"),
            _iso("8.25", "Secure development life cycle"),
            _soc2("CC8.1", "Change management"),
            _cis("16", "Application Software Security"),
        ),
        evidence_facts=("stage",),
        why_template="reviews are cheaper before commitment",
        tags=("governance", "process"),
    ),
)


CONTROLS_BY_ID: dict[str, Control] = {c.id: c for c in BUILTIN_CONTROLS}


def known_control_ids() -> set[str]:
    """Every valid control id. The gate rejects a finding citing anything else."""
    return set(CONTROLS_BY_ID)


def frameworks_covered() -> dict[str, int]:
    """How many controls reference each framework. Printed by ``entsec controls``."""
    counts: dict[str, int] = {}
    for entry in BUILTIN_CONTROLS:
        for framework in entry.frameworks:
            counts[framework.name] = counts.get(framework.name, 0) + 1
    return counts
