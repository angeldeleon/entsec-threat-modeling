# entsec

Security design review for enterprise environments. Another team wants to build, buy or connect something — entsec works out which controls apply, what is missing, and whether it can proceed.

[![CI](https://github.com/angeldeleon/entsec/actions/workflows/ci.yml/badge.svg)](https://github.com/angeldeleon/entsec/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)

## The problem

Marketing wants a webinar platform. IT wants a new MDM. Finance wants a SaaS vendor wired into the ERP. Each lands in the security team's queue as a design review, and each gets one of two outcomes: a thorough review that takes a week and arrives after the contract is signed, or a twenty-minute skim that catches nothing.

The usual fix is a checklist. Checklists fail because they ask every question of every project, so the reviewer wades through forty irrelevant items to find the three that matter, and the requesting team learns that the process is theatre.

entsec is the same review, made cheap enough to run every time.

## What it produces

A decision, then the conditions, then the reasoning underneath:

```
# Security design review — Brightwave Webinar Platform

## 🔴 Changes required

2 blocking control gaps (NET-02, TPR-02) mean this cannot proceed as described.
These are not conditions that can be carried with a date: proceeding would breach
an obligation that is already in force.

Requested by Marketing · System owner not named · Stage proposed · Vendor Brightwave Inc
23 controls in scope · 2 satisfied · 3 gaps · 7 blocking questions of 27 open

## What you need to do

1. Execute a data processing agreement before any personal data is sent. It must
   cover purpose limitation, subprocessors, breach notification and deletion.
   *Why: Data processing agreement in place*
2. Separate what the public needs from what is sensitive, and put authentication
   in front of the sensitive part.
   *Why: Public access to sensitive data is justified*
```

Two audiences, one document. The requesting team reads the top and knows what to do. The security reviewer reads on and finds the control mapping, the framework references and the reasoning — because they are the one who has to defend the decision six months later.

## Why you can trust the output

A language model asked to review a design will warn about an integration nobody mentioned, cite a control that does not exist, and write both in the same confident register as its correct findings. In a design review that is worse than in a code review, because the finding goes to another team as a condition they must satisfy, and the person receiving it has no way to tell.

So the model is not in charge of anything that matters.

**The decision is computed, not reasoned.** Which controls apply, which the answers satisfy, which they do not, and whether the design proceeds — all of it is a pure function of the intake form. Run it twice, get the same answer. Disagree with the answer and you can point at the line that produced it. `entsec check` runs this half with **no API key and no network call**.

**The model may only cite what exists.** Findings must reference intake facts the requesting team actually declared and control identifiers that are in the catalog. Anything else is dropped before you see it, and the drop is counted. An invented control reference is the most damaging error this tool could make — it survives into a ticket, into a GRC tracker, and into an audit conversation where somebody looks it up.

**Claims are clamped to the declared design.** A finding cannot claim wider exposure than the intake declares, or more sensitive data than the requester said the system holds. The model cannot make a system scarier than its own form.

**Severity is arithmetic.** Ask a model for a rating and it anchors on the drama of its own prose. Ratings here come from who is exposed, what data is at risk, and how many preconditions are unverified.

**Unknown is never treated as absent.** A blank field becomes a question, not a finding. Automated assessment tools lose the goodwill of engineering teams faster through false accusation than through anything else, and that goodwill is the whole process.

## Install

```bash
pip install entsec
```

## Usage

```bash
entsec questions                     # the blank intake form, to send to the requester
entsec controls                      # what you will be held to, and its framework mappings
entsec check    -i intake.yml        # controls + decision. No API key, no network.
entsec review   -i intake.yml -d design.md -o review.md
entsec rereview -i intake.yml        # only what changed since the last review
```

Set `ANTHROPIC_API_KEY` for `review` and `rereview`.

Start with `entsec questions`. A security team that publishes what it will ask gets better answers than one that asks in a meeting, because the requester can go and find out rather than guess in the room.

## Framework mapping

Every control carries its references, so a condition traces to an obligation in the language the rest of the organisation already uses:

| Framework | Used for |
|---|---|
| **NIST CSF 2.0** | Function and category references — broad, and readable by non-security teams |
| **ISO 27001:2022 Annex A** | What an ISO auditor expects a review to cite |
| **SOC 2 TSC** | The common language for SaaS and vendor assessment |
| **CIS Controls v8** | The most prescriptive — good for conditions handed to IT |

Control identifiers are taken from the published frameworks. The mapping *between* them is editorial judgement and is meant to be argued with — [`controls/catalog.py`](src/entsec/controls/catalog.py) is one reviewable table for exactly that reason.

Mapping a finding to ISO A.5.23 does not make a system certified, and this is not an audit. See Limitations.

## Re-review

The second review of the same system reports only what the change introduced. Designs come back — a vendor is swapped, a data type is added, an integration appears — and re-reading a full review each time is how the process gets skipped.

Comparison is on the *structure* of the declared design, not its wording, so rephrasing a purpose statement is not a change and does not resurface anything.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Reviewed, nothing at or above `fail_on`, nothing blocking |
| 1 | Reviewed, conditions or blocking items apply |
| 2 | Could not run |

1 and 2 are separate on purpose. A pipeline that treats them alike eventually goes green because the review broke rather than because the design got safer.

## What leaves your infrastructure

`check`, `questions` and `controls` send nothing. They are local and need no key.

`review` and `rereview` send the intake answers and, if you attach one with `-d`, the design document in full — prose cannot be summarised without losing what makes it useful. Credential-shaped strings are redacted before anything is sent. If a design document is too sensitive to leave your network, run `check` and do the reasoning half yourself; the control evaluation and the decision are identical either way.

The review history database is a list of every system reviewed and every gap found. It is created `0600` and gitignored by default.

## Limitations

Worth knowing before you rely on it:

- **It reviews what the requester declared, not what exists.** Every fact comes from a form another team filled in. A wrong answer produces a wrong review — attributably, since each fact records the question it answered, but wrong. This is an assessment of a design, not verification of a system.
- **This is not an audit and not a certification.** Framework references exist to place a finding in familiar language. An auditor wants evidence of operating effectiveness, which is a different exercise entirely.
- **The control catalog is a starting point, not your policy.** Twenty-five objectives covering identity, data, third-party, exposure, integration, logging and governance. Your organisation has requirements that are not in it, and some of these will not fit how you work. Fork the catalog — it is one file and it is meant to be edited.
- **The model is in the trust path for findings, though not for the decision.** A plausible-but-wrong finding that cites real facts and real controls will get through. Treat the findings section as a strong prompt for a human reviewer. The gaps and the decision do not have this property, which is why they are computed.
- **It does not read code.** A repository scanner exists in the sibling project [threatdrift](https://github.com/angeldeleon/threatdrift) for reviews that involve internal builds.

## Security design

Full detail in [SECURITY.md](SECURITY.md). The short version: intake is `yaml.safe_load` only with unknown keys rejected; intake text is treated as attacker-influenced and escaped per renderer; credential shapes are redacted before transmission; the API base is SSRF-guarded and redirects are refused; review history is SQLite at `0600` opened with `O_NOFOLLOW`.

CI runs ruff, mypy, bandit and pip-audit, and asserts the invariants a review would miss — including that no framework identifier in the catalog is malformed, and that the decision is never read from model output.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The most useful contribution is a control objective: one entry, its applicability rule, and its four framework references.

Security issues: [private reporting](https://github.com/angeldeleon/entsec/security/advisories/new), not a public issue.

## License

Apache 2.0.
