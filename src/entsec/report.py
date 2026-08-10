"""Rendering, for two audiences who want different things from one document.

A design review lands in front of two readers. The **requesting team** — a
marketing manager, an IT lead — wants to know whether they can proceed and what
they have to do. They will not read an attack chain, and they should not have
to. The **security reviewer** who owns the sign-off wants the reasoning, the
control mapping and the framework references, because they are the one who will
defend the decision.

Writing two documents solves it and creates a worse problem: they drift, and the
requester ends up acting on the wrong one. So this is one document in two parts.
The decision and the conditions come first, in plain language, and everything
underneath is the evidence for them. A requester who reads only the top of the
page has read everything they need; a reviewer who reads on finds the argument.

The ordering is deliberate and slightly unusual: conditions before findings.
Most security reports lead with what is wrong, which is the author's ordering
rather than the reader's. Somebody who has been told to fix something wants the
list first and the justification second.

Escaping: intake answers are written by another team and reach tickets and
chat. A system named ``x ![](https://evil/px.png)`` must not put a tracking
pixel in the review. Each renderer escapes for its own syntax — Markdown prose,
Markdown code spans and HTML each need different treatment, and using one
everywhere either leaves a hole or prints backslashes at the reader.
"""

from __future__ import annotations

import html
import json
import re
from typing import Any

from .analyze.severity import explain
from .models import Decision, Finding, Review, Severity

_SEVERITY_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}

_DECISION_LABEL = {
    Decision.APPROVED: ("✅", "Approved"),
    Decision.APPROVED_WITH_CONDITIONS: ("🟡", "Approved with conditions"),
    Decision.CHANGES_REQUIRED: ("🔴", "Changes required"),
    Decision.INSUFFICIENT_INFORMATION: ("⚪", "Insufficient information"),
}

_SEVERITY_COLOR = {
    Severity.CRITICAL: "#b3261e",
    Severity.HIGH: "#e8590c",
    Severity.MEDIUM: "#b7791f",
    Severity.LOW: "#1e6fb8",
    Severity.INFO: "#5f6b7a",
}

_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")

# Backtick breaks out of a code span; bracket, paren and bang build links and
# images. Emphasis markers are deliberately absent — escaping them renders every
# ``on_prem`` as ``on\_prem`` and the worst they achieve is bold text.
_MD_ESCAPE_RE = re.compile(r"([`\[\]()!])")


def _md(text: object) -> str:
    r"""Escape UNTRUSTED text for Markdown prose.

    Applied by provenance, not everywhere. Three sources of text end up in a
    review and only two of them are untrusted:

    * **Intake answers** -- written by another team, and a system named
      ``x ![](https://evil/px.png)`` must not put a tracking pixel in a document
      that goes to a ticket. Escaped.
    * **Model output** -- finding titles and conditions, which are derived from
      those same intake answers. Escaped.
    * **Catalog and decision text** -- written in this repository and reviewed
      in pull requests. NOT escaped, because escaping it renders every
      ``gap(s)`` as ``gap\(s\)`` and every ``(SAML or OIDC)`` as
      ``\(SAML or OIDC\)``, which makes the document look broken and teaches
      the reader that the tool is careless.

    Getting this backwards in either direction is a real failure: escape too
    little and a report carries a payload, escape too much and nobody trusts a
    document that cannot punctuate.
    """
    collapsed = " ".join(_CONTROL_CHARS_RE.sub(" ", str(text)).split())
    escaped = _MD_ESCAPE_RE.sub(r"\\\1", collapsed).replace("<", "&lt;")
    if escaped.startswith(">"):
        escaped = "&gt;" + escaped[1:]
    return escaped


def _prose(text: object, *, trusted: bool) -> str:
    r"""Render one line of prose according to where it came from.

    Provenance is decided once, here, so it reads the same at every call site.
    Both halves of getting it wrong have happened in this file: question text
    went out unescaped for every question in the review, including the ones
    quoting an answer somebody typed, and review notes went out escaped even
    though every one of them is written in this repository, so the reader was
    told "3 proposed finding\(s\) were rejected".
    """
    return str(text) if trusted else _md(text)


def _code(text: object) -> str:
    """Prepare a value for inside a Markdown code span.

    Backslash escapes are inert inside backticks, so :func:`_md` here would
    print them literally. The backtick would close the span and is replaced;
    ``<`` and ``>`` are entity-escaped as a second line of defence for renderers
    that mishandle code spans.
    """
    collapsed = " ".join(_CONTROL_CHARS_RE.sub(" ", str(text)).split())
    return collapsed.replace("`", "'").replace("<", "&lt;").replace(">", "&gt;")


def render_markdown(review: Review) -> str:
    intake = review.intake
    emoji, label = _DECISION_LABEL[review.decision]
    counts = review.counts_by_severity()
    conditions = review.conditions()
    blocking_questions = review.blocking_questions()

    lines: list[str] = [
        f"# Security design review — {_md(intake.system or 'unnamed system')}",
        "",
        f"## {emoji} {label}",
        "",
        review.decision_rationale,
        "",
    ]

    # Attribution before anything else. A review with no named requester is a
    # review nobody follows up.
    meta = [
        f"**Requested by** {_md(intake.requesting_team or 'not stated')}",
        f"**System owner** {_md(intake.owner or 'not named')}",
        f"**Stage** {_md(intake.stage)}",
    ]
    if intake.vendor:
        meta.append(f"**Vendor** {_md(intake.vendor)}")
    lines += [" · ".join(meta), ""]

    tally = " · ".join(f"{counts[s.value]} {s.value}" for s in Severity if counts[s.value])
    lines.append(
        f"{len(review.applicable_controls)} controls in scope · "
        f"{len(review.satisfied_controls)} satisfied · "
        f"{len(review.gaps)} gaps · {len(review.findings)} additional findings"
        + (f" · {tally}" if tally else "")
    )
    lines.append(
        f"Review confidence **{review.confidence.value}** · "
        f"design fingerprint `{intake.fingerprint()}`"
        + (
            f" (was `{_code(review.baseline_fingerprint)}`)"
            if review.baseline_fingerprint and review.baseline_fingerprint != intake.fingerprint()
            else ""
        )
    )
    lines.append("")

    # ---- The requester's half -------------------------------------------
    if conditions:
        lines += [
            "## What you need to do",
            "",
            "Each item below is a condition of this review. If anything is impractical, "
            "come back to the security team rather than proceeding around it — most have "
            "an alternative that is cheaper than the one you are avoiding.",
            "",
        ]
        for index, (action, reason, trusted) in enumerate(conditions, start=1):
            # Escaped only when it came from the model. Catalog remediation is
            # written in this repository, and escaping it printed
            # "\(SAML or OIDC\)" at the reader.
            lines.append(f"{index}. {_prose(action, trusted=trusted)}")
            lines.append(f"   *Why: {_prose(reason, trusted=trusted)}*")
        lines.append("")

    if blocking_questions:
        lines += [
            "## Questions we need answered",
            "",
            "The decision above cannot be settled until these are answered. They are "
            "questions rather than findings because guessing either way would be wrong: "
            "assuming the best waves through real risk, assuming the worst blocks a "
            "project over something that may already be handled.",
            "",
        ]
        for question in blocking_questions[:10]:
            lines.append(f"- {_prose(question.text, trusted=question.trusted)}")
            if question.why_it_matters:
                lines.append(f"  *{_prose(question.why_it_matters, trusted=question.trusted)}*")
        lines.append("")

    # ---- The reviewer's half --------------------------------------------
    if review.gaps:
        lines += [f"## Control gaps ({len(review.gaps)})", ""]
        for gap in review.gaps:
            marker = " · **BLOCKING**" if gap.blocking else ""
            lines += [
                f"### {gap.control_id} · {_SEVERITY_EMOJI[gap.severity]} "
                f"{gap.severity.value.upper()}{marker} · {gap.title}",
                "",
                f"{gap.what_is_missing} {gap.why_applicable}",
                "",
                f"**Fix** {gap.remediation}",
            ]
            if gap.frameworks:
                refs = " · ".join(f"`{_code(f)}`" for f in gap.frameworks)
                lines.append(f"**Maps to** {refs}")
            lines.append("")

    if review.findings:
        new_keys = review.new_finding_keys
        lines += [f"## Additional findings ({len(review.findings)})", ""]
        lines.append(
            "Risks that arise from how these facts combine, rather than from any single "
            "control. Produced by analysis over the declared design.",
        )
        lines.append("")
        for finding in review.findings:
            lines += _render_finding(finding, finding.key() in new_keys)

    other_questions = [q for q in review.questions if not q.blocks_decision]
    if other_questions:
        lines += [f"## Open questions ({len(other_questions)})", ""]
        lines += [f"- {_prose(q.text, trusted=q.trusted)}" for q in other_questions[:20]]
        lines.append("")

    if review.satisfied_controls:
        lines += [
            f"## Controls satisfied ({len(review.satisfied_controls)})",
            "",
            "Recorded so the review shows what the design got right, and so a reader can "
            "see the check was made rather than skipped.",
            "",
            "```",
            ", ".join(_code(c) for c in review.satisfied_controls),
            "```",
            "",
        ]

    if review.dropped_findings:
        lines += [
            f"> {review.dropped_findings} proposed finding(s) failed validation and were "
            "discarded — they cited intake facts or control identifiers that do not exist. "
            "Run with `--explain-drops` to see them.",
            "",
        ]

    # Notes are written in this repository -- the confidence sentence, the
    # rejection count, the fingerprint comparison -- so they are not escaped.
    # Escaping them printed "finding\(s\)" and "review \(fingerprint 3f2a\)",
    # which is the same carelessness the reader would read into a backslash
    # anywhere else on the page.
    if review.notes:
        lines += ["## Review notes", ""] + [f"- {n}" for n in review.notes[:12]] + [""]

    lines += [
        "---",
        f"_entsec {review.tool_version} · reviewed {review.reviewed_at}_  ",
        "_This review reflects the design as declared on the intake form. A material "
        "change to the design warrants a re-review._",
    ]
    return "\n".join(lines).rstrip() + "\n"


def _render_finding(finding: Finding, is_new: bool) -> list[str]:
    marker = " · **NEW**" if is_new else ""
    lines = [
        f"### {finding.id} · {_SEVERITY_EMOJI[finding.severity]} "
        f"{finding.severity.value.upper()}{marker} · {_md(finding.title)}",
        "",
        f"*{_md(explain(finding.exposed_to, finding.data_at_risk, len(finding.preconditions)))}*",
        "",
        "```",
        "  →  ".join(_code(step) for step in finding.chain),
        "```",
        "",
    ]
    if finding.preconditions:
        lines.append(f"**Requires** {' · '.join(_md(p) for p in finding.preconditions)}")
    if finding.condition:
        lines.append(f"**Fix** {_md(finding.condition)}")
    if finding.because:
        lines.append(f"**Because** {_md(finding.because)}")
    if finding.control_ids:
        lines.append(f"**Controls** {', '.join(f'`{_code(c)}`' for c in finding.control_ids)}")
    if finding.frameworks:
        refs = " · ".join(f"`{_code(f)}`" for f in finding.frameworks[:6])
        lines.append(f"**Maps to** {refs}")
    if finding.fact_ids:
        lines.append(f"**From** {', '.join(f'`{_code(f)}`' for f in finding.fact_ids)}")
    lines.append("")
    return lines


def render_json(review: Review) -> str:
    return json.dumps(review.to_dict(), indent=2, ensure_ascii=False) + "\n"


def render_check(review: Review) -> str:
    """The control evaluation alone, with no reasoning layer.

    Printed by ``entsec check``, which needs no API key. Its purpose is to let a
    security team see exactly what the deterministic half concluded before they
    ever send an intake to a third-party API — and to give them something usable
    when they would rather not send one at all.
    """
    intake = review.intake
    emoji, label = _DECISION_LABEL[review.decision]
    lines = [
        f"# Control check — {_md(intake.system or 'unnamed system')}",
        "",
        f"## {emoji} {label}",
        "",
        review.decision_rationale,
        "",
        f"{len(review.applicable_controls)} controls in scope · "
        f"{len(review.satisfied_controls)} satisfied · {len(review.gaps)} gaps · "
        f"{len(review.blocking_questions())} blocking question(s) of "
        f"{len(review.questions)} open",
        "",
        "This is the deterministic half of a review: applicability, gaps and the "
        "decision, computed from the intake with no model involved. Run `entsec review` "
        "to add analysis of how these facts combine.",
        "",
    ]

    if review.gaps:
        lines += ["## Gaps", ""]
        for gap in review.gaps:
            marker = " BLOCKING" if gap.blocking else ""
            lines.append(f"- **{gap.control_id}**{marker} · {gap.severity.value} · {gap.title}")
            lines.append(f"  {gap.remediation}")
        lines.append("")

    blocking = review.blocking_questions()
    if blocking:
        lines += ["## Questions blocking the decision", ""]
        lines += [f"- {_prose(q.text, trusted=q.trusted)}" for q in blocking[:15]]
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def render_html(review: Review) -> str:
    """A standalone page. No external assets, no JavaScript."""
    intake = review.intake
    emoji, label = _DECISION_LABEL[review.decision]
    colour = {
        Decision.APPROVED: "#1a7f37",
        Decision.APPROVED_WITH_CONDITIONS: "#b7791f",
        Decision.CHANGES_REQUIRED: "#b3261e",
        Decision.INSUFFICIENT_INFORMATION: "#5f6b7a",
    }[review.decision]

    conditions = "".join(
        f"<li><strong>{html.escape(action)}</strong><br><em>{html.escape(reason)}</em></li>"
        for action, reason, _ in review.conditions()
    )
    conditions_block = (
        f"<section><h2>What you need to do</h2><ol>{conditions}</ol></section>"
        if conditions
        else ""
    )

    gap_blocks = "".join(
        f'<article><h3><span class="sev" style="background:{_SEVERITY_COLOR[g.severity]}">'
        f"{html.escape(g.severity.value.upper())}</span> {html.escape(g.control_id)} · "
        f"{html.escape(g.title)}"
        + ('<span class="blocking">BLOCKING</span>' if g.blocking else "")
        + f"</h3><p>{html.escape(g.what_is_missing)} {html.escape(g.why_applicable)}</p>"
        f"<dl><dt>Fix</dt><dd>{html.escape(g.remediation)}</dd>"
        + (
            "<dt>Maps to</dt><dd><code>"
            + html.escape(" · ".join(str(f) for f in g.frameworks))
            + "</code></dd>"
            if g.frameworks
            else ""
        )
        + "</dl></article>"
        for g in review.gaps
    )

    finding_blocks = "".join(
        f'<article><h3><span class="sev" style="background:{_SEVERITY_COLOR[f.severity]}">'
        f"{html.escape(f.severity.value.upper())}</span> {html.escape(f.id)} · "
        f"{html.escape(f.title)}</h3>"
        f"<pre>{html.escape('  →  '.join(f.chain))}</pre>"
        f"<dl><dt>Fix</dt><dd>{html.escape(f.condition)}</dd></dl></article>"
        for f in review.findings
    )

    questions = "".join(f"<li>{html.escape(q.text)}</li>" for q in review.blocking_questions()[:10])
    questions_block = (
        f'<section class="notice"><h2>Questions we need answered</h2><ul>{questions}</ul>'
        "<p>The decision cannot be settled until these are answered.</p></section>"
        if questions
        else ""
    )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security design review — {html.escape(intake.system)}</title>
<style>
 :root {{ color-scheme: light dark; }}
 body {{ font: 15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
        margin:0; padding:2rem; max-width:900px; margin-inline:auto; }}
 h1 {{ font-size:1.45rem; margin:0 0 .5rem; }}
 h2 {{ font-size:1.05rem; margin:2rem 0 .75rem; }}
 h3 {{ font-size:.95rem; margin:0 0 .4rem; font-weight:600; }}
 .decision {{ border-left:5px solid {colour}; padding:.8rem 1rem; margin:1rem 0 1.5rem;
             background:#00000008; }}
 .decision b {{ font-size:1.1rem; }}
 .meta {{ color:#6b7280; font-size:.85rem; margin-bottom:1.5rem; }}
 .sev {{ color:#fff; padding:.1rem .45rem; border-radius:4px; font-size:.7rem; font-weight:600; }}
 .blocking {{ background:#b3261e; color:#fff; padding:.05rem .35rem; border-radius:3px;
              font-size:.65rem; margin-left:.4rem; }}
 article {{ border:1px solid #d1d5db; border-radius:8px; padding:1rem; margin-bottom:1rem; }}
 pre {{ background:#00000010; padding:.6rem .8rem; border-radius:6px; overflow-x:auto;
        font-size:.82rem; }}
 dl {{ display:grid; grid-template-columns:max-content 1fr; gap:.3rem .9rem; font-size:.88rem; }}
 dt {{ font-weight:600; color:#6b7280; }}
 dd {{ margin:0; }}
 ol li {{ margin-bottom:.6rem; }}
 .notice {{ border-left:3px solid #d97706; padding-left:1rem; }}
 footer {{ margin-top:2rem; color:#6b7280; font-size:.8rem; }}
</style></head><body>
<h1>Security design review — {html.escape(intake.system)}</h1>
<div class="decision"><b>{emoji} {html.escape(label)}</b><br>
{html.escape(review.decision_rationale)}</div>
<p class="meta">Requested by {html.escape(intake.requesting_team or "not stated")} ·
 owner {html.escape(intake.owner or "not named")} · stage {html.escape(intake.stage)} ·
 {len(review.applicable_controls)} controls in scope, {len(review.satisfied_controls)} satisfied ·
 confidence {html.escape(review.confidence.value)} ·
 fingerprint <code>{html.escape(intake.fingerprint())}</code></p>
{conditions_block}
{questions_block}
{f"<h2>Control gaps ({len(review.gaps)})</h2>{gap_blocks}" if gap_blocks else ""}
{f"<h2>Additional findings ({len(review.findings)})</h2>{finding_blocks}" if finding_blocks else ""}
<footer>entsec {html.escape(review.tool_version)} · reviewed {html.escape(review.reviewed_at)}<br>
This review reflects the design as declared on the intake form. A material change
warrants a re-review.</footer>
</body></html>
"""


def render(review: Review, fmt: str) -> str:
    renderers: dict[str, Any] = {
        "markdown": lambda: render_markdown(review),
        "md": lambda: render_markdown(review),
        "json": lambda: render_json(review),
        "html": lambda: render_html(review),
    }
    renderer = renderers.get(fmt)
    if renderer is None:
        raise ValueError(f"unknown format {fmt!r}; use markdown, json or html")
    # Called outside the lookup guard: wrapping both would report a KeyError
    # raised inside a renderer as "unknown format 'markdown'".
    return str(renderer())
