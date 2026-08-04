"""Command line interface.

Five commands, and the split between them is deliberate.

``questions`` prints the blank intake form. It exists because a security team
that publishes what it will ask gets better answers than one that asks in a
meeting -- the requester can go and find out rather than guess in the room.

``check`` runs the control evaluation and produces a decision with **no API key
and no network call**. This is the command a security team should run first: it
shows exactly what the rules concluded before anyone decides whether to send an
intake to a third-party API, and it is genuinely useful on its own for teams
that would rather not send one at all.

``review`` adds the reasoning layer on top. ``rereview`` reports only what
changed since the last review of the same system, which is the shape that makes
this survivable when a design comes back for the third time.

``controls`` prints the catalog. A team should be able to read what it will be
held to before the tool is pointed at a colleague's project.

Exit codes are a contract:

* ``0`` -- reviewed, nothing at or above ``fail_on``, nothing blocking
* ``1`` -- reviewed, conditions or blocking items apply
* ``2`` -- could not run

1 and 2 are separate on purpose. A pipeline that treats them alike eventually
goes green because the review broke rather than because the design got safer.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from . import report
from . import review as review_module
from .analyze.engine import AnalysisError, Analyzer
from .baseline import BaselineStore, StateError, apply_baseline, state_scope
from .config import Config, load_config
from .controls.catalog import BUILTIN_CONTROLS, frameworks_covered
from .intake import blank_form, load_intake
from .models import Intake
from .validation import ValidationError, safe_text

__version__ = "0.1.0"

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

log = logging.getLogger("entsec")

_MAX_DOC_BYTES = 400_000


def _setup_logging(verbose: bool, quiet: bool) -> None:
    level = logging.DEBUG if verbose else logging.ERROR if quiet else logging.INFO
    logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s")


def _write(text: str, destination: str | None) -> None:
    if not destination:
        sys.stdout.write(text)
        return
    Path(destination).expanduser().write_text(text, encoding="utf-8")
    log.info("wrote %s", destination)


def _attach_document(intake: Intake, path: str | None) -> None:
    """Attach a design document, if one was supplied.

    Separate from intake parsing so the transmission decision is visible: the
    questionnaire is structured and summarised before it is sent, whereas the
    document goes verbatim because prose cannot be summarised without losing
    what makes it useful. That is worth a warning rather than a silent default.
    """
    if not path:
        return
    file_path = Path(path).expanduser()
    if not file_path.is_file():
        raise ValidationError(f"design document not found: {file_path}")
    if file_path.stat().st_size > _MAX_DOC_BYTES:
        raise ValidationError(
            f"design document is above the {_MAX_DOC_BYTES} byte limit. Point at the "
            "section that matters, or rely on the questionnaire alone."
        )
    intake.document_lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    log.info(
        "attached %s (%d lines) — its full text is sent to the analysis API",
        file_path.name,
        len(intake.document_lines),
    )


def _analyzer(config: Config) -> Analyzer:
    if not config.analysis.verify_tls:
        log.warning(
            "TLS verification is disabled: the API key is exposed to anyone on the "
            "network path. This should never be on outside a lab."
        )
    return Analyzer(
        api_key_env=config.analysis.api_key_env,
        model=config.analysis.model,
        api_base=config.analysis.api_base,
        max_tokens=config.analysis.max_tokens,
        timeout=config.analysis.timeout,
        verify_tls=config.analysis.verify_tls,
        allow_internal=config.analysis.allow_internal,
        temperature=config.analysis.temperature,
    )


def _print_drops(result: object, args: argparse.Namespace) -> None:
    """Show what the gate refused, when asked. To stderr, so a redirected
    report is never contaminated."""
    if not getattr(args, "explain_drops", False):
        return
    rejections = getattr(result, "rejections", [])
    if not rejections:
        sys.stderr.write("No proposed findings were rejected on this review.\n")
        return
    sys.stderr.write(f"\n{len(rejections)} finding(s) rejected by the gate:\n")
    for title, reason in rejections:
        sys.stderr.write(f"  - {title}\n    {reason}\n")


def cmd_questions(args: argparse.Namespace) -> int:
    """Print the blank intake form for a requesting team to fill in."""
    _write(blank_form(), args.output)
    return EXIT_OK


def cmd_controls(args: argparse.Namespace) -> int:
    """Print the control catalog, with framework mappings."""
    lines = [
        "# entsec control catalog",
        "",
        f"{len(BUILTIN_CONTROLS)} control objectives. Each applies only when the intake "
        "says it should — a control that is not in scope is absent from the review "
        "entirely rather than listed and marked N/A.",
        "",
        "Framework references per control: "
        + ", ".join(f"{name} ({count})" for name, count in sorted(frameworks_covered().items())),
        "",
        "Mapping a finding to a control identifier does not make a system certified, "
        "and this is not an audit. The mapping exists so a condition can be traced to "
        "an obligation in the language the rest of the organisation already uses.",
        "",
    ]
    for entry in BUILTIN_CONTROLS:
        marker = " · BLOCKING" if entry.blocking else ""
        lines += [
            f"## {entry.id} · {entry.severity.value}{marker} · {entry.title}",
            "",
            entry.objective,
            "",
            f"*Applies when: {entry.why_template}.*",
            "",
            "| Framework | Reference |",
            "|---|---|",
        ]
        lines += [
            f"| {f.name} | {f.identifier}{f' — {f.title}' if f.title else ''} |"
            for f in entry.frameworks
        ]
        lines.append("")
    _write("\n".join(lines).rstrip() + "\n", args.output)
    return EXIT_OK


def cmd_check(args: argparse.Namespace) -> int:
    """Control evaluation and decision. No API key, no network call."""
    config = _config(args)
    intake = load_intake(args.intake)
    if intake.is_empty():
        log.error(
            "the intake has no system name or no answered questions. Refusing to "
            "produce a review of a form nobody filled in."
        )
        return EXIT_ERROR

    result = review_module.check(intake, tool_version=__version__)
    fmt = "check" if config.output_format in {"markdown", "md"} else config.output_format
    text = report.render_check(result) if fmt == "check" else report.render(result, fmt)
    _write(text, args.output)
    return review_module.exit_code(result, config.fail_on)


def cmd_review(args: argparse.Namespace) -> int:
    """The full review: control evaluation plus reasoned findings."""
    config = _config(args)
    intake = load_intake(args.intake)
    _attach_document(intake, args.document)
    if intake.is_empty():
        log.error("the intake has no system name or no answered questions; cannot review.")
        return EXIT_ERROR

    result = review_module.full(intake, _analyzer(config), tool_version=__version__)

    store = BaselineStore(config.state_path, scope=state_scope(intake), retain=config.retain)
    apply_baseline(result, store)
    if not args.no_save:
        store.save(result)

    _write(report.render(result, config.output_format), args.output)
    _print_drops(result, args)
    return review_module.exit_code(result, config.fail_on)


def cmd_rereview(args: argparse.Namespace) -> int:
    """Report only what changed since the last review of this system."""
    config = _config(args)
    intake = load_intake(args.intake)
    _attach_document(intake, args.document)
    if intake.is_empty():
        log.error("the intake has no system name or no answered questions; cannot review.")
        return EXIT_ERROR

    store = BaselineStore(config.state_path, scope=state_scope(intake), retain=config.retain)
    previous = store.previous()
    if previous is None:
        log.error(
            "no previous review of %r. Run `entsec review` once to establish the "
            "baseline, then re-review. Without one there is nothing to compare against, "
            "and reporting everything as new would be useless.",
            intake.system,
        )
        return EXIT_ERROR

    result = review_module.full(intake, _analyzer(config), tool_version=__version__)
    apply_baseline(result, store)

    # Save the FULL result before narrowing. Narrowing first and then saving
    # would write a baseline containing only the deltas, erasing every standing
    # item and re-reporting the whole backlog on the next pass.
    if not args.no_save:
        store.save(result)

    previous_fingerprint = result.baseline_fingerprint
    if previous_fingerprint == intake.fingerprint() and not result.new_findings():
        _write(
            f"# Re-review — {safe_text(intake.system, limit=120)}\n\n"
            "The declared design is unchanged since the last review and no new findings "
            f"were identified.\n\nFingerprint `{intake.fingerprint()}` (unchanged).\n",
            args.output,
        )
        return EXIT_OK

    _write(report.render(result, config.output_format), args.output)
    _print_drops(result, args)
    return review_module.exit_code(result, config.fail_on)


def _config(args: argparse.Namespace) -> Config:
    config = load_config(args.config) if getattr(args, "config", None) else Config()
    if getattr(args, "format", None):
        config.output_format = args.format
    if getattr(args, "state", None):
        config.state_path = args.state
    if getattr(args, "fail_on", None):
        config.fail_on = args.fail_on
    return config


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="entsec",
        description=(
            "Enterprise security design review: threat modelling for the systems "
            "other teams want to build, buy or connect."
        ),
    )
    parser.add_argument("--version", action="version", version=f"entsec {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    def common(sub: argparse.ArgumentParser, *, needs_intake: bool = True) -> None:
        if needs_intake:
            sub.add_argument("-i", "--intake", required=True, help="path to the intake YAML")
        sub.add_argument("-o", "--output", help="write here instead of stdout")
        sub.add_argument("-v", "--verbose", action="store_true")
        sub.add_argument("-q", "--quiet", action="store_true")

    def analysis_args(sub: argparse.ArgumentParser) -> None:
        sub.add_argument("-c", "--config", help="path to a config file")
        sub.add_argument(
            "-d",
            "--document",
            help="design document to attach (its full text is sent to the API)",
        )
        sub.add_argument("-f", "--format", choices=["markdown", "md", "json", "html"])
        sub.add_argument("--state", help="path to the review history database")
        sub.add_argument(
            "--fail-on",
            choices=["critical", "high", "medium", "low", "info"],
            help="exit 1 at or above this severity",
        )
        sub.add_argument("--no-save", action="store_true", help="do not record this review")
        sub.add_argument(
            "--explain-drops",
            action="store_true",
            help="show the findings the gate rejected, and why",
        )

    questions = subparsers.add_parser(
        "questions", help="print the blank intake form for a requesting team"
    )
    common(questions, needs_intake=False)
    questions.set_defaults(func=cmd_questions)

    controls = subparsers.add_parser(
        "controls", help="print the control catalog and its framework mappings"
    )
    common(controls, needs_intake=False)
    controls.set_defaults(func=cmd_controls)

    check = subparsers.add_parser(
        "check", help="control evaluation and decision (no API key, no network)"
    )
    common(check)
    check.add_argument("-c", "--config")
    check.add_argument("-f", "--format", choices=["markdown", "md", "json", "html"])
    check.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "info"])
    check.set_defaults(func=cmd_check)

    review_parser = subparsers.add_parser("review", help="full design review")
    common(review_parser)
    analysis_args(review_parser)
    review_parser.set_defaults(func=cmd_review)

    rereview = subparsers.add_parser(
        "rereview", help="report what changed since the last review of this system"
    )
    common(rereview)
    analysis_args(rereview)
    rereview.set_defaults(func=cmd_rereview)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _setup_logging(getattr(args, "verbose", False), getattr(args, "quiet", False))

    try:
        return int(args.func(args))
    except (ValidationError, StateError) as exc:
        log.error("%s", exc)
        return EXIT_ERROR
    except AnalysisError as exc:
        # Exit 2, not 1. The analysis did not run, so we know nothing about the
        # design -- and "we know nothing" must never share an exit code with
        # "we looked and it was fine".
        log.error("%s", exc)
        return EXIT_ERROR
    except KeyboardInterrupt:
        log.error("interrupted")
        return EXIT_ERROR
    except Exception as exc:
        log.error("entsec failed unexpectedly: %s: %s", type(exc).__name__, exc)
        log.debug("traceback", exc_info=True)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
