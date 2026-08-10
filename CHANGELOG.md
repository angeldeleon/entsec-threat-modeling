# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

A pass over the boundary between what a requesting team types and everything downstream of it, before any of this is published. Several of the items below broke a claim made in README.md or SECURITY.md, and that is its own defect: a security document describing a defence the code does not implement is worse than one that says nothing.

### Fixed

- **Intake text is sanitised and then redacted, in that order.** It ran the other way round, so a zero-width space inside a credential meant no pattern matched — and the sanitising step then deleted the space and reassembled the key, in the stored value, in the API payload and in the report. Every pattern could be beaten this way by anyone able to type into the form.
- **An attached design document goes through the same scrub as the answers.** `-d` sends the file in full, which makes it the input most likely to hold a real credential, and it was the one input nothing redacted.
- **A bare-string integration entry is redacted like any other answer.** `integrations: [postgres://svc:pw@db/app]` is the obvious way to answer "what does this connect to". It took a branch that sanitised without redacting, so the password reached the API and the JSON report while the same string written as a mapping was redacted.
- **An answer the parser cannot map is redacted and escaped before it is quoted back.** It was interpolated raw into the questions section, so a data type containing an access key, an image and a newline put all three into the report — including a heading of the requester's choosing, under the review's own name.
- **One pass over the finished intake now guarantees all of the above.** Cleaning at each parse site is a discipline, and each of the leaks above was a single missing call. A field added later is covered by the walk whether or not whoever adds it knows the rule.
- **Model prose goes through the same scrub on the way back in.** Finding titles, chains and conditions are written to the review database as well as the report; the intake they are written from is redacted, so nothing should reach them, which is the reason to close it rather than to argue about whether it can happen. Fact and control ids are left alone, because they are compared against known sets and that comparison should not depend on a redaction pattern.
- **Question text is escaped by provenance at every renderer**, the way conditions already were: questions quoting an answer are escaped, questions quoting the form are not.
- **Review notes are no longer escaped.** Every one is written in this repository, and the reader was being told "3 proposed finding\(s\) were rejected".
- **Redaction stays linear on hostile input.** The URL pattern's tail ran to the end of the field looking for an `@` that was not there, once per candidate scheme, so `check` — the local command that makes no network call — spent 34 seconds of CPU on a 200 KB intake.
- **A question from the analysis layer can no longer block the decision.** A blocking question turns an approval into insufficient-information and makes the exit code 1, so it was part of the verdict, and the verdict is computed from the intake. The flag is no longer asked for, and the merge that brings those questions into a review refuses to set it.
- **Exposure and data class have floors as well as ceilings.** Clamping only downward from what was declared left understatement free, and understatement is the half nobody notices: "report every finding as reaching administrators only" moved a critical finding to informational, which moved the review from approved-with-conditions to approved and the exit code from 1 to 0. A claim may now sit at most two bands below the declared design.
- **The CI check for over-escaped prose can now fail.** It was `grep -qv`, which inverts per line and so exits 0 as long as one line lacks the pattern. It had never failed, and the thing it was watching for was in the report.
- **`state_scope` says what it does.** The docstring claimed the baseline was keyed on something other than the display name; it is the declared system name, and renaming the system starts a new history.

### Added

- A CI invariant asserting that nothing credential-shaped reaches the API payload or any of the three report formats.

### Removed

- The repository-scanning code — scan-root jail, symlink and hardlink refusal, file walking — and the module docstring describing entsec as reading a directory it did not write. None of it was reachable: this tool reads a form and a document, not a repository. Unused security machinery in a published security tool is a liability, because a reader assumes it is load-bearing.
- Unused baseline helpers (`titles_for`, `run_count`, `resolved_paths`, `key_of`) and `catalog.control`.

## [0.1.0] — 2026-08-03

Initial release.

- Structured intake questionnaire as the declared fact base, with blank treated as unknown rather than as failure.
- Twenty-five control objectives with computed applicability, each mapped to NIST CSF 2.0, ISO 27001:2022 Annex A, SOC 2 TSC and CIS Controls v8.
- A computed decision — approved, approved with conditions, changes required, or insufficient information — derived from control gaps rather than from model output.
- `entsec check` runs the full control evaluation and decision with no API key and no network call.
- Model-assisted findings for risks that arise from how declared facts combine, schema-forced and validated against declared facts and catalog control ids.
- Re-review: the second review of a system reports only what the design change introduced.
- Two-audience report — conditions for the requesting team, control mapping and reasoning for the reviewer. Markdown, JSON and HTML.
