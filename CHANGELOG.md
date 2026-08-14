# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

A pass over the boundary between what a requesting team types and everything downstream of it, before any of this is published. Several of the items below broke a claim made in README.md or SECURITY.md, and that is its own defect: a security document describing a defence the code does not implement is worse than one that says nothing.

### Fixed

- **A named pipe at the baseline path no longer hangs the review.** The baseline was opened with `O_NOFOLLOW` and then checked for being a regular file — but opening a FIFO for reading blocks *inside* `os.open` until a writer appears, so the check that would have refused it never ran. Anyone able to write the state directory could stop every review indefinitely, with no error, no timeout and nothing in the log. Every read in the tool now sets `O_NONBLOCK` alongside `O_NOFOLLOW` and restores blocking mode once the descriptor is known to be a regular file.
- **Every other file is opened the same way.** The config, the intake form and the attached design document were read with `Path.read_text()` after a separate `is_file()` and `stat()` — two lookups of a name that somebody else can control between them. An intake arrives by email and gets saved into a shared folder; the design document is saved into the same one and its full text is sent to the analysis API, so a symlink planted beside it chose what got transmitted. All three now read through a descriptor, take their size from `fstat`, and refuse anything that is not a regular file.
- **The review is written `0600`, through a descriptor that will not follow a link.** A review names the system, the requesting team, the owner and every gap the evaluation found, which is a short list of where to attack the organisation. It was written at the process umask, to whatever the path resolved to — and the chmod that a fixed umask would have needed, done by path, is itself a way to lock somebody out of their own file.
- **The API host guard fails closed on an address it cannot parse.** It skipped the entry instead, so a host resolving only to such an address was connected to with nothing checked at all.
- **Carrier-grade NAT is refused.** `100.64.0.0/10` is neither private nor reserved on every Python version this supports, and it is where a cloud provider's own internal services sit. The guard now also requires the address to be globally routable unicast, which closes that and anything else the named flags do not cover.
- **A bare URL in an intake answer can no longer become a link in the review.** The escaper covered link *syntax*, and `https://evil.example/approval` uses none of it: GitHub-flavoured Markdown and the ticket systems a review gets pasted into autolink it on sight, putting a live link in a document that carries the security team's name. URL-shaped runs in untrusted text are now rendered inside a code span, where no CommonMark implementation autolinks. Escaping could not fix this one — the autolinker matches the shape of the text rather than a metacharacter. Prose written in this repository is still not escaped.
- **Log records go through a redacting filter, messages and tracebacks alike.** Intake answers are redacted where they enter and nothing logs one on purpose, but an error message quotes what it failed on and a traceback carries the arguments that caused the failure — and the input most likely to hold a real credential is a document somebody else wrote. `httpx`'s URL logging is suppressed for the same reason: the API base is operator-supplied and a self-hosted gateway can carry a token in its path.
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
- CI invariants asserting that every `os.open` in the tree carries `O_NOFOLLOW`, that every read carries `O_NONBLOCK`, that no module reaches around the guarded reader with `read_text`/`write_text`, and that the API host guard refuses every non-public spelling — loopback, RFC1918, link-local, IPv4-mapped, 6to4, NAT64, carrier-grade NAT and an unparseable address — while still allowing a public host.

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
