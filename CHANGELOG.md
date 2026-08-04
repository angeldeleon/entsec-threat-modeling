# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-08-03

Initial release.

- Structured intake questionnaire as the declared fact base, with blank treated as unknown rather than as failure.
- Twenty-five control objectives with computed applicability, each mapped to NIST CSF 2.0, ISO 27001:2022 Annex A, SOC 2 TSC and CIS Controls v8.
- A computed decision — approved, approved with conditions, changes required, or insufficient information — derived from control gaps rather than from model output.
- `entsec check` runs the full control evaluation and decision with no API key and no network call.
- Model-assisted findings for risks that arise from how declared facts combine, schema-forced and validated against declared facts and catalog control ids.
- Re-review: the second review of a system reports only what the design change introduced.
- Two-audience report — conditions for the requesting team, control mapping and reasoning for the reviewer. Markdown, JSON and HTML.
