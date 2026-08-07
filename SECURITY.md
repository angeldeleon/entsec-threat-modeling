# Security Policy

## Reporting a vulnerability

Report privately through GitHub's [private vulnerability reporting](https://github.com/angeldeleon/entsec-threat-modeling/security/advisories/new) rather than opening a public issue.

Include affected version, reproduction steps, and impact. I aim to acknowledge within 72 hours and to ship a fix or mitigation plan within 30 days for confirmed issues.

## What this tool is, and is not

**It is not an audit.** Framework references exist so a condition can be traced to an obligation in language the organisation already uses. An auditor wants evidence of operating effectiveness over a period; this reviews a design at a point in time, against what a requesting team declared.

**It reviews declarations, not systems.** Every fact comes from a form somebody else filled in. A wrong answer produces a wrong review. It is attributable — each fact records the question it answered — but it is still wrong, and no amount of processing downstream fixes it.

**The model is in the trust path for findings, but not for the decision.** That split is the design. Applicability, control gaps and the verdict are pure functions of the intake, so they are reproducible and defensible. The findings section is model-generated and constrained but not guaranteed: a plausible-but-wrong finding citing real facts and real controls can get through. Treat it as a strong prompt for a human reviewer.

## Threat model

entsec runs on a security team's machine, reads a form completed by another team, and transmits a distilled version of it to a third-party API.

| Threat | Mitigation |
|---|---|
| **Secrets pasted into the intake form** — requesters put connection strings and service-account keys in free-text answers routinely | Credential shapes are redacted in `Component`-equivalent construction and at every renderer, before storage and before transmission. Redacting at one sink would mean remembering to do it at four |
| **Prompt injection through the intake or design document** | Structural, not textual. Fabricated findings are caught by the gate. Suppressed findings are bounded by the deterministic evaluation, which produces the gaps and the decision whether or not the model cooperates — `entsec check` needs no API key and cannot be talked out of anything |
| **Fabricated findings and invented control references** | Every finding must cite intake facts that were actually declared and control identifiers that exist in the catalog. Failures are dropped, counted, and surfaced. An invented control reference is the most damaging error available here: it survives into a ticket, a GRC tracker, and an audit conversation |
| **Severity inflation** | The model does not choose severities. Exposure is clamped to the widest declared user population, data at risk to the most sensitive declared class. The formula is in `analyze/severity.py` |
| **Severity suppression** — the mirror image, and the one that quietly passes a review | The precondition penalty is capped at three. Uncapped, the model sets its own band by choosing how many preconditions to list, while every individual claim still passes the gate |
| **False accusation of a requesting team** | A blank answer produces a question, never a gap. An answer the parser cannot interpret is unknown, not false. This is the failure mode that ends adoption, because the goodwill of the teams being reviewed is what the process runs on |
| **Report injection** — a system or vendor named to forge a line or embed a link | Intake text is sanitised (control characters collapsed, invisible and bidi characters dropped, unpaired surrogates replaced) and escaped again per renderer. Escaping is applied **by provenance**: intake and model output are escaped, catalog and decision text is not, because over-escaping renders `gap(s)` as `gap\(s\)` and teaches the reader the tool is careless |
| **SSRF via the API base URL** | The base is operator-configurable, so it is validated and its host resolved before connecting; loopback, RFC1918, link-local, reserved and IPv4-mapped spellings are refused. Redirects are not followed |
| **Code execution via config or intake** | `yaml.safe_load` only, size-capped, unknown keys rejected in both |
| **Secret leakage through config** | Secrets come from the environment, never the file. A `*_env` field containing a URL or path is rejected |
| **Review history theft via symlink** | The database lists every system reviewed and every gap found — a map of where the organisation is weakest. Created `0600` before SQLite opens it, opened with `O_NOFOLLOW` on every open, and the parent chain is validated because `O_NOFOLLOW` covers only the final component |
| **A failed review reading as approval** | An empty intake raises rather than returning a clean result. Blocking items always produce exit 1 regardless of severity threshold. Exit 2 is reserved for could-not-run and is never shared with ran-and-found-nothing |

### Explicitly out of scope

- **Verifying anything.** The tool does not connect to the system, the vendor, or the identity provider. It reads a form.
- **Completeness of the catalog.** Twenty-five objectives is a starting point, not a policy. Your organisation has requirements that are not here.
- **The correctness of the model's reasoning.** See above.
- **DNS rebinding against the API base.** The host is resolved for validation and again by the HTTP client for the connection. Pinning the validated address at connect time would close it and is not implemented.

## Running it safely

- Run `entsec check` first. It needs no API key and no network, and it produces the gaps and the decision. Only reach for `review` when the reasoning layer is worth the disclosure.
- **Think before attaching a design document.** `-d` sends the file in full. If it is too sensitive to leave the network, run `check` — the decision is identical.
- Treat the review database as sensitive. It is gitignored by default; keep it that way.
- Keep `temperature` at 0, or re-review stops meaning anything.
- Fork the control catalog rather than working around it. It is one file, and a catalog that does not match your policy will be worked around by the people using it.
