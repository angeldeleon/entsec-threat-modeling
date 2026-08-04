# Contributing

## The most useful contribution

A **control objective**. [`src/entsec/controls/catalog.py`](src/entsec/controls/catalog.py) is one reviewable table of what a review checks. One entry is real value for about twenty lines, and it is the file most worth reviewing — a wrong applicability rule fires on projects it should not, and that is how a security process loses its audience.

Every entry needs four things:

1. **An applicability rule** — a pure predicate over the intake. If it returns True for every design, it is not a rule, it is a checklist item, and it will be ignored.
2. **A satisfaction rule** that can return `None`. Unknown must never collapse into failure.
3. **Remediation a non-security reader can act on.** Name the action. "Apply least privilege" is a sentence.
4. **All four framework references**, taken from the published frameworks rather than from memory. CI checks that every control maps to all four and that no identifier is blank.

## Before opening a pull request

```bash
pip install -e ".[dev]"
ruff format . && ruff check . && mypy src/entsec && bandit -q -r src/entsec -c pyproject.toml && pytest
```

## What will be pushed back on

- **A control that applies to everything.** The reason checklists fail.
- **Turning unknown into a finding.** `satisfied` returning `False` where the intake simply did not ask.
- **Letting the model decide anything the gate cannot check.** The decision, applicability and severity are computed deliberately.
- **Adding intake questions without removing any.** The form has a budget: roughly ten minutes of a non-security person's attention. Past that it does not get filled in, and a review that does not happen is worse than one that missed a nuance.
- **Longer reports.** Two audiences, one page each. A pull request that adds a section needs to argue why it earns the space.

## Security issues

Do not open a public issue. Use [private reporting](https://github.com/angeldeleon/entsec/security/advisories/new).
