# Delivery and handoff

Before integration, main checks the branch diff against the original scope, final HEAD, reviewer findings, actual tests and live evidence, and touched documentation. If the original checkout changed or has user edits, preserve it and ask about a consequential conflict; do not reset. Merge or fast-forward according to repo conventions, rerun relevant checks on the delivered state, and tell dependent owners what to rebase onto.

Attempt a normal feature-branch push and PR when a configured remote is reachable. A remote failure is a publication issue, not a reason to abandon local verification or integration. Report the exact safe error and do not force-push, try another remote, or loop on credentials. Separate PR status from local readiness.

The final handoff should let the user try the result immediately: original checkout path and delivered commit, one start or preview path/URL where applicable, safe seed/test-account instructions, exact test and watch commands, result/log location, and stop command. For CLI/API work, provide a runnable request or sample instead of inventing a UI. Explain uncovered risks and pending checks plainly.

Update affected docs with verified facts: README and how it works, contributing/standards, architecture, ERD, service/deployment map, OpenAPI/MCP, and developer/customer docs as relevant. Skip unrelated documents and empty boilerplate. Record source, date, and confidence for unstable external facts; use current official sources when APIs, security guidance, or dependencies may have changed. Redact personal data and secrets from logs, docs, PR packets, and traces.
