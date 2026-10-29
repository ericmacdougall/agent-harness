# Contributing

Keep the harness small and auditable. Change a policy only when it solves a concrete failure mode; avoid turning every task into a heavyweight process.

For code changes, include a focused regression that fails before the fix or against a controlled broken variant. Run `python3 -m unittest discover -s tests -v`, `python3 -m compileall -q install.py harness tests`, and `git diff --check`. For instruction changes, state the task behavior you expect and how you observed it in a fresh Claude Code session. Mark any behavior that was not live-tested.

Do not add personal settings, tokens, WALs, transcripts, private repos, customer data, or vendored dependencies. Keep local examples generic. Review model costs, permission changes, and data sent to external reviewers before proposing them.
