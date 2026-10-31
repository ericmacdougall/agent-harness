# Contributing

Keep the harness small and auditable. Change a policy only when it solves a concrete failure mode; avoid turning every task into a heavyweight process.

For code changes, include a focused regression that fails before the fix or against a controlled broken variant. Use Python 3.11 or newer to cover both editions; run `python3 -m unittest discover -s tests -v`, `python3 -m compileall -q install.py install_codex.py harness codex/hooks tests`, and `git diff --check` with that interpreter. For instruction changes, state the expected task behavior and how you observed it in a fresh session of the affected edition. In Codex, review and trust the installed hooks with `/hooks` after installation or updates. Mark behavior that was not live-tested.

Do not add personal settings, tokens, WALs, transcripts, private repos, customer data, or vendored dependencies. Keep local examples generic. Review model costs, permission changes, and data sent to external reviewers before proposing them.
