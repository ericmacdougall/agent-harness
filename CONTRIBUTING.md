# Contributing

Keep the harness small and auditable. Change a policy only when it solves a concrete failure mode; avoid turning every task into a heavyweight process.

For code changes, include a focused regression that fails before the fix or against a controlled broken variant. Use Python 3.11 or newer to cover both editions; run `python3 -m unittest discover -s tests -v`, `python3 -m compileall -q install.py install_codex.py harness codex/hooks tests`, and `git diff --check` with that interpreter. For instruction changes, state the expected task behavior and how you observed it in a fresh session of the affected edition. In Codex, review and trust the installed hooks with `/hooks` after installation or updates. Mark behavior that was not live-tested.

Do not add personal settings, tokens, WALs, transcripts, private repos, customer data, or vendored dependencies. Keep local examples generic. Review model costs, permission changes, and data sent to external reviewers before proposing them.

The interactive console is its own dependency-free Go module under `console/`.
For console changes, run `go test ./...`, `go test -race ./...`, and `go vet ./...`
from that directory. Its native CI matrix covers macOS, Windows, and Linux.
Protocol doubles must preserve real framing, working-directory, account, and
cancellation behavior; distinguish those checks from actual provider requests.
UI changes also need a browser flow through the compiled app. A successful
cross-compile does not prove native vault access, browser opening, or installation.
Keep live credentials and exact-head test receipts outside the repository.
