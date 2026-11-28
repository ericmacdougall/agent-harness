# Codex Desktop root recognition

GoodQA #15649 and #15668 track the Codex Desktop review-receipt compatibility path.
The review hook invokes `native_main.is_desktop_review_root(payload)` for an exact
review command. The audited merge waiver uses the same proof under its own
command and receipt policy. The remote hook-file deploy guard uses the proof
after validating the existing installed `ah.py install-files` command form.
Genuine Claude callers retain their existing path. The shared
`caller_identity.is_main` predicate continues to govern protected Stop and owner
handoff.

The adapter requires a current canonical PreToolUse Bash envelope with a valid
session UUID, current tool-use UUID, and empty child/agent/parent markers. Conflicting
aliases deny. That session must identify one current Desktop user-root metadata
row in the current user's fixed `.codex/state_5.sqlite`. The row must have
`source=vscode`, `thread_source=user`, `originator=Codex Desktop`, `archived=0`
and null agent path, role and attached parent. The reader projects eight identity
columns through a parameterized read-only query. It checks path ownership and
identity, rejects aliases and generated identity columns, bounds field sizes,
and uses a short busy/progress budget. SQLite's live committed WAL participates
in the read. Missing or unqualified metadata remains unavailable.

Historical Desktop metadata also requires current process corroboration. The
nearest verified OpenAI runtime must be parented to the running signed
Desktop GUI, either directly or through the one supported signed Aperitif
helper. The GUI has identifier `com.openai.codex` and OpenAI team `2DC432GLL2`.
The supported layout has GUI executable
`Contents/MacOS/ChatGPT` and embedded runtime
`Contents/Resources/codex-cli/CodexCLI.app/Contents/MacOS/codex` in the same app
bundle. The optional intermediary must have signed identifier
`com.openai.codex.helper`, the same OpenAI team, and the same app bundle and UID
as the other processes. Its kernel executable must match this versioned
framework layout.

```text
Contents/Frameworks/Codex Framework.framework/Versions/<numeric version>/Helpers/Codex (Aperitif).app/Contents/MacOS/Codex (Aperitif)
```

Signed executable paths must match kernel executable paths. Kernel PID, start,
parent, UID, executable, and running code identities are checked again before
admission.

A standalone CLI resuming a historical Desktop thread fails the current GUI
carrier requirement. A spawned child remains a child even when its command copies
root environment markers. Environment values and older WAL events cannot select
an authoritative current invocation. A more distant GUI ancestor or an arbitrary
intermediary fails the process check.

This follows the existing careless-agent threat model. It relies on the normal
host-supplied current hook envelope and user-owned application metadata. A malicious
same-user editor can alter those sources. The predicate supplies session-role
evidence for each documented operation. Human model consent uses a separate
verifier. Existing review command, author independence, HEAD, packet, approval and
receipt-consumption checks still determine whether a review action can proceed.
The remote installer still verifies the merged source, target host and file
allowlists, backups, and audit. Stamp purpose and key binding, expiry, and
atomic consumption retain their existing behavior.

Run the disposable source controls from the repository root with
`python3 -B -m unittest discover -s tests -p test_native_main.py -v`.
The controls use fake kernel/code identities and disposable SQLite databases.
The installer hook controls that ran against the command guard were deleted with it in release 1001. Use the
[reviewed merged-source repair flow](harness-repair.md) to refresh the installed
hooks. An authorized root flow and a child denial establish installed compatibility.
