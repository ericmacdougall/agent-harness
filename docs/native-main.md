# Desktop review-root recognition

GoodQA #15649 and #15668 track the Codex Desktop review-receipt compatibility path.
The existing review hook invokes `native_main.is_desktop_review_root(payload)`
after its plain review-command parser recognizes the command. Genuine Claude
callers retain their existing path. The shared `caller_identity.is_main` predicate
continues to govern its existing callers, including protected Stop and owner
handoff. The new observation applies to the review receipt at that one call site.

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
nearest verified OpenAI runtime must be directly parented to the running signed
Desktop GUI, under the observed package layout. The GUI has identifier
`com.openai.codex` and OpenAI team `2DC432GLL2`. Its signed executable must match
the kernel executable. The supported layout has GUI executable
`Contents/MacOS/ChatGPT` and embedded runtime
`Contents/Resources/codex-cli/CodexCLI.app/Contents/MacOS/codex` in the same app
bundle. Kernel PID, start, parent, UID, executable and running code identities are
checked again before admission. Other layouts remain unavailable until supported.

A standalone CLI resuming a historical Desktop thread fails the current GUI
carrier requirement. A spawned child remains a child even when its command copies
root environment markers. Environment values and older WAL events cannot select
an authoritative current invocation. A more distant GUI ancestor cannot substitute
for the direct parent of the nearest verified runtime.

This follows the existing careless-agent threat model. It relies on the normal
host-supplied current hook envelope and user-owned application metadata. A malicious
same-user editor can alter those sources. The predicate supplies review-role
evidence. Existing review command, author independence, HEAD, packet, approval and
receipt-consumption checks still determine whether an action can proceed. Stamp
purpose/key binding, expiry and atomic consumption retain their existing behavior.

Run the disposable source controls from the repository root with
`python3 -B -m unittest discover -s tests -p test_native_main.py -v`.
The controls use fake kernel/code identities and disposable SQLite databases.
Generic role, protected Stop, owner acknowledgement and unrelated review purposes
need separate regression controls at the integration seam. Installation requires
the reviewed adapter and exact review hook together. A later actual authorized
root flow and actual child denial establish installed compatibility.
