# Two host native module patch

GoodQA #16425 tracks this installer. It installs the reviewed native Desktop caller recognition module into both existing harness installations on the Mac and physical t2-dev. The manifest identifies each exact previous module hash and the candidate bytes. Its SHA-256 must be supplied independently in the release command.

The installer preflights both hosts before writes, reserves a private patch journal, saves originals and permissions, atomically replaces each module and verifies installed hashes. Repeating the same patch resumes a partial application. An identity reused with different manifest bytes is refused. `--rollback` restores the recorded original only while the installed file still matches one of the declared hashes. Later edits require reconciliation. A failed remote apply restores the local modules and leaves the remote recovery journal available. Lost SSH responses require remote reconciliation before any success claim.

Supported paths are exactly `.claude/hooks/native_main.py` and `.codex/agent-harness/native_main.py`. The installer rejects symlinks, writable shared parents, foreign files, unknown hashes and paths outside that set. It neither edits hook registration nor changes the Codex trust store. The Linux copy preserves its existing fail-closed behavior for Desktop-only authority.

The patch covers native caller recognition. Broker source activation uses a separate lifecycle helper that drains work, preserves its admission hold and verifies the running service. Physical disk capacity, the protected staging writer, migration and rollback with acknowledged data and uploads, the full product suites and release acceptance each require execution evidence. Installed console #283 supports its existing console-owned capacity wake behavior.

Focused controls exercise idempotence, exact restoration, permission preservation, changed source rejection, symlinks and escaped paths, candidate digest failure, duplicate identity rejection, interrupted second module update and an actual subprocess worker protocol.
