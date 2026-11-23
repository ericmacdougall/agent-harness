#!/bin/bash
# One-shot installer of the takeover cleanup (goodqa#16441). The USER runs this; an agent may only dry-run or verify it.
#
#   git -C <repo> fetch origin main
#   mkdir -m 700 ~/.agent-harness/takeover-kit-<sha12>
#   git -C <repo> archive <merge sha> scripts | tar -x -C ~/.agent-harness/takeover-kit-<sha12>
#   ~/.agent-harness/takeover-kit-<sha12>/scripts/enable-takeover-cleanup.sh --ref <merge sha> --repo <repo>
#
# Modes: --dry-run (default), --apply, --undo [--hooks] [--force-file P], --verify; --host all|local|t2-dev.
# This file is a thin front: the logic is scripts/enable_takeover_cleanup.py, which checks that this file, itself and
# takeover-cleanup-policy.md equal the blobs at --ref before it changes anything (git cat-file, no checkout).
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd -P)"

# Any word that could be --apply or --undo, or a prefix of one, is guarded here; the Python entry refuses prefixes
# (allow_abbrev off) and runs the same checks again (review M2 and m1).
guarded=0
for arg in "$@"; do
    case "$arg" in --a* | --u*) guarded=1 ;; esac
done

if [[ $guarded == 1 ]]; then
    # Accident prevention for an agent that reaches this script anyway (the command guards refuse it first): --apply and
    # --undo need a person at a terminal. Bypassable outside guarded sessions; the user is the control.
    for name in CLAUDE_CODE_SESSION_ID CODEX_THREAD_ID CLAUDECODE; do
        if [[ -n ${!name-} ]]; then
            printf '%s\n' "enable-takeover-cleanup: refused: $name is set; --apply and --undo are run by the user in a terminal." >&2
            exit 4
        fi
    done
    if [[ -n $(compgen -e | grep '^CODEX_' || true) ]]; then
        printf '%s\n' 'enable-takeover-cleanup: refused: a CODEX_* variable is set; --apply and --undo are run by the user in a terminal.' >&2
        exit 4
    fi
    if [[ ! -t 0 || ! -t 1 ]]; then
        printf '%s\n' 'enable-takeover-cleanup: refused: --apply and --undo need a terminal on stdin and stdout.' >&2
        exit 4
    fi
fi

for candidate in python3 python3.15 python3.14 python3.13 python3.12 python3.11 \
    /opt/homebrew/bin/python3.15 /opt/homebrew/bin/python3.14 /opt/homebrew/bin/python3.13 \
    /opt/homebrew/bin/python3.12 /opt/homebrew/bin/python3.11 /usr/local/bin/python3; do
    if "$candidate" -I -c 'import sys; sys.exit(sys.version_info < (3, 11))' 2>/dev/null; then
        exec "$candidate" -IB "$here/enable_takeover_cleanup.py" "$@"
    fi
done
printf '%s\n' 'Python 3.11 or later is required.' >&2
exit 2
