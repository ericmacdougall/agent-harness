#!/usr/bin/env bash
# goodqa#15561: drop one route from DESKTOP_POLL_ROUTES; the quiet-poll test must fail. Restores the file.
set -u
cd "$HOME/wt-15561/apps/api" || exit 2
F=src/lib/desktop-token-session.ts
cp "$F" /tmp/g15561-poll.bak
sed -i "s#'GET /v1/notifications', 'GET /v1/notifications/unread-count', #'GET /v1/notifications', #" "$F"
if cmp -s "$F" /tmp/g15561-poll.bak; then echo "sed did not change the file"; exit 3; fi
CAP=700 "$HOME/review-scratch/run15561.sh" mut-poll test/user-token-desktop-session-delegation.test.ts > /dev/null 2>&1
{ grep -E "^ FAIL |AssertionError|Tests " "$HOME/review-scratch/g15561-mut-poll.txt" | cut -c1-260 | head -8; } | tee "$HOME/release-evidence/g15561-mutant-poll-route.txt"
cp /tmp/g15561-poll.bak "$F"
git status --short
