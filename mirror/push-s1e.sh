#!/bin/sh
# Copies the S1e edit copies to the t2-dev worktree. Usage: push-s1e.sh
set -e
cd "$(dirname "$0")"
scp -q user-token-contact-timeline-default.test.ts gmail-limited-use.test.ts t2-dev:wt-15561/apps/api/test/
scp -q auth.ts.plugin t2-dev:wt-15561/apps/api/src/plugins/auth.ts
scp -q auth-gate.ts t2-dev:wt-15561/apps/api/src/modules/user-tokens/auth-gate.ts
scp -q desktop-token-session.ts t2-dev:wt-15561/apps/api/src/lib/desktop-token-session.ts
echo pushed
