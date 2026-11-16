#!/bin/bash
# goodqa#16148 step-2 PR evidence: every focused suite at HEAD, each with its exit status. Step-2 worktree root.
set -u
echo "HEAD $(git rev-parse HEAD) status-lines=$(git status --short | wc -l)"
df -h / | tail -1
step(){ echo "\$ $1"; bash -c "$1" 2>&1 | sed -E 's/\x1b\[[0-9;]*m//g' | grep -E "$2" | tail -4; echo "exit ${PIPESTATUS[0]}"; }
step "cd apps/job-dispatcher && timeout 900 npx vitest run" '^ +(Test Files|Tests) '
step "cd apps/job-dispatcher && timeout 600 npx tsc --noEmit" 'error TS'
step "bash infra/selfhost/app/run_derive_tests.sh" '^(Ran|OK|FAILED)'
step "cd infra/selfhost/app && DERIVE_TEST_TMP=\$PWD/../../../.scratch timeout 300 python3 -m unittest test_apply_job_secrets_wrapper test_cmdline_sampler" '^(Ran|OK|FAILED)'
step "timeout 300 node --test infra/selfhost-job-secrets-drift.test.mjs infra/selfhost-plan.test.mjs infra/selfhost/app/qa-closure-topology.test.mjs" '^# (tests|pass|fail)'
step "timeout 600 \$HOME/repos/fx-16136/venv/bin/python -m pytest -q -p no:cacheprovider infra/release-harness/test_selfhost_ctl_job_secrets.py infra/release-harness/test_selfhost_ctl.py" '(passed|failed)'
git diff 3b7cde1a97478251ff15dde8c5a9768e7b4e493b..HEAD > "$HOME/repos/fx-16136/probes/pr-16148.diff"
