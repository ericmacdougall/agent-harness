#!/usr/bin/env bash
# Focused 1377 suites on one exact commit, in the scratch worktree delta/gate-merge (t2-dev).
# Usage: bash gate-suites.sh <commit>
set -u
C=$1; W=$HOME/repos/fx-16136/delta/gate-merge; P=$HOME/repos/fx-16136/venv/bin/python
df -h / | tail -1
cd "$W" || exit 9
git checkout -q --detach "$C" || exit 9
echo "HEAD $(git rev-parse HEAD) status-lines=$(git status --short | wc -l)"
run(){ echo "\$ $1"; ( eval "$1" ) > "$HOME/repos/fx-16136/delta/step.log" 2>&1; rc=$?; tail -${2:-6} "$HOME/repos/fx-16136/delta/step.log"; echo "exit $rc"; }
run 'cd apps/job-dispatcher && timeout 900 npx vitest run' 5
run 'cd apps/job-dispatcher && timeout 600 npx tsc --noEmit' 3
run 'bash infra/selfhost/app/run_derive_tests.sh' 8
mkdir -p "$W/.scratch"
run 'cd infra/selfhost/app && DERIVE_TEST_TMP=$PWD/../../../.scratch timeout 300 python3 -m unittest test_apply_job_secrets_wrapper test_cmdline_sampler' 4
run 'timeout 300 node --test infra/selfhost-job-secrets-drift.test.mjs infra/selfhost-plan.test.mjs infra/selfhost/app/qa-closure-topology.test.mjs' 9
L=$HOME/repos/fx-16136/delta/rh-$C.log
echo '$ cd infra/release-harness && pytest -q (10 files)'
( cd infra/release-harness && GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.invalid GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.invalid \
  timeout 2400 "$P" -B -m pytest -q -p no:cacheprovider test_ac13_count.py test_rw_ship_jobsecret_gate.py test_rw_ship_selfhost.py \
  test_rw_release_authority_d2.py test_install_d2_upgrade.py test_runner_ship_adapter.py test_rw_runtime_root.py test_selfhost_ctl.py \
  test_selfhost_ctl_gate.py test_selfhost_ctl_job_secrets.py > "$L" 2>&1; echo "exit $?" >> "$L" )
grep -E '^FAILED|passed|failed|^exit' "$L" | tail -12
echo "full log kept: $L"
