#!/bin/bash
# goodqa#16148: run the derive-job-secrets.py and apply-job-secrets-host.py tests. Parse and compose-parity tests run on this
# host (needs the docker compose CLI); the ownership tests need root and run in a throwaway
# container (--rm, --network none, this directory read-only, a scratch dir for fake roots).
# Fake values only. Usage: infra/selfhost/app/run_derive_tests.sh [SCRATCH_DIR]
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRATCH="${1:-$HERE/../../../.scratch/derive-tests}"
IMAGE="${DERIVE_TEST_IMAGE:-python:3.12-slim}"
mkdir -p "$SCRATCH"
SCRATCH="$(cd "$SCRATCH" && pwd)"
echo "== host: parse + compose parity"
( cd "$HERE" && DERIVE_TEST_TMP="$SCRATCH" timeout 600 python3 -m unittest -v test_derive_job_secrets test_apply_job_secrets_host 2>&1 | tail -n 30 )
echo "== container (root): ownership, races, NEG-1/2/3/13, no value in output or argv"
docker run --rm --network none -v "$HERE:/t:ro" -v "$SCRATCH:/scratch" -e DERIVE_TEST_TMP=/scratch -w /t \
  "$IMAGE" timeout 600 python3 -m unittest -v test_derive_job_secrets test_apply_job_secrets_host 2>&1 | tail -n 30
