#!/usr/bin/env bash
# One command for the PR 1377 runtime qualification kit. See README.md.
#   bash qualify.sh <40-hex head sha> <bugtracker git checkout> [extra qual.py args]
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
[ $# -ge 2 ] || { echo "usage: bash qualify.sh <head sha> <bugtracker checkout> [--work DIR] [--python PY] [--floor GB]" >&2; exit 2; }
H=$1; REPO=$2; shift 2
case "$(hostname -s)" in *goodqa*|*prod*|gqapp*) echo "refusing: this looks like a production host ($(hostname -s))" >&2; exit 2;; esac
exec python3 -I "$HERE/qual.py" --head "$H" --repo "$REPO" "$@"
