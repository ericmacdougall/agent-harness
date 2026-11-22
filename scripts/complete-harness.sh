#!/bin/bash
# Human-run entry point. Installation never grants PR merge authority.
set -euo pipefail
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
exec python3 "$SCRIPT_DIR/bootstrap_native_review.py" "$@"
