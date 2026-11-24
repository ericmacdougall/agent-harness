#!/usr/bin/env bash
# AC-7 live check for the checkout registry (goodqa#16947). See checkout_registry_live.py for what it does and costs.
# Usage: bash tests/live/checkout_registry_live.sh RECEIPT_DIR [--claude PATH] [--model MODEL]
set -euo pipefail
exec python3 -I "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/checkout_registry_live.py" "$@"
