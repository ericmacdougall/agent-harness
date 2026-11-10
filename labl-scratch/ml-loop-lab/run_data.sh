#!/bin/bash
# Build splits and embeddings (CPU). Usage: VENV=/path/.venv ./run_data.sh
set -euo pipefail
cd "$(dirname "$0")/src"
. "${VENV:-../.venv}/bin/activate"
export LAB_DATA=../data
python prep_data.py
python embed.py
