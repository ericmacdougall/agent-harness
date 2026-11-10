#!/bin/bash
# Wait for embeddings, then dedupe and tune the head (dev only; held-out untouched).
set -euo pipefail
cd "$(dirname "$0")/src"
. "${VENV:-../../.venv}/bin/activate"
export LAB_DATA=${LAB_DATA:-../data_qg}
while [ ! -s "$LAB_DATA/emb.npz" ]; do sleep 20; done
sleep 5
python dedupe.py | tee "$LAB_DATA/dedupe.log"
python tune_head.py "$LAB_DATA/tune_head.json" | tee "$LAB_DATA/tune_head.log"
echo STAGE1_DONE
