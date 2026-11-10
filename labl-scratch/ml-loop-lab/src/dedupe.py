"""Find exact-pixel duplicates across splits and drop them from the NON-held-out side.

Writes calib_drop.json (indices into the calibration set to exclude when thresholds are calibrated).
Pool/gold/tune duplicates of held-out/peek would be dropped from pool/gold/tune; none were found in
practice (see the run log), so only calibration items appear.
"""
import hashlib
import json
import os

import numpy as np

from common import *  # noqa

sp = np.load(os.path.join(DATA_DIR, "splits.npz"))
H = {k: [hashlib.md5(x.tobytes()).hexdigest() for x in sp[f"X_{k}"]] for k in ("pool", "gold", "calib", "tune", "heldout", "peek")}
test_side = set(H["heldout"]) | set(H["peek"])
other = set(H["pool"]) | set(H["gold"]) | set(H["tune"])
drop = {"calib": [i for i, h in enumerate(H["calib"]) if h in test_side or h in other],
        "pool_vs_test": [i for i, h in enumerate(H["pool"]) if h in test_side],
        "gold_vs_test": [i for i, h in enumerate(H["gold"]) if h in test_side],
        "tune_vs_test": [i for i, h in enumerate(H["tune"]) if h in test_side]}
print(drop)
json.dump(drop, open(os.path.join(DATA_DIR, "drop.json"), "w"))
