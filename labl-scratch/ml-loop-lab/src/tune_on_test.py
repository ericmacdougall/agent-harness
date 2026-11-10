"""What goes wrong when you tune on the test set.

60 random head configurations (C, class weight, feature subset) are trained on the same 1800 labelled
items.  Selection rule A picks the best on the 400-item "peek" test set (the thing teams keep
re-using); rule B picks the best on the separate 1000-item tune split.  Both winners are then scored
on the locked held-out (3000).  Repeated over 40 training draws.  Run AFTER the final loop so it
cannot influence it.   usage: tune_on_test.py out.json
"""
import json
import os
import sys
import warnings

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score

from common import *  # noqa

warnings.filterwarnings("ignore")
em = np.load(os.path.join(DATA_DIR, "emb.npz")); sp = np.load(os.path.join(DATA_DIR, "splits.npz"))
X, y = em["E_pool"][: 6 * WEEKLY_ARRIVALS], sp["y_pool"][: 6 * WEEKLY_ARRIVALS]
sets = {k: (em[f"E_{k}"], sp[f"y_{k}"]) for k in ("peek", "tune", "heldout")}
rng = np.random.default_rng(424242)
cfgs = [dict(C=float(10 ** rng.uniform(-2, 5)), cw=rng.choice(["balanced", None]), frac=float(rng.uniform(0.2, 1.0)), seed=int(rng.integers(1e6))) for _ in range(60)]
out = []
for t in range(40):
    r2 = np.random.default_rng(1000 + t)
    idx = r2.choice(len(y), 1800, replace=False)
    scores = []
    for c in cfgs:
        cols = np.random.default_rng(c["seed"]).permutation(X.shape[1])[: int(X.shape[1] * c["frac"])]
        m = LogisticRegression(C=c["C"], class_weight=c["cw"], max_iter=300).fit(X[idx][:, cols], y[idx])
        scores.append({k: float(average_precision_score(v[1], m.decision_function(v[0][:, cols]))) for k, v in sets.items()})
    best_peek = max(range(60), key=lambda i: scores[i]["peek"])
    best_tune = max(range(60), key=lambda i: scores[i]["tune"])
    out.append(dict(draw=t, peek_pick=dict(peek=scores[best_peek]["peek"], heldout=scores[best_peek]["heldout"]),
                    tune_pick=dict(tune=scores[best_tune]["tune"], heldout=scores[best_tune]["heldout"]),
                    mean_cfg_heldout=float(np.mean([s["heldout"] for s in scores])),
                    best_possible_heldout=float(max(s["heldout"] for s in scores))))
g1 = np.array([o["peek_pick"]["peek"] - o["peek_pick"]["heldout"] for o in out])
g2 = np.array([o["tune_pick"]["tune"] - o["tune_pick"]["heldout"] for o in out])
res = dict(n_draws=len(out), optimism_peek_pick_mean=float(g1.mean()), optimism_peek_ci=[float(np.percentile(g1, 2.5)), float(np.percentile(g1, 97.5))],
           optimism_tune_pick_mean=float(g2.mean()), optimism_tune_ci=[float(np.percentile(g2, 2.5)), float(np.percentile(g2, 97.5))],
           heldout_ap_of_peek_pick=float(np.mean([o["peek_pick"]["heldout"] for o in out])),
           heldout_ap_of_tune_pick=float(np.mean([o["tune_pick"]["heldout"] for o in out])),
           heldout_ap_mean_config=float(np.mean([o["mean_cfg_heldout"] for o in out])), draws=out)
json.dump(res, open(sys.argv[1], "w"), indent=1)
print({k: v for k, v in res.items() if k != "draws"})
