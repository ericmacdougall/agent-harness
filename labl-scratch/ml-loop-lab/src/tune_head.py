"""Choose the classification head and its regularisation on the TUNE split only (never the held-out).

Trains on 1800 random pool items with true labels (what the loop has after 12 weeks if labels were
perfect) over dev seeds and scores average precision on the 1000-item tune split.
"""
import json
import os
import sys
import warnings

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score
from sklearn.neural_network import MLPClassifier

from common import *  # noqa

warnings.filterwarnings("ignore")
em = np.load(os.path.join(DATA_DIR, "emb.npz"))
sp = np.load(os.path.join(DATA_DIR, "splits.npz"))
X, y = em["E_pool"][: 6 * WEEKLY_ARRIVALS], sp["y_pool"][: 6 * WEEKLY_ARRIVALS]
Xt, yt = em["E_tune"], sp["y_tune"]
res = {}
for name, make in [(f"lr_C{c}", (lambda c=c: LogisticRegression(C=c, max_iter=500, class_weight="balanced"))) for c in (1, 10, 100, 1000, 10000)] + \
                  [("mlp_256", lambda: MLPClassifier((256,), alpha=1e-3, max_iter=300, early_stopping=True, random_state=0))]:
    aps = []
    for s in DEV_SEEDS:
        rng = np.random.default_rng(s)
        idx = rng.choice(len(y), 1800, replace=False)
        m = make().fit(X[idx], y[idx])
        sc = m.decision_function(Xt) if hasattr(m, "decision_function") else m.predict_proba(Xt)[:, 1]
        aps.append(average_precision_score(yt, sc))
    res[name] = dict(mean_ap=float(np.mean(aps)), sd=float(np.std(aps, ddof=1)), aps=[round(a, 4) for a in aps])
    print(name, res[name]["mean_ap"].__round__(4), "+-", round(res[name]["sd"], 4), flush=True)
json.dump(res, open(sys.argv[1] if len(sys.argv) > 1 else "tune_head.json", "w"), indent=1)
