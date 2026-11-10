"""Calibrate fraud-signal thresholds against precision and recall targets, then score them.

Signal models: (a) the loop's week-12 model (uncertainty strategy, final seeds) and (b) the open-weight
CLIP zero-shot score ("an AI-generated image" vs "a real photograph", no training at all).
Targets (pre-registered): auto-reject threshold with precision >= 0.95 on the calibration set;
review threshold with recall >= 0.90.  Thresholds are chosen on calib (clean, n=2000), reported on
held-out (n=3000, 600 fake) with Wilson CIs; then the drifted held-out shows the damage and the
effect of re-calibrating on drifted calibration items (n=1000).
usage: signal_thresholds.py main.jsonl out.json
"""
import json
import os
import sys

import numpy as np

from common import *  # noqa


def pick(scores, y, prec=None, rec=None):
    order = np.argsort(-scores)
    s, yy = scores[order], y[order]
    tp = np.cumsum(yy); k = np.arange(1, len(y) + 1)
    P, R = tp / k, tp / max(yy.sum(), 1)
    if prec is not None:
        ok = np.where(P >= prec)[0]
        return float(s[ok.max()]) if len(ok) else float("inf")      # lowest threshold still meeting precision
    ok = np.where(R >= rec)[0]
    return float(s[ok.min()]) if len(ok) else float("-inf")         # highest threshold still meeting recall


def score_at(scores, y, thr):
    pred = scores >= thr
    tp = int((pred & (y == 1)).sum()); fp = int((pred & (y == 0)).sum()); pos = int(y.sum())
    return dict(flagged=int(pred.sum()), tp=tp, fp=fp,
                precision=tp / max(tp + fp, 1), precision_ci=wilson(tp, tp + fp),
                recall=tp / pos, recall_ci=wilson(tp, pos))


if __name__ == "__main__":
    em = np.load(os.path.join(DATA_DIR, "emb.npz")); sp = np.load(os.path.join(DATA_DIR, "splits.npz"))
    yc, yh = sp["y_calib"].astype(int), sp["y_heldout"].astype(int)
    drop = json.load(open(os.path.join(DATA_DIR, "drop.json")))
    keep = np.ones(len(yc), bool); keep[drop["calib"]] = False   # duplicates of held-out/pool items
    out = {}
    runs = [json.loads(l) for l in open(sys.argv[1])]
    runs = [r for r in runs if r["cfg"]["strategy"] == "uncertainty" and r["cfg"]["suite"] == "main"]
    sig = {}
    for name, getter in [("loop_model", lambda r: (np.array(r["rows"][-1]["scores_calib"]), np.array(r["rows"][-1]["scores_clean"]),
                                                  np.array(r["rows"][-1]["scores_calib_drift"]), np.array(r["rows"][-1]["scores_drift"]))),
                         ("clip_zeroshot", None)]:
        per_seed = []
        for r in (runs if getter else runs[:1]):
            if getter:
                cal, held, cald, heldd = getter(r)
            else:
                cal, held = em["Z_calib"], em["Z_heldout"]
                cald, heldd = em["Z_calib_drift"], em["Z_heldout_drift"]
            cal = cal[keep]; t_rej = pick(cal, yc[keep], prec=0.95); t_rev = pick(cal, yc[keep], rec=0.90)
            d = dict(seed=r["cfg"]["seed"] if getter else None, t_reject=t_rej, t_review=t_rev,
                     calib_reject=score_at(cal, yc[keep], t_rej), calib_review=score_at(cal, yc[keep], t_rev),
                     held_reject=score_at(held, yh, t_rej), held_review=score_at(held, yh, t_rev),
                     drift_reject_stale=score_at(heldd, yh[:N_DRIFT_HELD], t_rej),
                     drift_review_stale=score_at(heldd, yh[:N_DRIFT_HELD], t_rev))
            yd = yc[:1000][keep[:1000]]; cald = cald[keep[:1000]]
            tr2 = pick(cald, yd, prec=0.95); tv2 = pick(cald, yd, rec=0.90)
            d.update(t_reject_recal=tr2, t_review_recal=tv2,
                     drift_reject_recal=score_at(heldd, yh[:N_DRIFT_HELD], tr2),
                     drift_review_recal=score_at(heldd, yh[:N_DRIFT_HELD], tv2))
            per_seed.append(d)
        sig[name] = per_seed
        keys = ["held_reject", "held_review", "drift_reject_stale", "drift_review_stale", "drift_reject_recal", "drift_review_recal"]
        summ = {}
        for k in keys:
            summ[k] = dict(precision=float(np.mean([p[k]["precision"] for p in per_seed])),
                           recall=float(np.mean([p[k]["recall"] for p in per_seed])),
                           flagged=float(np.mean([p[k]["flagged"] for p in per_seed])))
        out[name] = dict(summary=summ, n_models=len(per_seed))
        print(name, json.dumps(summ, indent=1))
    out["detail"] = sig
    json.dump(out, open(sys.argv[2], "w"), indent=1)
