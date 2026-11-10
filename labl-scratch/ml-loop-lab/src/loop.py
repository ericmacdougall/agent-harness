"""Weekly human-in-the-loop retraining simulation.

One run = (strategy, seed, label policy, noise multiplier, drift response).  Each week:
  1. 1500 new submissions arrive (from week DRIFT_WEEK on they come through the drifted pipeline);
  2. the current model picks BUDGET items from the unreviewed backlog (the strategy);
  3. simulated reviewers label them (difficulty-dependent noise, disagreement, adjudication);
  4. the model is retrained from scratch on gold seed + all reviewed labels (or a window);
  5. the model is scored on the fixed held-out set (clean 3000 + drifted 1000) .
Dev mode scores on the tune split only; --final scores on the locked held-out and needs the
pre-registration hash (see PREREG.md).
"""
import argparse
import hashlib
import json
import multiprocessing as mp
import os
import sys
import time
import warnings

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.model_selection import cross_val_predict

from common import *  # noqa

warnings.filterwarnings("ignore")
BUDGET = 150
C_HEAD = float(os.environ.get("LAB_C", "100"))   # set by tune_head.py (see RUNLOG)
STRATEGIES = ["random", "uncertainty", "topscore", "margin_div", "hybrid"]
BASE_ERR = [0.04, 0.07, 0.10]   # three junior reviewers
SENIOR_ERR = 0.03
HARD_SLOPE = 0.30                # extra error probability for the hardest items


def load():
    sp = np.load(os.path.join(DATA_DIR, "splits.npz"))
    em = np.load(os.path.join(DATA_DIR, "emb.npz"))
    D = {k[2:]: em[k] for k in em.files if k.startswith("E_")}
    Z = {k[2:]: em[k] for k in em.files if k.startswith("Z_")}
    Y = {k[2:]: sp[k].astype(int) for k in sp.files if k.startswith("y_")}
    off = (DRIFT_WEEK - 1) * WEEKLY_ARRIVALS
    Xpool = D["pool"].copy()
    Xpool[off:] = D["pool_drift"]          # what the model actually sees at arrival time
    return dict(D=D, Z=Z, Y=Y, Xpool=Xpool, ypool=Y["pool"], off=off)


def oracle_hardness(S):
    """Cross-fitted 'how ambiguous is this item' used only inside the reviewer simulator."""
    cache = os.path.join(DATA_DIR, "hardness.npy")
    if os.path.exists(cache):
        return np.load(cache)
    p = cross_val_predict(LogisticRegression(C=C_HEAD, max_iter=500, class_weight="balanced"),
                          S["Xpool"], S["ypool"], cv=5, method="predict_proba")[:, 1]
    h = 1 - np.abs(2 * p - 1)
    np.save(cache, h)
    return h


def review(idx, S, hard, rng, policy, noise):
    """Return (labels, cost_in_votes, disagreement_flags)."""
    y = S["ypool"][idx]
    n = len(idx)

    base = np.array(BASE_ERR) * noise
    if policy == "single":
        r = rng.integers(0, 3, n)
        perr = np.clip(base[r] + HARD_SLOPE * hard[idx] * noise, 0, 0.5)
        lab = np.where(rng.random(n) < perr, 1 - y, y)
        return lab, np.ones(n), np.zeros(n, bool)
    # two distinct junior reviewers
    r1 = rng.integers(0, 3, n)
    r2 = (r1 + 1 + rng.integers(0, 2, n)) % 3
    v = []
    for r in (r1, r2):
        perr = np.clip(base[r] + HARD_SLOPE * hard[idx] * noise, 0, 0.5)
        v.append(np.where(rng.random(n) < perr, 1 - y, y))
    disagree = v[0] != v[1]
    perr_s = np.clip(SENIOR_ERR * noise + HARD_SLOPE * 0.5 * hard[idx] * noise, 0, 0.5)
    senior = np.where(rng.random(n) < perr_s, 1 - y, y)
    if policy == "adjudicate":
        lab = np.where(disagree, senior, v[0])
        return lab, 2 + disagree.astype(float), disagree
    if policy == "majority3":
        third = senior
        lab = np.where(disagree, third, v[0])  # same decision rule, always pays for 3 votes
        return lab, np.full(n, 3.0), disagree
    raise ValueError(policy)


def fit(X, y, w=None):
    if len(np.unique(y)) < 2:
        return None
    m = LogisticRegression(C=C_HEAD, max_iter=300, class_weight="balanced")
    m.fit(X, y, sample_weight=w)
    return m


def kcenter(X, cand, k, rng):
    sel = [cand[rng.integers(len(cand))]]
    d = np.linalg.norm(X[cand] - X[sel[0]], axis=1)
    for _ in range(k - 1):
        j = int(np.argmax(d))
        sel.append(cand[j])
        d = np.minimum(d, np.linalg.norm(X[cand] - X[cand[j]], axis=1))
    return np.array(sel)


def select(strategy, model, backlog, X, rng):
    k = min(BUDGET, len(backlog))
    if strategy == "random" or model is None:
        return rng.choice(backlog, k, replace=False)
    p = model.predict_proba(X[backlog])[:, 1]
    if strategy == "uncertainty":
        return backlog[np.argsort(np.abs(p - 0.5))[:k]]
    if strategy == "topscore":
        return backlog[np.argsort(-p)[:k]]
    if strategy == "margin_div":
        cand = backlog[np.argsort(np.abs(p - 0.5))[:4 * k]]
        return kcenter(X, cand, k, rng)
    if strategy == "hybrid":
        ku = k // 2
        u = backlog[np.argsort(np.abs(p - 0.5))[:ku]]
        rest = np.setdiff1d(backlog, u)
        return np.concatenate([u, rng.choice(rest, k - ku, replace=False)])
    raise ValueError(strategy)


def metrics(model, X, y, thr):
    s = model.decision_function(X)
    pred = (s > 0).astype(int)
    tp = int(((pred == 1) & (y == 1)).sum()); fp = int(((pred == 1) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum()); tn = int(((pred == 0) & (y == 0)).sum())
    rec = tp / max(tp + fn, 1); spec = tn / max(tn + fp, 1)
    out = dict(ap=float(average_precision_score(y, s)), auc=float(roc_auc_score(y, s)),
               acc=(tp + tn) / len(y), bacc=(rec + spec) / 2, prec=tp / max(tp + fp, 1), rec=rec)
    if thr is not None:
        pr = (s > thr).astype(int)
        t = int(((pr == 1) & (y == 1)).sum()); f = int(((pr == 1) & (y == 0)).sum())
        out["rec_at_cal"] = t / max(int(y.sum()), 1)
        out["prec_at_cal"] = t / max(t + f, 1)
    return out


def drift_monitor(X_ref, X_new, rng):
    """Domain classifier AUC: can a linear model tell this week's arrivals from the reference weeks?"""
    n = min(len(X_ref), len(X_new))
    a = X_ref[rng.choice(len(X_ref), n, replace=False)]
    b = X_new[rng.choice(len(X_new), n, replace=False)]
    X = np.vstack([a, b]); y = np.r_[np.zeros(n), np.ones(n)]
    p = cross_val_predict(LogisticRegression(C=10, max_iter=200), X, y, cv=3, method="decision_function")
    return float(roc_auc_score(y, p))


def run_one(cfg):
    strategy, seed, policy, noise, resp, final = (cfg[k] for k in ("strategy", "seed", "policy", "noise", "drift_response", "final"))
    t0 = time.time()
    S = LOAD
    rng = np.random.default_rng(seed * 1000 + 7)
    hard = HARD
    D, Y = S["D"], S["Y"]
    X = S["Xpool"]
    if final:
        Xe, ye = D["heldout"], Y["heldout"]
        Xd, yd = D["heldout_drift"], Y["heldout"][:N_DRIFT_HELD]
        Xc, yc = D["calib"], Y["calib"]
    else:
        Xe, ye = D["tune"], Y["tune"]
        Xd, yd = D["calib_drift"], Y["calib"][:1000]
        Xc, yc = D["tune"], Y["tune"]
    Xg, yg = D["gold"], Y["gold"]
    lab_idx, lab_y, lab_week = [], [], []
    backlog = np.array([], dtype=int)
    model = fit(Xg, yg)
    cum_cost = 0.0
    rows = [dict(week=0, n_labeled=len(yg), cum_cost=0.0, clean=metrics(model, Xe, ye, None), drift=metrics(model, Xd, yd, None))]
    for week in range(1, WEEKS + 1):
        arr = np.arange((week - 1) * WEEKLY_ARRIVALS, week * WEEKLY_ARRIVALS)
        backlog = np.concatenate([backlog, arr])
        frozen = resp == "frozen" and week > DRIFT_WEEK - 1
        mon = None
        if week >= 2:
            ref = X[:3 * WEEKLY_ARRIVALS]
            mon = drift_monitor(ref, X[arr], rng) if week > 3 else None
        if not frozen:
            pick = select(strategy, model, backlog, X, rng)
            lab, cost, dis = review(pick, S, hard, rng, policy, noise)
            backlog = np.setdiff1d(backlog, pick)
            lab_idx += pick.tolist(); lab_y += lab.tolist(); lab_week += [week] * len(pick)
            cum_cost += float(cost.sum())
            wk_dis = float(dis.mean())
        else:
            wk_dis = float("nan")
        li = np.array(lab_idx, dtype=int); ly = np.array(lab_y)
        Xt = np.vstack([Xg, X[li]]) if len(li) else Xg
        yt = np.r_[yg, ly] if len(li) else yg
        if resp == "window4" and len(li):
            keep = np.array(lab_week) > week - 4
            Xt = np.vstack([Xg, X[li][keep]]); yt = np.r_[yg, ly[keep]]
        if not frozen:
            model = fit(Xt, yt) or model
        thr = None
        if final:
            sc = model.decision_function(Xc)
            thr = None  # thresholds are calibrated in signal.py, not here
        row = dict(week=week, n_labeled=int(len(li)) + len(yg), cum_cost=cum_cost, wk_disagree=wk_dis,
                   drift_auc=mon, backlog=int(len(backlog)),
                   label_noise=float((ly != S["ypool"][li]).mean()) if len(li) else 0.0,
                   fake_share_labeled=float(S["ypool"][li].mean()) if len(li) else 0.0)
        row["clean"] = metrics(model, Xe, ye, None)
        row["drift"] = metrics(model, Xd, yd, None)
        rows.append(row)
        if week == WEEKS and final:
            row["scores_clean"] = model.decision_function(Xe).round(4).tolist()
            row["scores_drift"] = model.decision_function(Xd).round(4).tolist()
            row["scores_calib"] = model.decision_function(Xc).round(4).tolist()
            row["scores_calib_drift"] = model.decision_function(D["calib_drift"]).round(4).tolist()
    return dict(cfg=cfg, rows=rows, secs=time.time() - t0)


def init():
    global LOAD, HARD
    LOAD = load()
    HARD = oracle_hardness(LOAD)


def configs(suite, seeds, final):
    cs = []
    base = dict(policy="adjudicate", noise=1.0, drift_response="all", final=final)
    if suite in ("main", "all"):
        for s in seeds:
            for st in STRATEGIES:
                cs.append(dict(base, strategy=st, seed=s, suite="main"))
    if suite in ("policy", "all"):
        for s in seeds:
            for st in ("random", "uncertainty"):
                for pol in ("single", "majority3"):
                    cs.append(dict(base, strategy=st, seed=s, policy=pol, suite="policy"))
    if suite in ("noise", "all"):
        for s in seeds:
            for st in ("random", "uncertainty"):
                for nz in (0.0, 2.0):
                    cs.append(dict(base, strategy=st, seed=s, noise=nz, suite="noise"))
    if suite in ("drift", "all"):
        for s in seeds:
            for resp in ("window4", "frozen"):
                cs.append(dict(base, strategy="uncertainty", seed=s, drift_response=resp, suite="drift"))
    return cs


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--suite", default="main")
    ap.add_argument("--seeds", default="dev")
    ap.add_argument("--final", action="store_true")
    ap.add_argument("--procs", type=int, default=12)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    seeds = DEV_SEEDS if a.seeds == "dev" else FINAL_SEEDS
    if a.final:
        reg = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "PREREG.md")
        rec = os.path.join(os.path.dirname(reg), "prereg.sha256")
        h = hashlib.sha256(open(reg, "rb").read()).hexdigest()
        if not os.path.exists(rec) or open(rec).read().split()[0] != h:
            sys.exit("REFUSED: PREREG.md missing or does not match prereg.sha256 (pre-register before scoring held-out)")
        assert a.seeds == "final", "final scoring uses the pre-registered final seeds"
    cs = configs(a.suite, seeds, a.final)
    print(f"{len(cs)} runs, procs={a.procs}, C={C_HEAD}, final={a.final}", flush=True)
    t0 = time.time()
    with mp.Pool(a.procs, initializer=init) as pool, open(a.out, "w") as f:
        for i, r in enumerate(pool.imap_unordered(run_one, cs)):
            f.write(json.dumps(r) + "\n")
            if i % 20 == 0:
                print(i, f"{time.time() - t0:.0f}s", flush=True)
    print("wall seconds", round(time.time() - t0))
