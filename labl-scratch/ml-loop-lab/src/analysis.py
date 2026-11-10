"""Aggregate loop runs: learning curves, CIs, paired bootstrap, review cost per AP point, plots.

usage: analysis.py OUTDIR main.jsonl [policy.jsonl noise.jsonl drift.jsonl ...]
Seeds are the replication unit for curves (t-interval over seeds).  For the pre-registered
final-week comparison the bootstrap resamples held-out ITEMS (shared across strategies, so the
comparison is paired) and SEEDS jointly, 1000 repetitions, seed 20261110.
"""
import json
import os
import sys
from collections import defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from sklearn.metrics import average_precision_score
from scipy import stats

outdir = sys.argv[1]
os.makedirs(outdir, exist_ok=True)
runs = []
for p in sys.argv[2:]:
    runs += [json.loads(l) for l in open(p)]


def key(r):
    c = r["cfg"]
    return (c["suite"], c["strategy"], c["policy"], c["noise"], c["drift_response"])


groups = defaultdict(list)
for r in runs:
    groups[key(r)].append(r)


def curve(rs, split, metric):
    M = np.array([[row[split][metric] for row in r["rows"]] for r in sorted(rs, key=lambda r: r["cfg"]["seed"])])
    m = M.mean(0)
    h = stats.t.ppf(0.975, M.shape[0] - 1) * M.std(0, ddof=1) / np.sqrt(M.shape[0])
    return m, h, M


def cost_curve(rs):
    return np.array([[row["cum_cost"] for row in r["rows"]] for r in rs]).mean(0)


summary = {}
for k, rs in groups.items():
    name = "|".join(map(str, k))
    entry = dict(n_seeds=len(rs))
    for split in ("clean", "drift"):
        for metric in ("ap", "auc", "acc", "bacc"):
            m, h, _ = curve(rs, split, metric)
            entry[f"{split}_{metric}"] = dict(mean=m.round(4).tolist(), ci=h.round(4).tolist())
    entry["cum_cost"] = cost_curve(rs).round(1).tolist()
    entry["label_noise"] = np.mean([[row.get("label_noise", 0) for row in r["rows"]] for r in rs], 0).round(4).tolist()
    entry["disagree"] = float(np.nanmean([[row.get("wk_disagree", np.nan) for row in r["rows"][1:]] for r in rs]))
    entry["fake_share_labeled"] = float(np.mean([r["rows"][-1].get("fake_share_labeled", 0) for r in rs]))
    entry["drift_auc"] = np.nanmean(np.array([[row.get("drift_auc") if row.get("drift_auc") is not None else np.nan for row in r["rows"]] for r in rs], dtype=float), 0).round(3).tolist()
    summary[name] = entry

# review cost per AP point (clean AP, main suite)
cost = {}
for k, rs in groups.items():
    if k[0] != "main" and k[0] != "policy" and k[0] != "noise":
        continue
    m, _, _ = curve(rs, "clean", "ap")
    c = cost_curve(rs)
    gain = m[-1] - m[0]
    cost["|".join(map(str, k))] = dict(ap0=float(m[0]), ap12=float(m[-1]), votes=float(c[-1]),
                                         votes_per_ap_point=float(c[-1] / (gain * 100)) if gain > 0 else None)
summary["_cost_per_ap_point"] = cost

# pre-registered paired bootstrap at week 12 (needs saved scores)
final_scores = {}
y_held = None
for k, rs in groups.items():
    if k[0] == "main" and "scores_clean" in rs[0]["rows"][-1]:
        final_scores[k[1]] = np.array([r["rows"][-1]["scores_clean"] for r in sorted(rs, key=lambda r: r["cfg"]["seed"])])
if final_scores:
    sp = np.load(os.path.join(os.environ.get("LAB_DATA", "data"), "splits.npz"))
    y = sp["y_heldout"].astype(int)
    n = len(y)
    rng = np.random.default_rng(20261110)
    S = len(next(iter(final_scores.values())))
    reps = 1000
    ap_boot = {s: np.zeros(reps) for s in final_scores}
    for b in range(reps):
        it = rng.integers(0, n, n)
        if y[it].sum() in (0, n):
            continue
        sd = rng.integers(0, S, S)
        for s, sc in final_scores.items():
            ap_boot[s][b] = np.mean([average_precision_score(y[it], sc[j][it]) for j in sd])
    pt = {s: float(np.mean([average_precision_score(y, sc[j]) for j in range(S)])) for s, sc in final_scores.items()}
    boot = {}
    for s in final_scores:
        lo, hi = np.percentile(ap_boot[s], [2.5, 97.5])
        boot[s] = dict(ap=pt[s], lo=float(lo), hi=float(hi))
    diffs = {}
    for s in final_scores:
        if s == "random":
            continue
        d = ap_boot[s] - ap_boot["random"]
        diffs[f"{s}-random"] = dict(diff=pt[s] - pt["random"], lo=float(np.percentile(d, 2.5)), hi=float(np.percentile(d, 97.5)))
    summary["_week12_heldout"] = dict(n_items=int(n), n_pos=int(y.sum()), n_seeds=S, ap=boot, paired_diff_vs_random=diffs)
    # single-model Wilson-free item CI example: seed 0 accuracy at threshold 0
    accs = {s: float(np.mean([((sc[j] > 0).astype(int) == y).mean() for j in range(S)])) for s, sc in final_scores.items()}
    summary["_week12_heldout"]["accuracy_mean_over_seeds"] = accs

json.dump(summary, open(os.path.join(outdir, "summary.json"), "w"), indent=1)

# plots
main = {k[1]: rs for k, rs in groups.items() if k[0] == "main"}
cols = dict(random="#888", uncertainty="#d62728", topscore="#1f77b4", margin_div="#2ca02c", hybrid="#ff7f0e")
fig, ax = plt.subplots(1, 3, figsize=(16, 4.4))
for s, rs in main.items():
    m, h, _ = curve(rs, "clean", "ap"); w = np.arange(len(m))
    ax[0].plot(w, m, label=s, color=cols.get(s)); ax[0].fill_between(w, m - h, m + h, alpha=.15, color=cols.get(s))
    c = cost_curve(rs); ax[1].plot(c, m, label=s, color=cols.get(s))
    m2, h2, _ = curve(rs, "drift", "ap"); ax[2].plot(w, m2, label=s, color=cols.get(s)); ax[2].fill_between(w, m2 - h2, m2 + h2, alpha=.15, color=cols.get(s))
ax[0].set(title="Held-out AP, clean (mean, 95% CI over seeds)", xlabel="week", ylabel="average precision")
ax[1].set(title="AP vs review cost", xlabel="cumulative reviewer votes", ylabel="average precision")
ax[2].set(title="Held-out AP, drifted pipeline", xlabel="week (drift starts week 7)")
for a_ in ax:
    a_.axvline(6.5, ls=":", c="k", lw=.8) if a_ is not ax[1] else None
    a_.grid(alpha=.3)
ax[0].legend()
fig.tight_layout(); fig.savefig(os.path.join(outdir, "learning_curves.png"), dpi=130)

fig, ax = plt.subplots(1, 3, figsize=(16, 4.2))
for (k, rs) in groups.items():
    if k[0] == "policy" or (k[0] == "main" and k[1] in ("random", "uncertainty")):
        m, h, _ = curve(rs, "clean", "ap"); ax[0].plot(np.arange(len(m)), m, label=f"{k[1]}/{k[2]}", ls="-" if k[1] == "uncertainty" else "--")
    if k[0] == "noise" or (k[0] == "main" and k[1] in ("random", "uncertainty")):
        m, h, _ = curve(rs, "clean", "ap"); ax[1].plot(np.arange(len(m)), m, label=f"{k[1]}/noise x{k[3]}", ls="-" if k[1] == "uncertainty" else "--")
    if k[0] == "drift" or (k[0] == "main" and k[1] == "uncertainty"):
        m, h, _ = curve(rs, "drift", "ap"); ax[2].plot(np.arange(len(m)), m, label=f"resp={k[4]}")
ax[0].set(title="Label policy (clean AP)", xlabel="week"); ax[1].set(title="Reviewer noise (clean AP)", xlabel="week"); ax[2].set(title="Drift response (drifted AP)", xlabel="week")
for a_ in ax:
    a_.legend(fontsize=7); a_.grid(alpha=.3)
fig.tight_layout(); fig.savefig(os.path.join(outdir, "ablations.png"), dpi=130)
print(json.dumps(summary.get("_week12_heldout"), indent=1))
print(json.dumps(summary["_cost_per_ap_point"], indent=1))
