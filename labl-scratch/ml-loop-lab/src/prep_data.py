"""Download CIFAKE (public, MIT) and cut disjoint splits at 20% fake prevalence.

Splits (all disjoint, seed 0):
  dataset train split : pool (18000), gold (200), calib (2000), tune (1000)
  dataset test split  : heldout (3000), peek (400)
"""
import hashlib
import json
import os

import numpy as np
from datasets import load_dataset

from common import *  # noqa

rng = np.random.default_rng(0)
os.makedirs(DATA_DIR, exist_ok=True)
ds = load_dataset(DATASET)
print(ds)
feat = ds["train"].features["label"]
print("label names", feat.names)
fake_id = [i for i, n in enumerate(feat.names) if n.upper().startswith("FAKE")][0]


def cut(split, sizes):
    labels = np.array(ds[split]["label"])
    fake_idx = rng.permutation(np.where(labels == fake_id)[0])
    real_idx = rng.permutation(np.where(labels != fake_id)[0])
    out, fp, rp = {}, 0, 0
    for name, n in sizes.items():
        nf = int(round(n * FAKE_RATE))
        idx = np.concatenate([fake_idx[fp:fp + nf], real_idx[rp:rp + n - nf]])
        fp += nf
        rp += n - nf
        out[name] = rng.permutation(idx)
    return out


train_cut = cut("train", dict(pool=N_POOL, gold=N_GOLD, calib=N_CALIB, tune=N_TUNE))
test_cut = cut("test", dict(heldout=N_HELD, peek=N_PEEK))


def fetch(split, idx):
    sub = ds[split].select(idx.tolist())
    X = np.stack([np.array(im.convert("RGB")) for im in sub["image"]])
    y = (np.array(sub["label"]) == fake_id).astype(np.int8)
    return X, y


arrays, meta, hashes = {}, {}, {}
for split, cuts in (("train", train_cut), ("test", test_cut)):
    for name, idx in cuts.items():
        X, y = fetch(split, idx)
        arrays[f"X_{name}"] = X
        arrays[f"y_{name}"] = y
        arrays[f"src_{name}"] = idx
        hashes[name] = [hashlib.md5(x.tobytes()).hexdigest() for x in X]
        meta[name] = dict(n=int(len(y)), fake=int(y.sum()), source_split=split,
                          within_split_dupes=int(len(y) - len(set(hashes[name]))))
        print(name, len(y), "fake", int(y.sum()), "within-split dupes", meta[name]["within_split_dupes"])

names = list(hashes)
dups = {}
for i, a in enumerate(names):
    for b in names[i + 1:]:
        d = len(set(hashes[a]) & set(hashes[b]))
        if d:
            dups[f"{a}&{b}"] = d
print("cross-split exact-pixel duplicates:", dups)
meta["cross_split_duplicates"] = dups
meta["dataset"] = DATASET
meta["fake_rate"] = FAKE_RATE
np.savez_compressed(os.path.join(DATA_DIR, "splits.npz"), **arrays)
with open(os.path.join(DATA_DIR, "splits.json"), "w") as f:
    json.dump(meta, f, indent=1)
