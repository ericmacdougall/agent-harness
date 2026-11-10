"""Embed every split with a frozen open-weight CLIP ViT-B/32 (OpenAI weights, MIT).

Also embeds drifted copies (pool weeks >= DRIFT_WEEK, first N_DRIFT_HELD held-out items, first 1000
calibration items) re-rendered through drift_image(). Zero-shot CLIP text scores ("a real photograph"
vs "an AI-generated image") are saved as the open-weight zero-shot signal model.
"""
import os
import time

import numpy as np
import open_clip
import torch
from PIL import Image

from common import *  # noqa

torch.set_num_threads(int(os.environ.get("LAB_THREADS", "24")))
model, _, preprocess = open_clip.create_model_and_transforms("ViT-B-32-quickgelu", pretrained="openai")
tok = open_clip.get_tokenizer("ViT-B-32-quickgelu")
model.eval()
sp = np.load(os.path.join(DATA_DIR, "splits.npz"))


def embed(X, bs=256):
    out = []
    t0 = time.time()
    for i in range(0, len(X), bs):
        batch = torch.stack([preprocess(Image.fromarray(x)) for x in X[i:i + bs]])
        with torch.no_grad():
            f = model.encode_image(batch)
            f = f / f.norm(dim=-1, keepdim=True)
        out.append(f.numpy().astype(np.float32))
        if (i // bs) % 10 == 0:
            print(f"  {i + len(batch)}/{len(X)}  {(i + len(batch)) / (time.time() - t0):.1f} img/s", flush=True)
    return np.concatenate(out)


off = (DRIFT_WEEK - 1) * WEEKLY_ARRIVALS
jobs = {
    "pool": sp["X_pool"], "gold": sp["X_gold"], "calib": sp["X_calib"], "tune": sp["X_tune"],
    "heldout": sp["X_heldout"], "peek": sp["X_peek"],
    "pool_drift": np.stack([drift_image(x, **DRIFT_PARAMS) for x in sp["X_pool"][off:]]),
    "heldout_drift": np.stack([drift_image(x, **DRIFT_PARAMS) for x in sp["X_heldout"][:N_DRIFT_HELD]]),
    "calib_drift": np.stack([drift_image(x, **DRIFT_PARAMS) for x in sp["X_calib"][:1000]]),
}
t_all = time.time()
emb = {}
for k, X in jobs.items():
    print("embedding", k, X.shape, flush=True)
    emb[k] = embed(X)
with torch.no_grad():
    tf = model.encode_text(tok(["a real photograph", "an AI-generated image"]))
    tf = (tf / tf.norm(dim=-1, keepdim=True)).numpy()
zs = {k: ((v @ tf.T) * 100.0) for k, v in emb.items()}
zs = {k: (v[:, 1] - v[:, 0]).astype(np.float32) for k, v in zs.items()}  # >0 means "AI-generated"
np.savez_compressed(os.path.join(DATA_DIR, "emb.npz"), **{f"E_{k}": v for k, v in emb.items()},
                    **{f"Z_{k}": v for k, v in zs.items()}, text_feats=tf)
print("done in %.0fs" % (time.time() - t_all))
