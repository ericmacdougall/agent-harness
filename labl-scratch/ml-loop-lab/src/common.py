"""Shared constants and helpers for the production-ML-loop lab."""
import hashlib
import io
import json
import os

import numpy as np
from PIL import Image, ImageEnhance, ImageFilter

DATASET = "dragonintelligence/CIFAKE-image-dataset"  # mirror of CIFAKE (Bird and Wang 2023); upstream licence MIT, mirror card has no tag
DATA_DIR = os.environ.get("LAB_DATA", "data")
FAKE_RATE = 0.20          # production-like class imbalance: 20% AI-generated submissions
WEEKS = 12
WEEKLY_ARRIVALS = 1500
N_POOL = WEEKS * WEEKLY_ARRIVALS
N_GOLD = 200              # expert-labelled seed set, noise free
N_CALIB = 2000            # threshold calibration set (never used to train or score)
N_TUNE = 1000             # hyper-parameter tuning set (never used for the final report)
N_HELD = 3000             # locked held-out (final report only)
N_PEEK = 400              # small "dev test" used only in the tune-on-test demo
N_DRIFT_HELD = 1000       # first 1000 held-out items re-rendered through the drifted pipeline
DRIFT_WEEK = 7            # first week that arrives through the new (drifted) upload pipeline
DRIFT_PARAMS = dict(jpeg_q=30, blur=0.7, brightness=0.9)
DEV_SEEDS = list(range(0, 5))
FINAL_SEEDS = list(range(100, 120))


def drift_image(arr, jpeg_q=30, blur=0.7, brightness=0.9):
    """A new client-side upload pipeline: stronger JPEG, a little blur, darker exposure."""
    im = Image.fromarray(arr)
    if blur:
        im = im.filter(ImageFilter.GaussianBlur(blur))
    im = ImageEnhance.Brightness(im).enhance(brightness)
    buf = io.BytesIO()
    im.save(buf, format="JPEG", quality=jpeg_q)
    buf.seek(0)
    return np.array(Image.open(buf).convert("RGB"))


def wilson(k, n, z=1.96):
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * np.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (float(c - h), float(c + h))
