"""The GIL effect: the same fixed amount of work run by 1..16 threads or processes.

Work kinds (each unit takes a few tens of ms serially):
  py     pure-Python pre-processing (tokenise, count, hash-mix a 20 KB text) - holds the GIL
  numpy  300x300 matmul with BLAS pinned to 1 thread - releases the GIL inside the kernel
  hash   sha256 over 8 MB - hashlib releases the GIL for large buffers
  io     time.sleep(0.02) standing in for a network/disk wait - releases the GIL

python bench_gil.py --out ../results/gil_<tag>.json --repeats 10
"""
import os

for v in ("OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS"):
    os.environ[v] = "1"

import argparse
import concurrent.futures as cf
import hashlib
import json
import sys
import sysconfig
import time

try:
    import numpy as np
except ImportError:  # free-threaded interpreter without numpy wheels
    np = None

TEXT = ("the quick brown fox jumps over the lazy dog and pays purchase order 4711 " * 300)
BUF = os.urandom(8 << 20)
UNITS = 200


def w_py(_=0):
    counts = {}
    h = 0
    for _ in range(4):
        for w in TEXT.split():
            counts[w] = counts.get(w, 0) + 1
            h = (h * 31 + len(w)) & 0xFFFFFFFF
    return h


def w_numpy(_=0):
    a = np.ones((300, 300))
    return float((a @ a).sum())


def w_hash(_=0):
    return hashlib.sha256(BUF).digest()[0]


def w_io(_=0):
    time.sleep(0.02)


WORK = {"py": w_py, "hash": w_hash, "io": w_io}
if np is not None:
    WORK["numpy"] = w_numpy


def _chunk(args):
    kind, k = args
    f = WORK[kind]
    for _ in range(k):
        f()
    return k


def run(kind, mode, workers):
    f = WORK[kind]
    if mode == "serial":
        t = time.perf_counter()
        for _ in range(UNITS):
            f()
        return time.perf_counter() - t
    if mode == "threads":
        with cf.ThreadPoolExecutor(workers) as ex:
            list(ex.map(f, range(workers)))                 # warm
            t = time.perf_counter()
            list(ex.map(f, range(UNITS)))
            return time.perf_counter() - t
    with cf.ProcessPoolExecutor(workers) as ex:
        list(ex.map(_chunk, [(kind, 1)] * workers))          # warm (fork + import)
        per = [(kind, UNITS // workers + (1 if i < UNITS % workers else 0)) for i in range(workers)]
        t = time.perf_counter()
        list(ex.map(_chunk, per))
        return time.perf_counter() - t


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--repeats", type=int, default=10)
    ap.add_argument("--workers", default="1,2,4,8,16")
    ap.add_argument("--modes", default="threads,processes")
    a = ap.parse_args()
    gil = getattr(sys, "_is_gil_enabled", lambda: True)()
    meta = dict(python=sys.version.split()[0], gil_enabled=gil, free_threaded_build=bool(sysconfig.get_config_var("Py_GIL_DISABLED")),
                cpus=os.cpu_count(), units=UNITS, load_start=os.getloadavg())
    res = []
    for rep in range(a.repeats):
        for kind in WORK:
            s = run(kind, "serial", 1)
            res.append(dict(kind=kind, mode="serial", workers=1, wall=s, rep=rep, load1=os.getloadavg()[0]))
            for mode in a.modes.split(","):
                for w in [int(x) for x in a.workers.split(",")]:
                    wall = run(kind, mode, w)
                    res.append(dict(kind=kind, mode=mode, workers=w, wall=wall, serial=s, rep=rep, load1=os.getloadavg()[0]))
                    print(f"rep{rep} {kind:5s} {mode:9s} w={w:2d} wall={wall:.2f}s speedup={s / wall:.2f}x load={os.getloadavg()[0]:.1f}", flush=True)
    json.dump(dict(meta=meta, runs=res), open(a.out, "w"), indent=1)
    print("ok", a.out, meta)
