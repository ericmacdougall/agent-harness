"""Generators and streaming: peak memory and time-to-first-result.

Part 1 (memory): process a JSONL file of N request logs (sum tokens per tenant) three ways, each in a
fresh subprocess so peak RSS (ru_maxrss) is clean:
  list    json.loads every line into a list, then aggregate
  gen     generator pipeline, one record alive at a time
  batched generator yielding lists of 1000 (what you feed a model or a bulk insert)
Part 2 (TTFT): consume the mock server's 40-chunk stream either incrementally (async generator, first
chunk handled as it arrives) or buffered (read everything, then handle).

python bench_mem.py --out ../results/mem.json --lines 1000000 --repeats 10
"""
import argparse
import asyncio
import json
import os
import resource
import subprocess
import sys
import tempfile
import time

from stats import mean_ci

CHILD = r"""
import json, resource, sys, time
mode, path = sys.argv[1], sys.argv[2]
def records(p):
    with open(p) as f:
        for line in f:
            yield json.loads(line)
def batches(it, n=1000):
    b = []
    for x in it:
        b.append(x)
        if len(b) == n:
            yield b; b = []
    if b: yield b
t = time.perf_counter(); tot = {}
if mode == "list":
    allr = [json.loads(l) for l in open(path)]
    for r in allr: tot[r["tenant"]] = tot.get(r["tenant"], 0) + r["tokens"]
elif mode == "gen":
    for r in records(path): tot[r["tenant"]] = tot.get(r["tenant"], 0) + r["tokens"]
else:
    for b in batches(records(path)):
        for r in b: tot[r["tenant"]] = tot.get(r["tenant"], 0) + r["tokens"]
print(json.dumps(dict(secs=time.perf_counter() - t, rss_mb=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, tenants=len(tot), total=sum(tot.values()))))
"""


def make_file(n):
    path = os.path.join(tempfile.gettempdir(), f"lab_requests_{n}.jsonl")
    if not os.path.exists(path):
        with open(path, "w") as f:
            for i in range(n):
                f.write(json.dumps({"tenant": f"t{i % 500}", "tokens": i % 997, "model": "m-large",
                                    "prompt_hash": f"{i:016x}", "ts": 1.7e9 + i}) + "\n")
    return path


async def ttft(stream):
    import aiohttp
    t0 = time.perf_counter()
    async with aiohttp.ClientSession() as s:
        async with s.get("http://127.0.0.1:18080/v1/stream") as r:
            if stream:
                async for _line in r.content:
                    return time.perf_counter() - t0, None
            body = await r.read()
            return time.perf_counter() - t0, len(body)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--lines", type=int, default=1_000_000)
    ap.add_argument("--repeats", type=int, default=10)
    a = ap.parse_args()
    path = make_file(a.lines)
    size = os.path.getsize(path) / 1e6
    res = []
    for rep in range(a.repeats):
        for mode in ("list", "gen", "batched"):
            out = subprocess.run([sys.executable, "-c", CHILD, mode, path], capture_output=True, text=True, check=True).stdout
            r = json.loads(out); r.update(mode=mode, rep=rep, kind="mem")
            res.append(r)
            print(f"rep{rep} {mode:8s} {r['secs']:.2f}s rss={r['rss_mb']:.0f}MB", flush=True)
        for stream in (True, False):
            t, _ = asyncio.run(ttft(stream))
            res.append(dict(kind="ttft", mode="stream" if stream else "buffered", ttft_ms=t * 1000, rep=rep))
            print(f"rep{rep} ttft {'stream' if stream else 'buffered'} {t * 1000:.0f} ms", flush=True)
    json.dump(dict(meta=dict(lines=a.lines, file_mb=size, python=sys.version.split()[0], load_start=os.getloadavg()), runs=res), open(a.out, "w"), indent=1)
    os.remove(path)
    print("ok")
