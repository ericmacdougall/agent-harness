"""Fan out N model calls to the mock server with asyncio, threads or processes.

Each (approach, concurrency) cell is repeated REPEATS times against a fresh server session; the
script records wall time, throughput, per-call latency percentiles, client CPU seconds and peak RSS
and loadavg (the host is shared, so load is part of the result).

python bench_fanout.py --out ../results/fanout.json --repeats 10 --calls 1000
"""
import argparse
import asyncio
import concurrent.futures as cf
import http.client
import json
import os
import resource
import threading
import time

import aiohttp

from stats import mean_ci, pctl

HOST, PORT = "127.0.0.1", 18080
BODY = json.dumps({"prompt": "hello " * 100}).encode()


async def run_async(n, conc):
    lat = []
    sem = asyncio.Semaphore(conc)
    conn = aiohttp.TCPConnector(limit=0)
    async with aiohttp.ClientSession(connector=conn) as s:
        async def one():
            async with sem:
                t = time.perf_counter()
                async with s.post(f"http://{HOST}:{PORT}/v1/complete", data=BODY) as r:
                    await r.read()
                lat.append(time.perf_counter() - t)
        await asyncio.gather(*[one() for _ in range(n)])
    return lat


_local = threading.local()


def _sync_call():
    c = getattr(_local, "c", None)
    if c is None:
        c = _local.c = http.client.HTTPConnection(HOST, PORT)
    t = time.perf_counter()
    c.request("POST", "/v1/complete", BODY)
    c.getresponse().read()
    return time.perf_counter() - t


def run_threads(n, conc):
    with cf.ThreadPoolExecutor(conc) as ex:
        return list(ex.map(lambda _: _sync_call(), range(n)))


def _proc_chunk(k):
    c = http.client.HTTPConnection(HOST, PORT)
    out = []
    for _ in range(k):
        t = time.perf_counter()
        c.request("POST", "/v1/complete", BODY)
        c.getresponse().read()
        out.append(time.perf_counter() - t)
    return out


def run_procs(n, conc):
    per = [n // conc + (1 if i < n % conc else 0) for i in range(conc)]
    with cf.ProcessPoolExecutor(conc) as ex:
        return [x for chunk in ex.map(_proc_chunk, per) for x in chunk]


def timed(fn, n, conc):
    r0 = resource.getrusage(resource.RUSAGE_SELF)
    c0 = resource.getrusage(resource.RUSAGE_CHILDREN)
    t = time.perf_counter()
    lat = asyncio.run(fn(n, conc)) if asyncio.iscoroutinefunction(fn) else fn(n, conc)
    wall = time.perf_counter() - t
    r1 = resource.getrusage(resource.RUSAGE_SELF)
    c1 = resource.getrusage(resource.RUSAGE_CHILDREN)
    cpu = (r1.ru_utime + r1.ru_stime - r0.ru_utime - r0.ru_stime) + (c1.ru_utime + c1.ru_stime - c0.ru_utime - c0.ru_stime)
    return dict(wall=wall, thr=n / wall, p50=pctl(lat, .5) * 1000, p99=pctl(lat, .99) * 1000, cpu=cpu,
                rss_mb=r1.ru_maxrss / 1024, load1=os.getloadavg()[0], n_ok=len(lat))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--repeats", type=int, default=10)
    ap.add_argument("--calls", type=int, default=1000)
    a = ap.parse_args()
    grid = [("asyncio", run_async, [4, 16, 64, 256, 1024]),
            ("threads", run_threads, [4, 16, 64, 256, 1024]),
            ("processes", run_procs, [4, 16, 64])]
    res = []
    for rep in range(a.repeats):
        for name, fn, levels in grid:      # interleave approaches inside each repeat (drift-robust)
            for c in levels:
                r = timed(fn, a.calls, c)
                r.update(approach=name, conc=c, rep=rep)
                res.append(r)
                print(f"rep{rep} {name:9s} c={c:5d} wall={r['wall']:.2f}s thr={r['thr']:.0f}/s p99={r['p99']:.0f}ms cpu={r['cpu']:.2f}s rss={r['rss_mb']:.0f}MB load={r['load1']:.1f}", flush=True)
    meta = dict(calls=a.calls, repeats=a.repeats, cpus=os.cpu_count(), load_start=os.getloadavg())
    json.dump(dict(meta=meta, runs=res), open(a.out, "w"), indent=1)
    print("ok", a.out)
