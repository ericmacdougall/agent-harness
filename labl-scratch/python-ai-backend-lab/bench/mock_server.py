"""Mock model endpoint with a realistic latency profile and a finite capacity.

POST /v1/complete          -> one JSON completion after a lognormal service time
GET  /v1/stream            -> 40 chunks, 20 ms apart (server-sent style, newline framed)
Capacity: at most CAPACITY requests are "in the model" at once; extra requests queue (like a provider
rate limit), so latency grows when a client over-subscribes it.

Usage: python mock_server.py --port 18080 --median-ms 50 --sigma 0.5 --capacity 256
"""
import argparse
import asyncio
import json
import math
import random

from aiohttp import web


def make_app(median_ms: float, sigma: float, capacity: int, seed: int):
    rng = random.Random(seed)
    sem = asyncio.Semaphore(capacity)
    body = json.dumps({"text": "x" * 800, "tokens_in": 120, "tokens_out": 180})

    async def complete(request: web.Request) -> web.Response:
        async with sem:
            lat = rng.lognormvariate(math.log(median_ms / 1000.0), sigma)
            await asyncio.sleep(lat)
        return web.Response(text=body, content_type="application/json")

    async def stream(request: web.Request) -> web.StreamResponse:
        resp = web.StreamResponse()
        await resp.prepare(request)
        for i in range(40):
            await asyncio.sleep(0.02)
            await resp.write(f"tok{i} ".encode() + b"\n")
        await resp.write_eof()
        return resp

    async def health(request: web.Request) -> web.Response:
        return web.Response(text="ok")

    app = web.Application()
    app.add_routes([web.post("/v1/complete", complete), web.get("/v1/stream", stream), web.get("/health", health)])
    return app


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=18080)
    ap.add_argument("--median-ms", type=float, default=50.0)
    ap.add_argument("--sigma", type=float, default=0.5)
    ap.add_argument("--capacity", type=int, default=256)
    ap.add_argument("--seed", type=int, default=1)
    a = ap.parse_args()
    web.run_app(make_app(a.median_ms, a.sigma, a.capacity, a.seed), host="127.0.0.1", port=a.port, access_log=None, print=None)
