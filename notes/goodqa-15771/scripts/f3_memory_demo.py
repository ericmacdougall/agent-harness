"""F3 evidence (goodqa#15771): peak Python allocation in the ops-watch process while the default runner reads a
child that prints 8 MiB, as the pool check calls it. Old runner (7bb3aa29): run(argv, 25), everything buffered
before the 1 MiB check. New runner: run(argv, 25, max_bytes=POOL_MAX_BYTES).
Usage: python3 -B f3_memory_demo.py <dir holding ops_watch.py> <label>"""
import importlib.util
import sys
import tracemalloc

spec = importlib.util.spec_from_file_location("ops_watch", sys.argv[1] + "/ops_watch.py")
ow = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ow)

argv = [sys.executable, "-c", "import sys; sys.stdout.write('x' * (8 << 20))"]
kw = {"max_bytes": ow.POOL_MAX_BYTES} if hasattr(ow, "POOL_MAX_BYTES") else {}
tracemalloc.start()
rc, out = ow.run(argv, 25, **kw)
peak = tracemalloc.get_traced_memory()[1]
tracemalloc.stop()
print(f"{sys.argv[2]}: rc={rc} returned_bytes={len(out)} peak_alloc_mib={peak / 2**20:.1f} cap_kw={kw or 'none'}")
