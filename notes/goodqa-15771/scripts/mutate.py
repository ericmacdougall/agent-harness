"""In-memory mutation checks for the r2 F1 fix (goodqa#15771). Each broken variant of ops_watch.py is compiled from
a string and registered as `ops_watch`; tests.test_ops_watch_proxmox must then fail. No file is written.
Usage: python3 -B mutate.py <worktree>"""
import importlib
import io
import sys
import types
import unittest
from pathlib import Path

WT = Path(sys.argv[1])
SRC = (WT / "harness/hooks/ops_watch.py").read_text()
MUTATIONS = {
    "M1-images-only": ('POOL_GUEST_TYPES = ("images", "rootdir")', 'POOL_GUEST_TYPES = ("images",)'),
    "M2-no-file-crosscheck": ("        if (int(m.group(1)), m.group(2)) not in listed:", "        if False:"),
    "M3-zero-size-ok": (" and int(cols[3]) > 0:", ":"),
    "M4-ignore-vols-rc": ('list_ok = list_ok and rcs.get("VOLS") == 0 and "VOLS" in sections', "list_ok = list_ok"),
    "M5-ignore-files-rc": ('files_ok = files_ok and rcs.get("FILES") == 0 and "FILES" in sections', "files_ok = files_ok"),
    "M6-trust-partial-listing": ("    if not (list_ok and files_ok):  # every", "    if not files_ok:  # every"),
    "M8-trust-subtotals-without-files": ("    if not (list_ok and files_ok):  # every", "    if not list_ok:  # every"),
    "M9-ignore-du-rc": ('if len(vals) == 1 and rcs.get(f"DU {vm}") == 0}', "if len(vals) == 1}"),
    "M10-du-duplicates-ok": ('if len(vals) == 1 and rcs.get(f"DU {vm}") == 0}', 'if rcs.get(f"DU {vm}") == 0}'),
    "M11-du-without-rc-line": ('timeout 5 du -sk {mount}/images/{int(v)}; echo \\"##RC DU {int(v)} $?\\"; ',
                               'timeout 5 du -sk {mount}/images/{int(v)}; '),
    "M12-no-stdout-cap": ("                if len(out) > max_bytes:\n                    return out, True",
                          "                if False:\n                    return out, True"),
    "M13-no-stderr-cap": ("                if err > max_bytes:\n                    return out, True",
                          "                if False:\n                    return out, True"),
    "M16-overflow-not-sticky": (  # the r5 bug: the flag is reassigned per chunk and only checked after the batch
        "            if key.data == \"out\":\n                out += chunk\n                if len(out) > max_bytes:\n"
        "                    return out, True\n            else:\n"
        "                err += len(chunk)  # discarded, but counted against the same cap\n"
        "                if err > max_bytes:\n                    return out, True\n    return out, False",
        "            if key.data == \"out\":\n                out += chunk\n                hit = len(out) > max_bytes\n"
        "            else:\n                err += len(chunk)\n                hit = err > max_bytes\n"
        "        if locals().get(\"hit\"):\n            return out, True\n    return out, False"),
    "M14-no-kill-on-overflow": ("        if overflow:\n            p.kill()\n            p.wait()\n",
                                "        if overflow:\n"),
    "M15-pool-uncapped": ("pool_script(storage, mount, watch)], 25, max_bytes=POOL_MAX_BYTES)",
                          "pool_script(storage, mount, watch)], 25)"),
    "M7-backup-counts": ("        if cols[2] not in POOL_GUEST_TYPES:\n            continue\n", ""),
}
sys.path.insert(0, str(WT / "harness/hooks"))
sys.path.insert(0, str(WT))
dead = 0
for name, (old, new) in MUTATIONS.items():
    if SRC.count(old) != 1:
        print(f"{name}: MUTATION NOT APPLIED")
        continue
    mod = types.ModuleType("ops_watch")
    mod.__file__ = str(WT / "harness/hooks/ops_watch.py")
    sys.modules["ops_watch"] = mod
    exec(compile(SRC.replace(old, new), mod.__file__, "exec"), mod.__dict__)
    sys.modules.pop("tests.test_ops_watch_proxmox", None)
    tests = importlib.import_module("tests.test_ops_watch_proxmox")
    res = unittest.TextTestRunner(stream=io.StringIO(), verbosity=0).run(
        unittest.defaultTestLoader.loadTestsFromModule(tests))
    killed = not res.wasSuccessful()
    dead += killed
    print(f"{name}: {'KILLED' if killed else 'SURVIVED'} ({len(res.failures)} failures, {len(res.errors)} errors "
          f"of {res.testsRun})")
print(f"{dead} of {len(MUTATIONS)} mutations killed")
sys.exit(0 if dead == len(MUTATIONS) else 1)
