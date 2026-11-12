"""goodqa#15827 failing-first evidence: the new tests must fail against the code WITHOUT the fix (origin/main) and against each
controlled broken variant of forward_foreign.

Run: python3 -B tests/mutants_ops_forward.py   (copies the hooks and the tests into a temporary tree; changes nothing here)."""
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEST = "tests.test_ops_watch_forward"
TARGET = "ops_watch.py"

MUTANTS = {
    "forwarding removed": ("    foreign = forward_foreign(cfg, home, state, ring, now)", "    foreign = []"),
    "deadman not fed": ("        queue_events(cfg, state, [dict(e, detail=e[\"detail\"] if isinstance(e.get(\"detail\"), dict) else {}) for e in foreign], now)",
                        "        state[\"pending_comment\"] = ((state.get(\"pending_comment\") or []) + [compact(e) for e in foreign])[-500:]"),
    "every severity forwarded": ("            if e.get(\"event\") == \"raise\" and e.get(\"severity\") == \"critical\":\n                if detail.get",
                                 "            if e.get(\"event\") == \"raise\":\n                if detail.get"),
    "clear never forwarded": ("            elif e.get(\"event\") == \"clear\" and ident in active:", "            elif False:"),
    "clear without a forwarded raise": ("            elif e.get(\"event\") == \"clear\" and ident in active:  # an expiry clear carries updated=true and still closes the raise\n                del active[ident]",
                                        "            elif e.get(\"event\") == \"clear\":\n                active.pop(ident, None)"),
    "forwarded seq not advanced": ("    state[\"fwd_seq\"] = top", "    pass"),
    "text refreshes forwarded": ("                if detail.get(\"updated\") or detail.get(\"reasserted\"):\n                    continue  # a text refresh is not a new alert",
                                 "                if False:\n                    continue"),
    "first run forwards the history": ("    seen = state.get(\"fwd_seq\")\n", "    seen = state.get(\"fwd_seq\") or 0\n"),
    "ops-watch source not excluded": (" or ring_host(e) != host or e.get(\"source\") == SOURCE:\n                continue",
                                      " or ring_host(e) != host:\n                continue"),
    "ring reset ignored": ("    recreated = isinstance(seen, int) and ((bool(stored_id) and stored_id != ring_id) or state[\"fwd_low\"] >= 3)",
                           "    recreated = False"),
    "non-dict detail trusted": ('            detail = e.get("detail") if isinstance(e.get("detail"), dict) else {}  # emit() lets any JSON through as detail',
                                '            detail = e.get("detail") or {}'),
    "empty or unreadable read treated as a reset": ("    if isinstance(seen, int) and not rows:\n        return []", "    if False:\n        return []"),
    "one low read resets": ("state[\"fwd_low\"] >= 3)", "state[\"fwd_low\"] >= 1)"),
    "expiry clear skipped": ("            elif e.get(\"event\") == \"clear\" and ident in active:", "            elif e.get(\"event\") == \"clear\" and ident in active and not detail.get(\"updated\"):"),
    "emit accepts a non-string key": ("    if not all(isinstance(event.get(k), str) for k in (\"host\", \"source\", \"key\")):", "    if False:"),
    "reader accepts a non-string key": ("                and all(isinstance(obj.get(k), (str, type(None))) for k in (\"host\", \"source\", \"key\"))):", "                ):"),
    "reset drops the lost clear": ("            elif e.get(\"event\") == \"clear\" and f\"{src}/{key}\" in before:", "            elif False:"),
}


def run(tmp, label):
    done = subprocess.run([sys.executable, "-B", "-m", "unittest", TEST], cwd=str(tmp), capture_output=True, text=True)
    killed = done.returncode != 0
    print("%-42s %s" % (label, "FAILS (good)" if killed else "PASSES (test is vacuous)"))
    return killed


def tree():
    tmp = Path(tempfile.mkdtemp(prefix="mutant-"))
    shutil.copytree(ROOT / "harness" / "hooks", tmp / "harness" / "hooks", ignore=shutil.ignore_patterns("__pycache__"))
    (tmp / "tests").mkdir()
    for name in ("test_ops_watch_forward.py", "test_ops_watch.py"):
        shutil.copy(ROOT / "tests" / name, tmp / "tests")
    return tmp


def main():
    bad = 0
    tmp = tree()
    try:
        base = subprocess.run(["git", "-C", str(ROOT), "show", "origin/main:harness/hooks/" + TARGET], capture_output=True, check=True).stdout
        (tmp / "harness" / "hooks" / TARGET).write_bytes(base)
        bad += 0 if run(tmp, "origin/main (no fix)") else 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    for name, (old, new) in MUTANTS.items():
        tmp = tree()
        try:
            path = tmp / "harness" / "hooks" / TARGET
            text = path.read_text()
            if old not in text:
                print("MUTANT NOT APPLIED:", name)
                bad += 1
                continue
            path.write_text(text.replace(old, new, 1))
            bad += 0 if run(tmp, name) else 1
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
