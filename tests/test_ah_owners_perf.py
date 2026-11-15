"""goodqa#15963: `ah owners` must stay inside tier_gate's 4 s deadline on a 2,400-agent session.

Count-based (deterministic) checks fail against the previous implementation: it stat-ed every agent in every
project's subagents dir (agents x dirs) and rewrote every index file on every call. A golden comparison runs the
origin/main implementation (AH_OLD_PY, when given) on the same fixture. Wall-clock numbers are reported in the
ticket, never asserted here.
"""
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "harness" / "hooks"))
import ah  # noqa: E402

SESSION = "11111111-2222-4333-8444-555555555555"
NOW = 1_794_600_000.0


def iso(ts):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def jl(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a") as f:
        for r in rows:
            f.write((r if isinstance(r, str) else json.dumps(r)) + "\n")


def build(home: Path, agents: int, dirs: int):
    """A session with `agents` sub-agents over `dirs` project dirs; transcripts live in one of them, as in reality.
    Covers live, SILENT-HIGH, idle-helper, DROPPED, done, returned, handoff, restricted and transcript-only rows."""
    w = home / ".claude" / "wals" / SESSION
    proj = home / ".claude" / "projects"
    for d in range(dirs):
        (proj / f"-p{d}").mkdir(parents=True)
    sub = proj / "-p0" / SESSION / "subagents"
    sub.mkdir(parents=True)
    main = []
    for i in range(agents):
        aid = f"a{i:016x}"
        kind = ("task-owner", "fixer", "general-purpose", "red-team")[i % 4]
        main.append({"at": iso(NOW - 9000), "event": "subagent", "agent_id": aid, "agent_type": kind})
        mode = i % 7
        if mode == 0:     # live owner with a ticket
            jl(w / f"agent-{aid}.jsonl", [{"at": iso(NOW - 30), "event": "intent", "note": f"build GoodQA goodqa#{i}"}])
        elif mode == 1:   # silent (high)
            jl(w / f"agent-{aid}.jsonl", [{"at": iso(NOW - 7300), "event": "intent", "note": "quiet work"}])
        elif mode == 2:   # stopped without a result: DROPPED for owners, returned for helpers
            jl(w / f"agent-{aid}.jsonl", [{"at": iso(NOW - 4000), "event": "intent", "note": "dropped"}])
            main.append({"at": iso(NOW - 100), "event": "subagent_stop", "agent_id": aid, "agent_type": kind})
        elif mode == 3:   # done
            jl(w / f"agent-{aid}.jsonl", [{"at": iso(NOW - 500), "event": "intent", "note": "x"},
                                          {"at": iso(NOW - 200), "event": "result", "note": "all done"}])
            main.append({"at": iso(NOW - 100), "event": "subagent_stop", "agent_id": aid, "agent_type": kind})
        elif mode == 4:   # handoff
            jl(w / f"agent-{aid}.jsonl", [{"at": iso(NOW - 900), "event": "handoff", "note": "over to main"}])
            main.append({"at": iso(NOW - 100), "event": "subagent_stop", "agent_id": aid, "agent_type": kind})
        elif mode == 5:   # restricted task text
            jl(w / f"agent-{aid}.jsonl", [{"at": iso(NOW - 40), "event": "intent", "note": "Solve interview prep"}])
        # mode 6: no WAL at all; transcript only
        meta = {"agentType": kind, "description": f"d{i}"}
        if mode == 3:
            meta["finished"] = True
        (sub / f"agent-{aid}.meta.json").write_text(json.dumps(meta))
        t = sub / f"agent-{aid}.jsonl"
        t.write_text("{}\n")
        age = 20 if mode == 6 else 8000      # mode 6: the transcript is newer than any WAL
        os.utime(t, (NOW - age, NOW - age))
    jl(w / "main.jsonl", main)


def load_old():
    path = os.environ.get("AH_OLD_PY")
    if not path:
        return None
    spec = importlib.util.spec_from_file_location("ah_old", path)
    mod = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(Path(path).parent))
    spec.loader.exec_module(mod)
    return mod


def strip(data):
    return {k: v for k, v in data.items() if k != "generated"}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name) / "h"
        self.addCleanup(self.tmp.cleanup)
        p = mock.patch.dict(os.environ, {"AH_HOME": str(self.home), "HOME": str(self.home)})
        p.start()
        self.addCleanup(p.stop)

    def home_copy(self, name):
        dest = Path(self.tmp.name) / name
        shutil.copytree(self.home, dest, symlinks=True)
        return dest


class Counts(Base):
    AGENTS, DIRS = 240, 120

    def setUp(self):
        super().setUp()
        build(self.home, self.AGENTS, self.DIRS)

    def test_stat_and_scandir_calls_do_not_grow_with_agents_times_dirs(self):  # AC-1 (R4, M3)
        """Adding 120 empty project dirs may cost a few calls per dir, never one per agent per dir (old: +28,800)."""
        def count(home):
            calls = {"stat": 0, "scandir": 0, "lstat": 0}
            real = {name: getattr(os, name) for name in calls}

            def wrap(name):
                def f(*a, **k):
                    calls[name] += 1
                    return real[name](*a, **k)
                return f
            with mock.patch.object(os, "stat", wrap("stat")), mock.patch.object(os, "scandir", wrap("scandir")), \
                    mock.patch.object(os, "lstat", wrap("lstat")), \
                    mock.patch.dict(os.environ, {"AH_HOME": str(home), "HOME": str(home)}):
                ah.owners(home, SESSION, now=NOW)
            return sum(calls.values()), calls
        small = Path(self.tmp.name) / "small"
        build(small, self.AGENTS, self.DIRS)
        more = Path(self.tmp.name) / "more"   # same depth as `small`, so realpath costs match
        build(more, self.AGENTS, self.DIRS * 2)
        (few, few_calls), (many, many_calls) = count(small), count(more)
        self.assertLess(many - few, 4 * self.DIRS, (few_calls, many_calls))

    def test_an_unchanged_second_call_writes_no_index_file(self):  # AC-1 (R1: no unconditional rewrites)
        ah.owners(self.home, SESSION, now=NOW)
        with mock.patch.object(ah, "atomic_json", wraps=ah.atomic_json) as write:
            ah.owners(self.home, SESSION, now=NOW)
        self.assertEqual(write.call_count, 0)

    def test_a_changed_wal_the_cache_holds_skips_its_index_file(self):  # PR 245 cold path
        """The owners cache's own summary is the starting state: the per-WAL index is neither read nor written again,
        and the result equals a fresh read of the same files (incremental, checked by offset, inode and tail hash)."""
        ah.owners(self.home, SESSION, now=NOW)
        aid = "a" + f"{4:016x}"     # mode 4: handoff
        index = ah.state_dir(self.home, "ah-index")
        before = {f.name: f.read_bytes() for f in index.glob("wal-*.json")}
        jl(self.home / ".claude" / "wals" / SESSION / f"agent-{aid}.jsonl",
           [{"at": iso(NOW - 10), "event": "intent", "note": "back at it GoodQA goodqa#77"}, "{torn"])
        real = ah._bounded
        reads = []

        def spy(path, *a, **k):
            if Path(path).name.startswith("wal-"):
                reads.append(Path(path).name)
            return real(path, *a, **k)
        with mock.patch.object(ah, "_bounded", spy):
            again = ah.owners(self.home, SESSION, now=NOW)
        self.assertEqual(reads, [], "no per-WAL index file was read")
        self.assertEqual({f.name: f.read_bytes() for f in index.glob("wal-*.json")}, before, "no index file changed")
        fresh = ah.owners(self.home_copy("fresh-changed"), SESSION, now=NOW)
        row = {r["agent_id"]: r for r in again["owners"]}[aid]
        self.assertEqual(row, {r["agent_id"]: r for r in fresh["owners"]}[aid])
        self.assertEqual(again["read"]["skipped"], fresh["read"]["skipped"])

    def test_progress_saves_are_bounded_by_time(self):  # PR 245 cold path: not one whole-cache save per N misses
        saves = []
        real = ah._save_owners_cache

        def spy(path, cache, prune=True):
            saves.append(prune)
            return real(path, cache, prune)
        with mock.patch.object(ah, "_save_owners_cache", spy), mock.patch.object(ah, "OWNERS_CACHE_SAVE_EVERY", 20), \
                mock.patch.object(ah, "OWNERS_CACHE_SAVE_GAP_S", 3600.0, create=True):
            ah.owners(self.home, SESSION, now=NOW)
        self.assertEqual(saves, [True], "only the final save inside the gap")

    def test_an_appended_wal_is_picked_up(self):  # NEG-2
        first = {r["agent_id"]: r for r in ah.owners(self.home, SESSION, now=NOW)["owners"]}
        aid = "a" + f"{4:016x}"     # mode 4: handoff
        self.assertEqual(first[aid]["state"], "handoff")
        jl(self.home / ".claude" / "wals" / SESSION / f"agent-{aid}.jsonl",
           [{"at": iso(NOW - 10), "event": "intent", "note": "back at it"}])
        again = {r["agent_id"]: r for r in ah.owners(self.home, SESSION, now=NOW)["owners"]}
        self.assertNotEqual(again[aid]["state"], "handoff")

    def test_a_replaced_wal_of_the_same_size_is_reread(self):  # NEG-3
        aid = "a" + f"{3:016x}"     # mode 3: done
        path = self.home / ".claude" / "wals" / SESSION / f"agent-{aid}.jsonl"
        ah.owners(self.home, SESSION, now=NOW)
        text = path.read_text().replace('"result"', '"status"')   # same length, new content, new inode
        path.unlink()
        path.write_text(text)
        row = {r["agent_id"]: r for r in ah.owners(self.home, SESSION, now=NOW)["owners"]}[aid]
        fresh = self.home_copy("fresh")
        expect = {r["agent_id"]: r for r in ah.owners(fresh, SESSION, now=NOW)["owners"]}[aid]
        self.assertEqual(row, expect)

    def test_corrupt_combined_cache_is_rebuilt(self):  # NEG-1
        good = strip(ah.owners(self.home, SESSION, now=NOW))
        cache = ah._owners_cache_path(ah.state_dir(self.home, "ah-index"), SESSION)
        cache.write_text('{"schema": 1, "wal": {"x": ')
        self.assertEqual(strip(ah.owners(self.home, SESSION, now=NOW)), good)
        cache.write_text(json.dumps({"schema": 1, "wal": {k: {"fp": [0, 0, 0], "s": {"bogus": 1}}
                                                           for k in ("a", "b")}, "meta": []}))
        self.assertEqual(strip(ah.owners(self.home, SESSION, now=NOW)), good)
        cache.write_text("[" * 20000 + "]" * 20000)   # review B-5: RecursionError is not a ValueError
        self.assertEqual(strip(ah.owners(self.home, SESSION, now=NOW)), good)

    def test_a_matching_fingerprint_with_a_wrong_shape_is_rebuilt(self):  # PR 245 m1 receipt F2
        good = strip(ah.owners(self.home, SESSION, now=NOW))
        path = ah._owners_cache_path(ah.state_dir(self.home, "ah-index"), SESSION)
        saved = json.loads(path.read_text())
        wal_key = next(iter(saved["wal"]))
        meta_key = next(iter(saved["meta"]))
        bad_summaries = {"empty": {}, "last_at text": dict(saved["wal"][wal_key]["s"], last_at="soon"),
                         "tickets a string": dict(saved["wal"][wal_key]["s"], tickets="goodqa#1"),
                         "no first": {k: v for k, v in saved["wal"][wal_key]["s"].items() if k != "first"}}
        for name, bad in bad_summaries.items():
            with self.subTest(summary=name):
                data = json.loads(json.dumps(saved))
                data["wal"][wal_key]["s"] = bad   # the fingerprint still matches the unchanged WAL
                path.write_text(json.dumps(data))
                for _ in range(2):   # rebuilt, and not served again on the next call
                    self.assertEqual(strip(ah.owners(self.home, SESSION, now=NOW)), good)
        for name, bad in {"empty": {}, "finished text": dict(saved["meta"][meta_key]["m"], finished="yes"),
                          "no type": {k: v for k, v in saved["meta"][meta_key]["m"].items() if k != "type"}}.items():
            with self.subTest(meta=name):
                data = json.loads(json.dumps(saved))
                data["meta"][meta_key]["m"] = bad
                path.write_text(json.dumps(data))
                self.assertEqual(strip(ah.owners(self.home, SESSION, now=NOW)), good)

    BAD_FIELDS = {   # PR 245 m2 receipt: each passed the m1 check and then raised on use
        "meta offset text": lambda e: e["meta"].__setitem__("offset", "bad"),
        "meta inode text": lambda e: e["meta"].__setitem__("inode", "bad"),
        "meta not a dict": lambda e: e.__setitem__("meta", ["bad"]),
        "lost_trail last text": lambda e: e["lost_trail"].__setitem__("last", "bad"),
        "lost_trail extra text": lambda e: e["lost_trail"].__setitem__("extra", "bad"),
        "lost_trail ordered text": lambda e: e["lost_trail"].__setitem__("ordered", "yes"),
        "schema text": lambda e: e.__setitem__("schema", "bad"),
        "events text": lambda e: e.__setitem__("events", "bad"),
        "skipped_to text": lambda e: e.__setitem__("skipped_to", "bad"),
        # PR 245 m3 receipt: numbers that pass a type check and still raise on use
        "lost_trail last 10**309": lambda e: e["lost_trail"].__setitem__("last", 10 ** 309),
        "lost_trail last inf": lambda e: e["lost_trail"].__setitem__("last", float("inf")),
        "lost_trail next 10**309": lambda e: e["lost_trail"].__setitem__("nexts", [10 ** 309]),
        "last_at 1e309": lambda e: e.__setitem__("last_at", 1e309),
        "last_at 1e300": lambda e: e.__setitem__("last_at", 1e300),
        "last_at 10**309": lambda e: e.__setitem__("last_at", 10 ** 309),
        "outcome_at 1e309": lambda e: (e.__setitem__("outcome", "done"), e.__setitem__("outcome_at", 1e309)),
        "outcome_at nan": lambda e: (e.__setitem__("outcome", "done"), e.__setitem__("outcome_at", float("nan"))),
        "events 10**400": lambda e: e.__setitem__("events", 10 ** 400),
    }

    def corrupt_and_check(self, where):
        """Corrupt one field (in the owners cache, or in every per-WAL index file), then: this call is right, the next
        call is right, and the stored state was replaced (the corruption is not served again)."""
        good = strip(ah.owners(self.home, SESSION, now=NOW))
        index = ah.state_dir(self.home, "ah-index")
        cache_path = ah._owners_cache_path(index, SESSION)
        saved_cache = cache_path.read_text()
        saved_index = {f: f.read_text() for f in index.glob("wal-*.json")}
        for name, damage in self.BAD_FIELDS.items():
            with self.subTest(where=where, field=name):
                cache_path.write_text(saved_cache)
                for f, text in saved_index.items():
                    f.write_text(text)
                if where == "owners cache":
                    data = json.loads(saved_cache)
                    for entry in data["wal"].values():
                        damage(entry["s"])
                    cache_path.write_text(json.dumps(data))
                else:   # the per-WAL index files, with no owners cache (an upgrade, or a lost cache)
                    cache_path.unlink()
                    for f, text in saved_index.items():
                        entry = json.loads(text)
                        damage(entry)
                        f.write_text(json.dumps(entry))
                self.assertEqual(strip(ah.owners(self.home, SESSION, now=NOW)), good, f"{name}: this call")
                self.assertEqual(strip(ah.owners(self.home, SESSION, now=NOW)), good, f"{name}: the next call recovers")
                served = json.loads(cache_path.read_text())["wal"].values()
                self.assertTrue(all(ah._cached_summary_ok(e["s"]) for e in served), f"{name}: the entry was replaced")

    def test_a_cache_entry_with_a_wrong_field_type_is_rebuilt(self):  # PR 245 m2 receipt
        self.corrupt_and_check("owners cache")

    def test_an_index_file_with_a_wrong_field_type_is_rebuilt(self):  # PR 245 m2 receipt (the same rule, older store)
        self.corrupt_and_check("per-WAL index")

    def test_any_failure_using_a_cached_entry_is_a_miss_that_rewrites_it(self):  # PR 245 m2 receipt, defence in depth
        good = strip(ah.owners(self.home, SESSION, now=NOW))
        aid = "a" + f"{4:016x}"
        jl(self.home / ".claude" / "wals" / SESSION / f"agent-{aid}.jsonl",
           [{"at": iso(NOW - 10), "event": "status", "note": "later"}])   # a miss with a prior entry for this WAL
        real = ah._summarize_agent_wal
        calls = []

        def flaky(path, index_dir, prior=None):
            calls.append(prior is None or bool(prior))
            if prior:
                raise TypeError("unexpected state in a cached entry")   # a shape no check foresaw
            return real(path, index_dir, prior)
        with mock.patch.object(ah, "_summarize_agent_wal", flaky):
            again = {r["agent_id"]: r for r in ah.owners(self.home, SESSION, now=NOW)["owners"]}
        fresh = {r["agent_id"]: r for r in ah.owners(self.home_copy("fresh-flaky"), SESSION, now=NOW)["owners"]}
        self.assertEqual(again[aid], fresh[aid], "rebuilt from the start, not a crash")
        self.assertIn(True, calls)
        self.assertNotEqual(strip(ah.owners(self.home, SESSION, now=NOW)), good)   # the append is shown on later calls

    def test_owner_rows_format_an_unrepresentable_time_as_none(self):  # PR 245 m3 receipt: the safe helper
        for bad in (1e309, 1e300, 10 ** 309, float("nan"), -1e20):
            self.assertIsNone(ah._iso_or_none(bad), bad)
        self.assertEqual(ah._iso_or_none(NOW), ah.iso(NOW))

    def test_lost_trail_state_out_of_range_is_none_not_an_exception(self):  # PR 245 m3 receipt, at the source
        LT = ah._prov().LostTrail
        for bad in ({"nexts": [10 ** 309]}, {"nexts": [float("nan")]}, {"nexts": [], "last": 10 ** 309},
                    {"nexts": [], "last": float("inf")}, {"nexts": [], "extra": "2"}, {"nexts": [True]}):
            self.assertIsNone(LT.from_state(bad), bad)
        self.assertIsNotNone(LT.from_state({"nexts": [None, 5.0], "last": 3.0, "extra": 2, "ordered": True}))

    def test_a_deeply_nested_meta_file_is_skipped(self):  # delta review follow-up (discover_agents meta read)
        aid = "a" + f"{5:016x}"
        meta = self.home / ".claude" / "projects" / "-p0" / SESSION / "subagents" / f"agent-{aid}.meta.json"
        meta.write_text("[" * 20000 + "]" * 20000)
        rows = {r["agent_id"]: r for r in ah.owners(self.home, SESSION, now=NOW)["owners"]}
        self.assertIn(aid, rows)

    def test_a_deeply_nested_wal_line_is_skipped(self):  # review B-5 (the same parser, per WAL line)
        good = strip(ah.owners(self.home, SESSION, now=NOW))
        aid = "a" + f"{3:016x}"
        path = self.home / ".claude" / "wals" / SESSION / f"agent-{aid}.jsonl"
        jl(path, ["[" * 20000 + "]" * 20000])
        os.utime(path, (NOW - 200, NOW - 200))
        row = {r["agent_id"]: r for r in ah.owners(self.home, SESSION, now=NOW)["owners"]}[aid]
        want = {r["agent_id"]: r for r in good["owners"]}[aid]
        self.assertEqual(row["state"], want["state"])

    def test_stale_tmp_files_are_cleaned_only_when_old_and_orphaned(self):  # M1
        index = ah.state_dir(self.home, "ah-index")
        index.mkdir(parents=True, exist_ok=True)
        old_dead = index / "wal-x.json.999999.tmp"
        old_alive = index / f"wal-y.json.{os.getpid()}.tmp"
        young_dead = index / "wal-z.json.999998.tmp"
        for p in (old_dead, old_alive, young_dead):
            p.write_text("{}")
        for p in (old_dead, old_alive):
            os.utime(p, (NOW - 7200, NOW - 7200))
        os.utime(young_dead, (NOW - 60, NOW - 60))
        ah.owners(self.home, SESSION, now=NOW)
        self.assertEqual((old_dead.exists(), old_alive.exists(), young_dead.exists()), (False, True, True))

    def test_an_out_of_range_pid_tmp_never_fails_the_read(self):  # review B-1
        good = strip(ah.owners(self.home, SESSION, now=NOW))
        index = ah.state_dir(self.home, "ah-index")
        for name in ("x.json.99999999999.tmp", "y.json.1.99999999999999999999.tmp"):
            p = index / name
            p.write_text("{}")
            os.utime(p, (NOW - 7200, NOW - 7200))
        with mock.patch.object(ah.os, "kill", side_effect=OverflowError("signed integer is greater than maximum")):
            self.assertEqual(strip(ah.owners(self.home, SESSION, now=NOW)), good)

    def test_a_cache_from_another_summary_format_is_ignored(self):  # review B-2
        ah.owners(self.home, SESSION, now=NOW)
        path = ah._owners_cache_path(ah.state_dir(self.home, "ah-index"), SESSION)
        data = json.loads(path.read_text())
        aid = "a" + f"{0:016x}"
        key = next(k for k in data["wal"] if aid in k)
        data["wal"][key]["s"] = dict(data["wal"][key]["s"], outcome="handoff", outcome_at=NOW - 50)  # old-shape lie
        data["format"] = [0, "older"]
        path.write_text(json.dumps(data))
        row = {r["agent_id"]: r for r in ah.owners(self.home, SESSION, now=NOW)["owners"]}[aid]
        self.assertIsNone(row["result_at"])

    def test_two_threads_never_share_a_tmp_name(self):  # review B-4
        import threading
        names = []
        real = os.replace

        def spy(src, dst):
            names.append(os.fspath(src))
            return real(src, dst)
        target = ah.state_dir(self.home, "ah-index") / "probe.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        with mock.patch.object(os, "replace", spy):
            threads = [threading.Thread(target=ah.atomic_json, args=(target, {"n": i})) for i in range(2)]
            for th in threads:
                th.start()
            for th in threads:
                th.join()
        self.assertEqual(len(set(names)), 2, names)

    def test_an_interrupted_cold_run_still_leaves_progress(self):  # NEG-6 (R8)
        calls = {"n": 0}
        real = ah._summarize_agent_wal   # PR 234 merge: the uncached reader sits below the cache and the tally

        def boom(path, index_dir):
            calls["n"] += 1
            if calls["n"] > 120:
                raise KeyboardInterrupt  # stands in for tier_gate's deadline alarm
            return real(path, index_dir)
        with mock.patch.object(ah, "_summarize_agent_wal", boom), mock.patch.object(ah, "OWNERS_CACHE_SAVE_EVERY", 50), \
                mock.patch.object(ah, "OWNERS_CACHE_SAVE_GAP_S", 0.0), \
                self.assertRaises(KeyboardInterrupt):
            ah.owners(self.home, SESSION, now=NOW)
        cache = json.loads(ah._owners_cache_path(ah.state_dir(self.home, "ah-index"), SESSION).read_text())
        self.assertGreaterEqual(len(cache["wal"]), 100)


# origin/main feb19d1a's owners() on build(140, 60): the 98e33c5d rows unchanged, plus PR 234's read block
GOLDEN = REPO / "tests" / "data" / "ah_owners_golden.json"


class Golden(Base):
    """Same rows as the previous implementation for the same input, cold, warm and over an index the old code wrote
    (R5). The frozen rows were produced by origin/main feb19d1a, so this runs on every test run (review B-3);
    AH_OLD_PY additionally runs a live old copy, which also writes the old-format index for the mixed case."""

    def setUp(self):
        super().setUp()
        build(self.home, 140, 60)
        self.want = json.loads(GOLDEN.read_text())

    def test_frozen_rows_cover_every_state(self):
        states = {r["state"] for r in self.want["owners"]}
        self.assertTrue({"live", "DROPPED", "done", "returned", "handoff", "idle-helper", "SILENT-HIGH"} <= states, states)
        self.assertTrue(any(r["restricted"] for r in self.want["owners"]))

    def test_same_output_as_the_previous_implementation(self):
        self.assertEqual(strip(ah.owners(self.home, SESSION, now=NOW)), self.want, "cold")
        self.assertEqual(strip(ah.owners(self.home, SESSION, now=NOW)), self.want, "warm")

    def test_same_output_over_an_index_the_old_code_wrote(self):
        old = load_old()
        if old is None:
            self.skipTest("set AH_OLD_PY to origin/main's harness/hooks/ah.py for the mixed-index case")
        self.assertEqual(strip(old.owners(self.home, SESSION, now=NOW)), self.want, "old code, frozen rows")
        self.assertEqual(strip(ah.owners(self.home, SESSION, now=NOW)), self.want, "new code over the old index")


if __name__ == "__main__":
    unittest.main()
