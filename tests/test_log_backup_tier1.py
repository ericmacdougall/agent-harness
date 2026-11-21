"""Tier 1 of harness/bin/log-backup.sh: the ledger, the incremental send, the reconcile and the last-ok gate (goodqa#15532).

Real rclone to a local directory as the remote, behind a thin wrapper that records every call, charges a cost model
taken from measurements of the Dropbox backend (one request per remote folder walked, one per file looked up, one
per folder of a listing plus the root pages) and injects failures. LOG_BACKUP_TEST_SCRIPT points the same tests at
another copy of the script: run against origin/main 3e256723 the budget tests must fail (failing first).
"""
import json
import os
import subprocess
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_log_backup_script import REAL_RCLONE, SCRIPT, Case  # noqa: E402

T1_SCRIPT = Path(os.environ.get("LOG_BACKUP_TEST_SCRIPT") or SCRIPT)
US = "\x1f"
TIER1 = (".claude/wals", ".claude/projects", ".codex/sessions")

WRAPPER = """#!%(python)s
import json, os, subprocess, sys
argv = sys.argv[1:]
real = os.environ["REAL_RCLONE"]
log = os.environ["FAKE_LOG"]
entry = {"argv": argv}
if "--files-from-raw" in argv:
    entry["from"] = [l for l in open(argv[argv.index("--files-from-raw") + 1]).read().split("\\n") if l]
with open(log, "a") as h:
    h.write(json.dumps(entry) + "\\n")
if argv and argv[0] == "listremotes":
    print(os.environ.get("FAKE_REMOTES", "lessons-dropbox: dropbox"))
    sys.exit(0)
remote_root = os.environ.get("FAKE_REMOTE_ROOT", "")
sep = argv.index("--") if "--" in argv else -1
def charge(cost, code):
    budget = os.environ.get("FAKE_COST_OPS")
    if not budget:
        return
    counter = log + ".cost"
    spent = int(open(counter).read()) if os.path.exists(counter) else 0
    spent += cost
    open(counter, "w").write(str(spent))
    if spent > int(budget):
        if "--log-file" in argv:
            open(argv[argv.index("--log-file") + 1], "a").write("ERROR : budget\\n")
        sys.exit(code)
def dirs_under(path):
    return sum(1 for _ in os.walk(path)) if os.path.isdir(path) else 1
if argv and argv[0] == "copy" and sep >= 0:
    src, dst = argv[sep + 1:]
    if os.environ.get("FAKE_THROTTLE") and "--files-from-raw" in argv:
        with open(argv[argv.index("--log-file") + 1], "a") as h:
            h.write("2026/11/20 10:00:00 ERROR : x: Failed to copy: too_many_write_operations/.\\n")
        sys.exit(10)
    names = entry.get("from", [])
    if os.environ.get("FAKE_FAIL_FILE") and os.environ["FAKE_FAIL_FILE"] in names:
        with open(argv[argv.index("--log-file") + 1], "a") as h:
            h.write("2026/11/20 10:00:00 ERROR : %%s: Failed to copy: permanent failure\\n" %% os.environ["FAKE_FAIL_FILE"])
            h.write("2026/11/20 10:00:00 NOTICE: Failed to copy with 1 errors: last error was: permanent failure\\n")
        sys.exit(1)
    vanish = os.environ.get("FAKE_VANISH")
    if vanish and vanish in names and os.path.exists(os.path.join(src, vanish)):
        os.unlink(os.path.join(src, vanish))
    if os.environ.get("FAKE_COPY_DELAY") and "--files-from-raw" in argv:
        import time
        time.sleep(float(os.environ["FAKE_COPY_DELAY"]))  # a slow upload: time pressure on the run budget
    if "--no-traverse" in argv and "--files-from-raw" in argv:
        charge(len(names), 10)
    elif os.path.isfile(src):
        charge(1, 10)  # one file: one lookup
    else:
        charge(dirs_under(dst) + 1, 10)  # a copy that walks the remote: one request per folder
if os.environ.get("FAKE_HASH_LSF_DELAY") and argv and argv[0] == "lsf" and "--hash" in argv:
    import time
    time.sleep(float(os.environ["FAKE_HASH_LSF_DELAY"]))  # a slow remote listing or slow local hashing
if argv and argv[0] == "lsf" and sep >= 0 and remote_root and argv[-1].startswith(remote_root):
    target = argv[-1]
    if "--include-from" in argv:
        pats = [l for l in open(argv[argv.index("--include-from") + 1]).read().split("\\n") if l]
        cost = 3 + sum(1 for p in pats if os.path.isdir(os.path.join(target, p.strip("/").replace("/**", ""))))
    else:
        cost = dirs_under(target)
    charge(cost, 1)
os.execv(real, [real] + argv)
"""


def calls_of(case):
    return case.recorded()


class TierOne(Case):
    def setUp(self):
        super().setUp()
        if not REAL_RCLONE:
            if os.environ.get("LOG_BACKUP_REQUIRE_RCLONE") == "1":
                self.fail("rclone is required on this host (LOG_BACKUP_REQUIRE_RCLONE=1) but was not found")
            self.skipTest("rclone not installed")
        self.fake.write_text(WRAPPER % {"python": sys.executable})
        self.fake.chmod(0o755)
        self.ledger_dir = self.logs / "log-backup.t1.d"

    # ---- helpers
    def go(self, **extra):
        env = dict(REAL_RCLONE=REAL_RCLONE, FAKE_REMOTE_ROOT=str(self.remote), LOG_BACKUP_REMOTE=str(self.remote),
                   LOG_BACKUP_ALLOW_LOCAL="1", LOG_BACKUP_BULK_EVERY_SECONDS="99999", LOG_BACKUP_RETRIES="0",
                   LOG_BACKUP_BUDGET_FILE=str(self.tmp / "no-budget"), TZ="UTC")
        env.update(extra)
        cost = Path(str(self.calls) + ".cost")
        if cost.exists():
            cost.unlink()
        done = self.run_script(script=T1_SCRIPT, **env)
        return done

    def log_text(self):
        p = self.logs / "log-backup.log"
        text = p.read_text() if p.exists() else ""
        return "\n".join(l for l in text.split("\n") if "Config file" not in l)

    def clear_calls(self):
        if self.calls.exists():
            self.calls.unlink()

    def tier1_copies(self):
        out = []
        for c in self.recorded():
            a = c["argv"]
            if a[0] == "copy" and any(a[-1].endswith(s) for s in TIER1):
                out.append(c)
        return out

    def ledger(self, src=".claude/wals"):
        return self.ledger_dir / src.replace("/", "_") / "ledger"

    def ledger_lines(self, src=".claude/wals"):
        p = self.ledger(src)
        return p.read_text().split("\n")[1:-1] if p.exists() else []

    def sessions(self, n, prefix="s", base=".claude/wals", age=3600):
        for i in range(n):
            rel = f"{base}/{prefix}{i}/main.jsonl"
            self.put(rel, b"line %d\n" % i)
            old = time.time() - age - i
            os.utime(self.home / rel, (old, old))

    def remote_has(self, rel):
        return (self.remote / "testhost" / rel).exists()

    def assert_read_only_verbs(self):
        for c in self.recorded():
            self.assertIn(c["argv"][0], ("copy", "listremotes", "lsf"), c["argv"])
            for flag in c["argv"]:
                self.assertFalse(flag.startswith("--delete"), c["argv"])

    def old_last_ok(self, seconds_ago=200, remote=None):
        self.logs.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - seconds_ago))
        (self.logs / "log-backup.last-ok").write_text(f"{stamp} sources=6 remote={remote or (str(self.remote) + '/testhost')}\n")
        return stamp


class TierOneIncremental(TierOne):
    def test_copies_never_walk_the_remote(self):
        self.sessions(12)
        done = self.go()
        self.assertTrue(self.last_ok().exists(), self.log_text()[:3500] + done.stderr.decode())
        copies = self.tier1_copies()
        self.assertTrue(copies)
        for c in copies:
            self.assertIn("--no-traverse", c["argv"])
            self.assertIn("--files-from-raw", c["argv"])
        self.assertEqual(sum(1 for i in range(12) if self.remote_has(f".claude/wals/s{i}/main.jsonl")), 12)
        self.assert_read_only_verbs()

    def test_an_idle_run_still_writes_last_ok(self):
        self.sessions(5)
        self.go()
        self.last_ok().unlink()
        self.clear_calls()
        self.go()
        self.assertTrue(self.last_ok().exists(), self.log_text()[-1500:])
        self.assertEqual(self.tier1_copies(), [], "nothing changed, so nothing is sent")

    def test_only_changes_are_sent_newest_first(self):
        self.sessions(4)
        self.go()
        self.clear_calls()
        self.put(".claude/wals/s1/main.jsonl", b"line 1 grown\nmore\n")
        for name, age in (("n1", 100), ("n2", 10)):
            rel = f".claude/wals/{name}/main.jsonl"
            self.put(rel, name.encode())
            os.utime(self.home / rel, (time.time() - age, time.time() - age))
        self.go(LOG_BACKUP_BULK_CHUNK="1", LOG_BACKUP_RECON_SECONDS="0")
        sent = [n for c in self.tier1_copies() for n in c.get("from", [])]
        self.assertEqual(sorted(sent), ["n1/main.jsonl", "n2/main.jsonl", "s1/main.jsonl"])
        self.assertLess(sent.index("n2/main.jsonl"), sent.index("n1/main.jsonl"), "newest first")
        self.assertEqual((self.remote / "testhost/.claude/wals/s1/main.jsonl").read_bytes(), b"line 1 grown\nmore\n")
        kept = list((self.remote / "testhost/versions").rglob("s1/main.jsonl"))
        self.assertTrue(kept, "the changed file's old copy stays under versions/")

    def test_thousands_of_folders_finish_inside_the_budget(self):
        # The traversing copy of the old script costs one request per folder; 2500 folders do not fit 1500 requests.
        self.sessions(2500)
        self.go(FAKE_COST_OPS="10000000")
        self.last_ok().unlink()
        done = self.go(FAKE_COST_OPS="1500")
        self.assertTrue(self.last_ok().exists(), self.log_text()[:3500] + done.stderr.decode())

    def test_backlog_drains_over_runs_and_writes_last_ok_once(self):
        self.sessions(30)
        first_ok = None
        for run in range(1, 30):
            self.go(FAKE_COST_OPS="30", LOG_BACKUP_BULK_CHUNK="5", LOG_BACKUP_RECON_SECONDS="0")
            if self.last_ok().exists():
                first_ok = run
                break
        self.assertIsNotNone(first_ok, self.log_text()[-1500:])
        self.assertGreater(first_ok, 1, "a backlog bigger than one run's budget must not write last-ok in the first run")
        self.assertEqual(sum(1 for i in range(30) if self.remote_has(f".claude/wals/s{i}/main.jsonl")), 30)

    def test_a_file_changed_or_vanished_during_its_chunk_is_not_recorded(self):
        self.sessions(4)
        self.go(FAKE_VANISH="s3/main.jsonl")
        self.assertFalse(self.last_ok().exists(), "a path rclone skipped without error must not count as sent")
        self.assertFalse(any(US + ".claude" in l for l in []))
        self.assertFalse(self.remote_has(".claude/wals/s3/main.jsonl"))
        self.assertFalse(any("s3/main.jsonl" in l for l in self.ledger_lines()))
        self.go()
        self.assertTrue(self.remote_has(".claude/wals/s3/main.jsonl"))
        self.assertTrue(self.last_ok().exists(), self.log_text()[-1500:])

    def test_deleted_and_renamed_session_folders_leave_the_remote_alone(self):
        self.sessions(6)
        self.go()
        (self.home / ".claude/wals/s2/main.jsonl").unlink()
        os.rename(self.home / ".claude/wals/s5", self.home / ".claude/wals/s5b")
        self.clear_calls()
        self.go()
        self.assertTrue(self.remote_has(".claude/wals/s2/main.jsonl"), "a local deletion never reaches the remote")
        self.assertTrue(self.remote_has(".claude/wals/s5/main.jsonl"))
        self.assertTrue(self.remote_has(".claude/wals/s5b/main.jsonl"))
        self.assert_read_only_verbs()

    def test_time_zone_change_does_not_resend_the_tree(self):
        self.sessions(6)
        self.go(TZ="UTC")
        self.last_ok().unlink()
        self.clear_calls()
        self.go(TZ="Asia/Tokyo")
        self.assertEqual(self.tier1_copies(), [])
        self.assertTrue(self.last_ok().exists())

    def test_refused_names_are_counted_and_control_character_names_are_sent(self):
        self.sessions(3)
        self.put(".claude/wals/s1/.DS_Store", b"x")
        done = self.go()
        self.assertTrue(self.last_ok().exists(), self.log_text()[:3500] + done.stderr.decode())
        self.assertFalse(self.remote_has(".claude/wals/s1/.DS_Store"))
        self.last_ok().unlink()
        # rclone escapes control characters in listed names and maps them back on copy, so this name is sent like any other
        self.put(".claude/wals/s1/we\nird.jsonl", b"odd name")
        self.go()
        self.assertTrue(self.last_ok().exists(), self.log_text()[:2500])
        sent = [p.name for p in (self.remote / "testhost/.claude/wals/s1").iterdir()]
        self.assertTrue(any(n.endswith("ird.jsonl") for n in sent), sent)

    def test_case_collisions_block_last_ok(self):
        self.sessions(2)
        a, b = self.home / ".claude/wals/s0/Same.jsonl", self.home / ".claude/wals/s0/same.jsonl"
        a.write_bytes(b"1")
        b.write_bytes(b"2")
        if len(list(a.parent.glob("*ame.jsonl"))) < 2:
            self.skipTest("case-insensitive file system")
        self.go()
        self.assertFalse(self.last_ok().exists())
        self.assertIn("collide", self.log_text())

    def test_names_with_control_characters_arrive_under_their_own_names(self):
        # rclone escapes control characters in what it lists and maps them back on copy: a newline, a tab, the unit
        # separator used by this script's lists, and a literal backslash sequence must all be sent and keep their bytes.
        self.sessions(2)
        names = ["a\nb.jsonl", "c\td.jsonl", "e\x1ff.jsonl", "g\\nh.jsonl"]
        for i, name in enumerate(names):
            self.put(f".claude/wals/s0/{name}", b"content %d" % i)
        done = self.go()
        self.assertTrue(self.last_ok().exists(), self.log_text()[:2500] + done.stderr.decode())
        remote = {p.name: p.read_bytes() for p in (self.remote / "testhost/.claude/wals/s0").iterdir()}
        for i, name in enumerate(names):
            self.assertEqual(remote.get(name), b"content %d" % i, (name, sorted(remote)))

    def test_a_permanent_failure_sticks_one_file_and_not_the_rest(self):
        self.sessions(5)
        self.go(FAKE_FAIL_FILE="s2/main.jsonl")
        self.assertFalse(self.last_ok().exists())
        self.assertIn("stuck, could not send: s2/main.jsonl", self.log_text())
        for i in (0, 1, 3, 4):
            self.assertTrue(self.remote_has(f".claude/wals/s{i}/main.jsonl"), i)
        self.assertFalse(self.remote_has(".claude/wals/s2/main.jsonl"))
        self.go()
        self.assertTrue(self.remote_has(".claude/wals/s2/main.jsonl"), "the next run sends it once the fault is gone")
        self.assertTrue(self.last_ok().exists())

    def test_a_write_rate_limit_stops_the_run_and_records_nothing(self):
        self.sessions(3)
        self.go()
        self.last_ok().unlink()
        self.clear_calls()
        self.put(".claude/wals/s0/main.jsonl", b"changed after the first backup\n")
        self.go(FAKE_THROTTLE="1")
        self.assertFalse(self.last_ok().exists())
        self.assertTrue((self.logs / "log-backup.throttled").exists())
        remote_lists = [c for c in self.recorded() if c["argv"][0] == "lsf" and c["argv"][-1].startswith(str(self.remote))]
        self.assertEqual(remote_lists, [], "no reconcile starts after a throttle")
        self.assertFalse(any(l.split(US)[1] == "s0/main.jsonl" and "grown" in l for l in self.ledger_lines()))
        self.go()
        self.assertEqual((self.remote / "testhost/.claude/wals/s0/main.jsonl").read_bytes(), b"changed after the first backup\n")
        self.assertTrue(self.last_ok().exists())


class TierOneBootstrap(TierOne):
    def old_tree(self, n=6):
        self.sessions(n, prefix="o", age=3 * 86400)  # three days old: older than the old last-ok less the margin
        self.sessions(1, prefix="fresh", age=300)

    def test_seed_skips_old_files_and_withholds_last_ok_until_reconciled(self):
        self.old_tree()
        stamp = self.old_last_ok()
        done = self.go(LOG_BACKUP_RECON_SECONDS="0")
        self.assertFalse(self.remote_has(".claude/wals/o0/main.jsonl"), "seeded files are not sent")
        self.assertTrue(self.remote_has(".claude/wals/fresh0/main.jsonl"), "newer files are sent first")
        self.assertEqual((self.logs / "log-backup.last-ok").read_text().split()[0], stamp, "last-ok is withheld (still the old one)")
        self.assertTrue(any(l.startswith("S" + US) for l in self.ledger_lines()))
        done = self.go()
        self.assertTrue(self.remote_has(".claude/wals/o0/main.jsonl"), "the reconcile found the seeded files missing and sent them")
        self.assertNotEqual((self.logs / "log-backup.last-ok").read_text().split()[0], stamp, self.log_text()[-1800:] + done.stderr.decode())
        self.assertFalse(any(l.startswith("S" + US) for l in self.ledger_lines()))
        self.assert_read_only_verbs()

    def test_cold_start_returns_last_ok_within_the_modelled_runs(self):
        self.old_tree(8)
        stamp = self.old_last_ok()
        # 8 old folders seeded, 2 folders per chunk, one chunk per run: the reconcile takes several runs.
        runs = 0
        for runs in range(1, 40):
            self.go(LOG_BACKUP_RECON_CHUNK_DIRS="2", LOG_BACKUP_RECON_MAX_CHUNKS="1", FAKE_COST_OPS="100000")
            if (self.logs / "log-backup.last-ok").read_text().split()[0] != stamp:
                break
        self.assertGreater(runs, 3, "a reconcile of several chunks cannot finish in one run")
        self.assertLess(runs, 39, self.log_text()[-1500:])
        self.assertEqual(sum(1 for i in range(8) if self.remote_has(f".claude/wals/o{i}/main.jsonl")), 8)

    def test_changing_files_do_not_starve_the_reconcile(self):
        # Uploads are slow (1 s a chunk of one file) against a 40 s run, and 15 more files change before each of the first three
        # runs. The reconcile still gets its reserved slice each run, so the seeded files are proven and last-ok returns
        # once the changes stop.
        self.old_tree(6)
        stamp = self.old_last_ok()
        env = dict(FAKE_COPY_DELAY="1", LOG_BACKUP_BULK_CHUNK="1", LOG_BACKUP_BUDGET_SECONDS="40", LOG_BACKUP_RECON_SECONDS="16",
                   LOG_BACKUP_RECON_CHUNK_DIRS="10", LOG_BACKUP_DEADLINE_GRACE_SECONDS="1", LOG_BACKUP_KILL_GRACE_SECONDS="1",
                   LOG_BACKUP_SLICE_RESERVE_SECONDS="1", LOG_BACKUP_PERIOD_SECONDS="900")
        s_counts, cursors = [], []
        for run in range(1, 11):
            if run <= 3:
                for i in range(15):
                    rel = f".claude/wals/new{run}_{i}/main.jsonl"
                    self.put(rel, b"new %d %d" % (run, i))
                    os.utime(self.home / rel, (time.time() - 5, time.time() - 5))
            self.go(**env)
            s_counts.append(sum(1 for l in self.ledger_lines() if l.startswith("S" + US)))
            cursor = self.ledger_dir / ".claude_wals" / "recon" / "cursor"
            cursors.append(int(cursor.read_text()) if cursor.exists() else 10 ** 6)  # no checkpoint left: it finished
            if (self.logs / "log-backup.last-ok").read_text().split()[0] != stamp:
                break
        self.assertEqual(s_counts[-1], 0, s_counts)
        # files changed before runs 1 to 3: without the reserved slice the uploads use every run and the reconcile waits
        self.assertEqual(cursors[min(2, len(cursors) - 1)], 10 ** 6, ("the reconcile finished while files were still changing", cursors))
        self.assertTrue(self.remote_has(".claude/wals/o0/main.jsonl"))

    def test_kill_points_around_the_seed_never_write_last_ok(self):
        self.old_tree(3)
        self.old_last_ok()
        self.go(LOG_BACKUP_RECON_SECONDS="0")
        marker = self.logs / "log-backup.last-ok"
        before = marker.read_text()
        # A ledger with S lines and no other marker (the crash window the review named) still holds last-ok back.
        self.assertTrue(any(l.startswith("S" + US) for l in self.ledger_lines()))
        self.go(LOG_BACKUP_RECON_SECONDS="0")
        self.assertEqual(marker.read_text(), before)

    def test_a_ledger_for_another_destination_is_not_trusted(self):
        self.sessions(4)
        self.go()
        text = self.ledger(".claude/wals").read_text().split("\n")
        text[0] = "#log-backup-t1 1 /somewhere/else/host"
        self.ledger(".claude/wals").write_text("\n".join(text))
        shutil_calls = self.clear_calls()
        self.last_ok().unlink()
        for i in range(4):
            target = self.remote / f"testhost/.claude/wals/s{i}/main.jsonl"
            target.unlink()
        self.go()
        for i in range(4):
            self.assertTrue(self.remote_has(f".claude/wals/s{i}/main.jsonl"), "everything is sent again, nothing is trusted")
        self.assertIn("another destination", self.log_text())

    def test_an_old_last_ok_for_another_remote_or_the_future_seeds_nothing(self):
        self.old_tree(3)
        self.old_last_ok(remote="some-other-remote")
        self.go(LOG_BACKUP_RECON_SECONDS="0")
        self.assertTrue(self.remote_has(".claude/wals/o0/main.jsonl"), "no seed: every file is sent")
        shutil_left = [l for l in self.ledger_lines() if l.startswith("S" + US)]
        self.assertEqual(shutil_left, [])


class TierOneReconcile(TierOne):
    def test_missing_and_short_remote_files_are_found_and_resent(self):
        self.sessions(6)
        self.go()
        (self.remote / "testhost/.claude/wals/s1/main.jsonl").unlink()
        (self.remote / "testhost/.claude/wals/s2/main.jsonl").write_bytes(b"x")
        self.last_ok().unlink()
        done = self.go(LOG_BACKUP_AUDIT_EVERY_SECONDS="0")
        self.assertEqual((self.remote / "testhost/.claude/wals/s1/main.jsonl").read_bytes(), b"line 1\n")
        self.assertEqual((self.remote / "testhost/.claude/wals/s2/main.jsonl").read_bytes(), b"line 2\n")
        self.assertTrue(self.last_ok().exists(), self.log_text()[-1800:] + done.stderr.decode())
        self.assert_read_only_verbs()

    def test_reconcile_resumes_after_a_cut_short_run(self):
        self.sessions(9)
        self.go()
        (self.remote / "testhost/.claude/wals/s8/main.jsonl").unlink()
        self.go(LOG_BACKUP_AUDIT_EVERY_SECONDS="0", LOG_BACKUP_RECON_CHUNK_DIRS="2", LOG_BACKUP_RECON_MAX_CHUNKS="1")
        state = self.ledger_dir / ".claude_wals" / "recon"
        self.assertTrue(state.exists(), "a cut-short reconcile keeps its cursor")
        self.assertGreater(int((state / "cursor").read_text()), 0)
        for _ in range(12):
            self.go(LOG_BACKUP_AUDIT_EVERY_SECONDS="86400", LOG_BACKUP_RECON_CHUNK_DIRS="2", LOG_BACKUP_RECON_MAX_CHUNKS="1")
            if not state.exists():
                break
        self.assertFalse(state.exists())
        self.assertTrue(self.remote_has(".claude/wals/s8/main.jsonl"))

    def test_reconcile_request_count_is_folders_plus_pages(self):
        self.sessions(20)
        self.go()
        self.last_ok().unlink()
        self.go(LOG_BACKUP_AUDIT_EVERY_SECONDS="0", LOG_BACKUP_RECON_CHUNK_DIRS="5", FAKE_COST_OPS="100000")
        spent = int(Path(str(self.calls) + ".cost").read_text())
        folders = len({p.parent for src in TIER1 for p in (self.home / src).rglob("*") if p.is_file()})
        self.assertLessEqual(spent, folders + 3 * (folders // 5 + 3) + 3, (spent, folders))
        self.assertTrue(self.last_ok().exists(), self.log_text()[-1500:])

    def test_kill_between_ledger_and_cursor_loses_nothing(self):
        # Simulated crash after the ledger was written and before the cursor moved: the chunk is checked again.
        self.sessions(6)
        self.go()
        (self.remote / "testhost/.claude/wals/s0/main.jsonl").unlink()
        self.go(LOG_BACKUP_AUDIT_EVERY_SECONDS="0", LOG_BACKUP_RECON_CHUNK_DIRS="2", LOG_BACKUP_RECON_MAX_CHUNKS="1")
        state = self.ledger_dir / ".claude_wals" / "recon"
        (state / "cursor").write_text("0\n")
        for _ in range(10):
            self.go(LOG_BACKUP_AUDIT_EVERY_SECONDS="86400", LOG_BACKUP_RECON_CHUNK_DIRS="2", LOG_BACKUP_RECON_MAX_CHUNKS="1")
        self.assertTrue(self.remote_has(".claude/wals/s0/main.jsonl"))
        self.assertTrue(self.last_ok().exists(), self.log_text()[-1500:])

    def test_a_slow_remote_listing_leaves_no_time_for_hashing_and_the_cursor_stays(self):
        # The slice is 10 s and the remote listing takes 6 s: the local hashing must not get a second full slice (code review F2).
        self.sessions(4)
        self.go()
        self.go(LOG_BACKUP_AUDIT_EVERY_SECONDS="0", LOG_BACKUP_RECON_SECONDS="10", FAKE_HASH_LSF_DELAY="6")
        state = self.ledger_dir / ".claude_wals" / "recon"
        self.assertTrue(state.exists(), self.log_text()[-1500:])
        self.assertEqual((state / "cursor").read_text().strip(), "0")
        self.assertIn("the slice ended during the remote listing", self.log_text())

    def test_a_failing_listing_does_not_advance_the_cursor(self):
        self.sessions(6)
        self.go()
        self.go(LOG_BACKUP_AUDIT_EVERY_SECONDS="0", LOG_BACKUP_RECON_CHUNK_DIRS="2", LOG_BACKUP_RECON_MAX_CHUNKS="1")
        state = self.ledger_dir / ".claude_wals" / "recon"
        cursor = (state / "cursor").read_text()
        self.go(LOG_BACKUP_AUDIT_EVERY_SECONDS="86400", LOG_BACKUP_RECON_CHUNK_DIRS="2", LOG_BACKUP_RECON_MAX_CHUNKS="1",
                FAKE_COST_OPS="1")
        self.assertEqual((state / "cursor").read_text(), cursor)
        self.assertIn("reconcile listing failed", self.log_text())


class TierOneContent(TierOne):
    def test_same_size_different_bytes_is_found(self):
        # A size match is not proof: one remote file holds other bytes of the same length.
        self.sessions(4, prefix="o", age=3 * 86400)
        self.go()
        self.last_ok().unlink()
        target = self.remote / "testhost/.claude/wals/o1/main.jsonl"
        good = target.read_bytes()
        target.write_bytes(b"X" * len(good))
        self.go(LOG_BACKUP_AUDIT_EVERY_SECONDS="0")
        self.assertEqual(target.read_bytes(), good)
        self.assertTrue(self.last_ok().exists(), self.log_text()[-1500:])


class TierOneFence(TierOne):
    def test_an_orphan_uploader_blocks_the_next_run(self):
        self.sessions(3)
        # A process whose command is an executable named rclone and whose arguments name the destination, with a parent
        # that is no log-backup run (this test process): an orphaned uploader as ps shows it.
        bindir = self.tmp / "orphan-bin"
        bindir.mkdir()
        fake = bindir / "rclone"
        fake.symlink_to("/bin/bash")
        dst = f"{self.remote}/testhost/.claude/wals"
        orphan = subprocess.Popen([str(fake), "-c", "sleep 40; true", "copy", "--", str(self.home), dst], start_new_session=True)
        try:
            time.sleep(0.5)
            self.go()
            self.assertFalse(self.last_ok().exists())
            self.assertIn("outlived the run that started it", self.log_text())
            self.assertEqual(self.tier1_copies(), [], "nothing is uploaded beside the orphan")
        finally:
            orphan.terminate()
            orphan.wait()
        self.go()
        self.assertTrue(self.last_ok().exists(), self.log_text()[:2500])


class TierOneOwnership(TierOne):
    def test_a_hashless_remote_fails_closed(self):
        self.sessions(3)
        done = self.run_script(script=T1_SCRIPT, REAL_RCLONE=REAL_RCLONE, LOG_BACKUP_REMOTE="vault:Backups/agent-logs",
                               FAKE_REMOTES="vault: crypt", LOG_BACKUP_RETRIES="0", LOG_BACKUP_BULK_EVERY_SECONDS="99999",
                               LOG_BACKUP_BUDGET_FILE=str(self.tmp / "no-budget"))
        self.assertFalse(self.last_ok().exists())
        self.assertIn("returns no content hash", self.log_text())
        self.assertEqual(self.tier1_copies(), [])

    def test_a_live_lock_holder_is_never_taken_over(self):
        self.sessions(3)
        holder_script = self.tmp / "holder" / "log-backup.sh"
        holder_script.parent.mkdir()
        holder_script.write_text("#!/bin/sh\nsleep 40\n")
        holder = subprocess.Popen(["/bin/sh", str(holder_script)], start_new_session=True)
        try:
            lock = self.logs / "log-backup.lock.d"
            lock.mkdir(parents=True)
            (lock / "pid").write_text(f"{holder.pid}\n")
            old = time.time() - 3 * 86400
            os.utime(lock, (old, old))  # past the stale limit, but its holder lives
            self.go()
            self.assertFalse(self.last_ok().exists())
            self.assertEqual(self.tier1_copies(), [])
            self.assertIn("another backup run holds the lock", self.log_text())
        finally:
            holder.terminate()
            holder.wait()

    def test_unicode_equivalent_names_block_last_ok(self):
        self.sessions(2)
        a = self.home / ".claude/wals/s0/café.jsonl"
        b = self.home / ".claude/wals/s0/café.jsonl"
        a.write_bytes(b"1")
        b.write_bytes(b"2")
        if len([p for p in a.parent.iterdir() if p.name.startswith("caf")]) < 2:
            self.skipTest("this file system folds the two spellings into one file")
        self.go()
        self.assertFalse(self.last_ok().exists())
        self.assertIn("collide", self.log_text())


if __name__ == "__main__":
    unittest.main()
