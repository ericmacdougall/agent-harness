"""Tests for harness/hooks/loss_inventory.py (goodqa#14565, PL-03).

LOSS_INVENTORY_SCRIPT may point at a mutated copy of the script; the suite must then fail.
"""
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REAL = Path(__file__).resolve().parents[1] / "harness" / "hooks" / "loss_inventory.py"
SCRIPT = Path(os.environ.get("LOSS_INVENTORY_SCRIPT", REAL))
GIT_ENV = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}


def git(cwd, *argv):
    env = dict(os.environ, **GIT_ENV)
    return subprocess.run(["git", "-C", str(cwd)] + list(argv), check=True, env=env,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.decode()


def commit(repo, name):
    (Path(repo) / name).write_text(name)
    git(repo, "add", name)
    git(repo, "commit", "-qm", name)


class Fixture(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.home = Path(tmp.name).resolve()
        self.env = dict(os.environ, HOME=str(self.home))
        self.env.pop("GIT_DIR", None)
        # (a) repo with a branch commit not on its fake bare remote
        rtmp = tempfile.TemporaryDirectory()  # the fake remote lives off-host, outside the scanned HOME
        self.addCleanup(rtmp.cleanup)
        self.bare = Path(rtmp.name).resolve() / "remote.git"
        subprocess.run(["git", "init", "-q", "--bare", str(self.bare)], check=True)
        self.work = self.home / "code" / "withremote"
        self.work.mkdir(parents=True)
        git(self.work, "init", "-q", "-b", "main")
        commit(self.work, "c1")
        git(self.work, "remote", "add", "origin", str(self.bare))
        git(self.work, "push", "-q", "origin", "main")  # creates refs/remotes/origin/main
        git(self.work, "checkout", "-q", "-b", "work")
        commit(self.work, "c2")  # one commit on no remote
        # (b) repo with no remote
        self.noremote = self.home / "code" / "noremote"
        self.noremote.mkdir()
        git(self.noremote, "init", "-q", "-b", "main")
        commit(self.noremote, "n1")
        # (c) systemd user units
        ud = self.home / ".config" / "systemd" / "user"
        ud.mkdir(parents=True)
        (ud / "a.service").write_text("[Service]\nExecStart=/bin/true\n")
        (ud / "a.timer").write_text("[Timer]\nOnCalendar=daily\n")
        # (d) 1 MB sqlite outside git (+ one inside a repo and a tiny one, which must not count)
        self.db = self.home / "data" / "state.sqlite"
        self.db.parent.mkdir()
        con = sqlite3.connect(str(self.db))
        con.execute("create table t(b blob)")
        con.execute("insert into t values (?)", (b"x" * 1100000,))
        con.commit()
        con.close()
        shutil.copy(str(self.db), str(self.work / "inrepo.sqlite"))
        git(self.work, "add", "inrepo.sqlite")  # tracked db lives in git: must not count
        git(self.work, "commit", "-qm", "db")
        sqlite3.connect(str(self.home / "data" / "tiny.sqlite")).close()
        self.assertGreaterEqual(self.db.stat().st_size, 1000000)

    def run_cli(self, *argv, expect=None):
        p = subprocess.run([sys.executable, str(SCRIPT)] + list(argv), env=self.env,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
        if expect is not None:
            self.assertEqual(p.returncode, expect, p.stdout.decode() + p.stderr.decode())
        return p

    def scan(self, *extra):
        p = self.run_cli("scan", "--root", str(self.home), "--json", *extra, expect=0)
        return json.loads(p.stdout)

    def counts(self, **kw):
        return self.scan()["classes"]


class ScanTests(Fixture):
    def test_counts_and_row_shape(self):
        r = self.scan()
        self.assertEqual(r["classes"], {"unpushed_branch": 1, "no_remote_repo": 1, "systemd_user_unit": 1,
                                        "timer": 1, "state_db_outside_git": 1}, r)
        self.assertEqual(len(r["rows"]), 5)
        self.assertFalse(r["partial"])
        self.assertTrue(r["host"] and r["scanned_at"])
        for row in r["rows"]:
            self.assertEqual(set(row), {"class", "path", "age_days", "bytes", "decision", "fp", "decision_stale"})
            self.assertIsNone(row["decision"])
        by = {x["class"]: x for x in r["rows"]}
        self.assertEqual(by["unpushed_branch"]["path"], "%s::work" % self.work)
        self.assertEqual(by["no_remote_repo"]["path"], str(self.noremote))
        self.assertEqual(by["state_db_outside_git"]["path"], str(self.db))
        self.assertGreaterEqual(by["state_db_outside_git"]["bytes"], 1000000)

    def test_control_remote_ref_changes_unpushed_count(self):
        self.assertEqual(self.counts()["unpushed_branch"], 1)
        # push work: the remote-tracking ref now contains it -> 0
        git(self.work, "push", "-q", "origin", "work")
        self.assertEqual(self.counts()["unpushed_branch"], 0)
        # drop the remote-tracking refs: nothing is known to be on a remote -> main and work both unpushed
        git(self.work, "update-ref", "-d", "refs/remotes/origin/main")
        git(self.work, "update-ref", "-d", "refs/remotes/origin/work")
        self.assertEqual(self.counts()["unpushed_branch"], 2)

    def test_scan_never_fetches(self):
        # the real remote gets a new commit; the local view must not change (documented staleness)
        other = self.home / "other"
        subprocess.run(["git", "clone", "-q", str(self.bare), str(other)], check=True)
        commit(other, "x")
        git(other, "push", "-q", "origin", "HEAD:main")
        before = git(self.work, "for-each-ref", "refs/remotes")
        self.scan()
        self.assertEqual(git(self.work, "for-each-ref", "refs/remotes"), before)

    def test_detached_head_and_broken_repo_do_not_crash(self):
        git(self.work, "checkout", "-q", "--detach")
        commit(self.work, "d1")  # detached commit on no ref
        broken = self.home / "code" / "broken"
        (broken / ".git").mkdir(parents=True)
        (broken / ".git" / "HEAD").write_text("garbage")
        r = self.scan()
        self.assertEqual(r["classes"]["unpushed_branch"], 2, r)  # work + detached
        self.assertTrue(any("(detached HEAD)" in x["path"] for x in r["rows"]))
        self.assertTrue(any(e["path"] == str(broken) for e in r["errors"]), r["errors"])

    def test_skips_node_modules_and_never_follows_symlinks(self):
        nm = self.home / "code" / "node_modules" / "pkg"
        nm.mkdir(parents=True)
        shutil.copy(str(self.db), str(nm / "hidden.sqlite"))
        outside = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, str(outside))
        shutil.copy(str(self.db), str(outside / "ext.sqlite"))
        os.symlink(str(outside), str(self.home / "link"))
        os.symlink(str(self.db), str(self.home / "linked.sqlite"))
        r = self.scan()
        self.assertEqual(r["classes"]["state_db_outside_git"], 1, r["rows"])

    def test_unreadable_dir_is_recorded(self):
        if os.geteuid() == 0:
            self.skipTest("root ignores permissions")
        d = self.home / "locked"
        d.mkdir()
        d.chmod(0)
        self.addCleanup(d.chmod, 0o700)
        r = self.scan()
        self.assertTrue(any(e["path"] == str(d) for e in r["errors"]), r["errors"])
        self.assertEqual(r["classes"]["no_remote_repo"], 1)
        # a scan with errors cannot prove nothing is left, even with every row decided
        for row in r["rows"]:
            self.run_cli("decide", "--row", row["path"], "--decision", "moved", "--ticket", "t#1", expect=0)
        p = self.run_cli("report", expect=1)
        self.assertIn(str(d), p.stdout.decode())

    def test_max_seconds_reports_partial(self):
        r = self.scan("--max-seconds", "0.000001")
        self.assertTrue(r["partial"])
        self.assertIn("budget", r["partial_reason"])

    def test_no_file_contents_in_output(self):
        secret = "SECRET-TOKEN-12345"
        (self.home / "code" / "noremote" / "creds.txt").write_text(secret)
        p = self.run_cli("scan", "--root", str(self.home), "--json", expect=0)
        self.assertNotIn(secret, p.stdout.decode() + p.stderr.decode())


class CoverageTests(Fixture):
    def test_untracked_db_inside_repo_counts_tracked_does_not(self):
        shutil.copy(str(self.db), str(self.noremote / "prod.db"))  # sqlite magic, untracked
        r = self.scan()
        paths = [x["path"] for x in r["rows"] if x["class"] == "state_db_outside_git"]
        self.assertIn(str(self.noremote / "prod.db"), paths)
        self.assertNotIn(str(self.work / "inrepo.sqlite"), paths)
        self.assertEqual(len(paths), 2)

    def test_bare_repo_and_its_worktree_counted_once(self):
        bare = self.home / "bare" / "b.git"
        subprocess.run(["git", "clone", "-q", "--bare", str(self.bare), str(bare)], check=True)
        git(bare, "remote", "add", "o2", str(self.bare))
        git(bare, "fetch", "-q", "o2")  # remote-tracking refs so main counts as pushed
        wt = self.home / "wt"
        git(bare, "worktree", "add", "-q", "-b", "feat", str(wt))
        commit(wt, "w1")
        r = self.scan()
        rows = [x["path"] for x in r["rows"] if x["class"] == "unpushed_branch"]
        self.assertEqual(sum(1 for x in rows if x.endswith("::feat")), 1, rows)
        self.assertEqual(len(rows), 2, rows)  # work + feat

    def test_lone_bare_repo_without_remote_is_reported(self):
        bare = self.home / "bare2.git"
        subprocess.run(["git", "init", "-q", "--bare", str(bare)], check=True)
        r = self.scan()
        self.assertEqual(r["classes"]["no_remote_repo"], 2)

    def test_overlapping_roots_do_not_double_count(self):
        p = self.run_cli("scan", "--root", str(self.home), "--root", str(self.home / "data"), "--json", expect=0)
        self.assertEqual(json.loads(p.stdout)["classes"]["state_db_outside_git"], 1)


class DecideReportTests(Fixture):
    def test_decision_goes_stale_when_branch_moves(self):
        self.scan()
        path = "%s::work" % self.work
        self.run_cli("decide", "--row", path, "--decision", "moved", "--ticket", "t#1", expect=0)
        und = [x["path"] for x in json.loads(self.run_cli("report", "--json", expect=1).stdout)["undecided"]]
        self.assertNotIn(path, und)
        commit(self.work, "later")  # new unpushed work on the same branch
        self.scan()
        und = [x["path"] for x in json.loads(self.run_cli("report", "--json", expect=1).stdout)["undecided"]]
        self.assertIn(path, und)

    def test_undecodable_decision_store_does_not_crash(self):
        self.scan()
        sd = self.home / ".agent-harness/state/loss-inventory"
        (sd / "decisions.jsonl").write_bytes(b"\xff\xfe\n")
        self.scan()
        self.run_cli("report", expect=1)

    def test_malformed_last_scan_is_rejected_not_crash(self):
        self.scan()
        (self.home / ".agent-harness/state/loss-inventory/last-scan.json").write_text("[]")
        self.assertEqual(self.run_cli("report").returncode, 2)

    def test_report_exit_codes_and_decide(self):
        self.assertEqual(self.run_cli("report").returncode, 2)  # no saved scan yet
        self.scan()
        rep = self.run_cli("report", "--json", expect=1)
        und = json.loads(rep.stdout)["undecided"]
        self.assertEqual(len(und), 5)
        for row in und[:-1]:
            self.run_cli("decide", "--row", row["path"], "--decision", "accepted-loss", "--ticket", "goodqa#1", expect=0)
            self.assertEqual(self.run_cli("report").returncode, 1)
        self.run_cli("decide", "--row", und[-1]["path"], "--decision", "moved", "--ticket", "goodqa#2", expect=0)
        self.run_cli("report", expect=0)
        # a rescan merges recorded decisions
        r = self.scan()
        self.assertTrue(all(x["decision"] for x in r["rows"]))
        lines = (self.home / ".agent-harness/state/loss-inventory/decisions.jsonl").read_text().splitlines()
        self.assertEqual(len(lines), 5)
        e = json.loads(lines[0])
        self.assertEqual(set(e), {"ts", "path", "class", "decision", "ticket", "by", "fp"})

    def test_decide_validation(self):
        self.scan()
        path = str(self.noremote)
        bad = [("--decision", "ignore", "--ticket", "t#1"), ("--decision", "moved", "--ticket", ""),
               ("--decision", "moved", "--ticket", "has space")]
        for b in bad:
            self.assertNotEqual(self.run_cli("decide", "--row", path, *b).returncode, 0, b)
        self.assertNotEqual(self.run_cli("decide", "--row", "/nope", "--decision", "moved", "--ticket", "t#1").returncode, 0)
        self.assertNotEqual(self.run_cli("decide", "--row", path, "--decision", "moved").returncode, 0)
        self.assertFalse((self.home / ".agent-harness/state/loss-inventory/decisions.jsonl").exists())
        self.run_cli("report", expect=1)

    def test_partial_scan_blocks_clean_report(self):
        self.scan("--max-seconds", "0.000001")
        p = self.run_cli("report", expect=1)  # zero rows but partial -> not clean
        self.assertIn("PARTIAL", p.stdout.decode())

    def test_malformed_decision_lines_ignored(self):
        self.scan()
        sd = self.home / ".agent-harness/state/loss-inventory"
        (sd / "decisions.jsonl").write_text("not json\n{\"path\": 5}\n")
        r = self.run_cli("report", "--json", expect=1)
        self.assertEqual(len(json.loads(r.stdout)["undecided"]), 5)


class MutantTest(unittest.TestCase):
    """The suite must notice if the for-each-ref --contains step is disabled."""

    def test_mutant_is_detected(self):
        src = REAL.read_text()
        needle = 'if not self.contained_in(repo, sha, "refs/remotes"):'
        self.assertEqual(src.count(needle), 1)
        with tempfile.TemporaryDirectory() as d:
            m = Path(d) / "loss_inventory.py"
            m.write_text(src.replace(needle, "if False:"))
            env = dict(os.environ, LOSS_INVENTORY_SCRIPT=str(m))
            p = subprocess.run([sys.executable, "-m", "unittest", "tests.test_loss_inventory.ScanTests.test_counts_and_row_shape"],
                               cwd=str(REAL.parents[2]), env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            self.assertNotEqual(p.returncode, 0, "mutant survived: " + p.stdout.decode())
            self.assertIn("unpushed_branch", p.stdout.decode())


if __name__ == "__main__":
    unittest.main()
