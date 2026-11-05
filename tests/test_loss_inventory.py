"""Tests for harness/hooks/loss_inventory.py (goodqa#14565, PL-03).

LOSS_INVENTORY_SCRIPT may point at a mutated copy of the script; the suite must then fail.
"""
import importlib.util
import json
import os
import stat
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
        fb = tempfile.TemporaryDirectory()
        self.addCleanup(fb.cleanup)
        self.fakebin = Path(fb.name).resolve()
        ct = self.fakebin / "crontab"
        ct.write_text('#!/bin/sh\ncat "$FAKE_CRONTAB" 2>/dev/null || { echo "no crontab" >&2; exit 1; }\n')
        ct.chmod(0o755)
        self.env = dict(os.environ, HOME=str(self.home), PATH="%s:%s" % (self.fakebin, os.environ.get("PATH", "")))
        self.env.pop("FAKE_CRONTAB", None)
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
        # the bare dir stands in for an off-host remote: a local-path URL would (correctly) count as same-host
        git(self.work, "remote", "set-url", "origin", "https://remote.example.invalid/r.git")
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
                                        "timer": 1, "state_db_outside_git": 1, "git_stash": 0, "local_tag": 0,
                                        "dirty_worktree": 0, "crontab": 0}, r)
        self.assertEqual(r["schema"], 2)
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
        git(self.work, "push", "-q", str(self.bare), "work")  # origin URL is fake; push by path
        git(self.work, "update-ref", "refs/remotes/origin/work", "work")
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
    def saved(self):
        return self.home / ".agent-harness/state/loss-inventory/last-scan.json"

    def decide_all(self):
        for row in json.loads(self.run_cli("report", "--json").stdout)["undecided"]:
            self.run_cli("decide", "--row", row["path"], "--decision", "moved", "--ticket", "t#1", expect=0)

    def test_symlinked_git_and_dir_block_report_unless_target_scanned(self):
        out = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, str(out))
        # off-root repo with an unpushed branch, reachable only through symlinks
        ext = out / "ext"
        ext.mkdir()
        git(ext, "init", "-q", "-b", "main")
        commit(ext, "e1")
        git(ext, "remote", "add", "origin", "https://remote.example.invalid/e.git")
        lr = self.home / "linkrepo"
        lr.mkdir()
        os.symlink(str(ext / ".git"), str(lr / ".git"))
        os.symlink(str(out), str(self.home / "linkdir"))
        r = self.scan()
        sk = [x["path"] for x in r["skipped_symlinks"]]
        self.assertIn(str(lr / ".git"), sk)
        self.assertIn(str(self.home / "linkdir"), sk)
        self.decide_all()
        self.assertEqual(self.run_cli("report", expect=1).returncode, 1)  # nothing undecided, still blocked
        self.assertIn("SKIPPED_SYMLINK", self.run_cli("report").stdout.decode())
        # scanning the target as a root resolves the dir link (the .git symlink stays blocking)
        p = self.run_cli("scan", "--root", str(self.home), "--root", str(out), "--json", expect=0)
        r2 = json.loads(p.stdout)
        self.assertNotIn(str(self.home / "linkdir"), [x["path"] for x in r2["skipped_symlinks"]])
        # explicit acknowledgement is recorded
        p = self.run_cli("scan", "--root", str(self.home), "--allow-symlink-target", str(out), "--json", expect=0)
        r3 = json.loads(p.stdout)
        self.assertEqual(r3["skipped_symlinks"], [x for x in r3["skipped_symlinks"] if x["path"] == str(lr / ".git")])
        self.assertEqual(r3["symlink_allow"], [str(out)])

    def test_any_decision_on_branch_goes_stale_when_recreated(self):
        self.scan()
        path = "%s::work" % self.work
        self.run_cli("decide", "--row", path, "--decision", "accepted-loss", "--ticket", "t#1", expect=0)
        git(self.work, "checkout", "-q", "main")
        git(self.work, "branch", "-D", "work")
        git(self.work, "checkout", "-q", "-b", "work")
        commit(self.work, "new")
        self.scan()
        und = [x["path"] for x in json.loads(self.run_cli("report", "--json", expect=1).stdout)["undecided"]]
        self.assertIn(path, und)

    def test_report_does_not_trust_arbitrary_saved_scan(self):
        self.saved().parent.mkdir(parents=True, exist_ok=True)
        self.saved().write_text(json.dumps({"scanned_at": "1970-01-01T00:00:00Z", "rows": []}))
        p = self.run_cli("report", expect=1)
        self.assertIn("incomplete", p.stdout.decode())

    def test_report_blocks_scan_of_wrong_roots_and_old_scans(self):
        empty = self.home / "emptydir"
        empty.mkdir()
        self.run_cli("scan", "--root", str(empty), "--json", expect=0)
        self.decide_all()
        p = self.run_cli("report", expect=1)  # roots do not include $HOME
        self.assertIn("ROOTS", p.stdout.decode())
        self.run_cli("report", "--allow-partial-roots", expect=0)
        d = json.loads(self.saved().read_text())
        d["scanned_at"] = "2020-01-01T00:00:00Z"
        self.saved().write_text(json.dumps(d))
        p = self.run_cli("report", "--allow-partial-roots", expect=1)
        self.assertIn("older than", p.stdout.decode())
        self.run_cli("report", "--allow-partial-roots", "--max-age", "1000000", expect=0)

    def test_same_host_remotes_do_not_count_as_pushed(self):
        git(self.work, "remote", "set-url", "origin", str(self.bare))  # local path
        r = self.scan()
        self.assertEqual(r["classes"]["no_remote_repo"], 2, r["rows"])
        self.assertEqual(r["classes"]["unpushed_branch"], 0)
        import socket
        git(self.work, "remote", "set-url", "origin", "ssh://%s/srv/r.git" % socket.gethostname())
        self.assertEqual(self.scan()["classes"]["no_remote_repo"], 2)
        git(self.work, "remote", "set-url", "origin", "git@%s:r.git" % socket.gethostname())
        self.assertEqual(self.scan()["classes"]["no_remote_repo"], 2)
        git(self.work, "remote", "set-url", "origin", "git@github.example.invalid:r.git")
        self.assertEqual(self.scan()["classes"]["no_remote_repo"], 1)

    def test_skipped_mounts_block_report(self):
        self.scan()
        self.decide_all()
        self.run_cli("report", expect=0)
        d = json.loads(self.saved().read_text())
        d["skipped_mounts"], d["skipped_mounts_total"] = ["/mnt/x"], 1
        self.saved().write_text(json.dumps(d))
        self.assertIn("SKIPPED_MOUNT", self.run_cli("report", expect=1).stdout.decode())

    def test_builtin_prune_names_listed(self):
        r = self.scan()
        self.assertIn("node_modules", r["prune"])
        self.assertIn("PRUNED_DIR_NAMES", self.run_cli("report").stdout.decode())

    def test_state_files_private(self):
        sd = self.home / ".agent-harness/state/loss-inventory"
        sd.mkdir(parents=True)
        sd.chmod(0o755)
        self.scan()
        self.assertEqual(stat.S_IMODE(sd.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(self.saved().stat().st_mode), 0o600)

    def test_none_fingerprint_makes_decision_stale(self):
        spec = importlib.util.spec_from_file_location("li_under_test", str(SCRIPT))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        old = os.environ.get("HOME")
        os.environ["HOME"] = str(self.home)
        self.addCleanup(lambda: os.environ.__setitem__("HOME", old))
        sd = Path(mod.state_dir())
        sd.mkdir(parents=True)
        (sd / "decisions.jsonl").write_text(json.dumps({"path": "/r::b", "decision": "moved", "fp": None}) + "\n")
        rows = mod.merge_decisions([{"class": "unpushed_branch", "path": "/r::b", "fp": None}])
        self.assertIsNone(rows[0]["decision"])

    def test_stash_local_tag_dirty_crontab_and_extra_units(self):
        (self.work / "c1").write_text("changed")  # tracked file modified -> dirty
        git(self.work, "stash", "-q")
        (self.work / "c1").write_text("again")
        git(self.work, "tag", "v-local", "work")
        ud = self.home / ".local" / "share" / "systemd" / "user"
        ud.mkdir(parents=True)
        (ud / "s.socket").write_text("[Socket]\n")
        (ud / "p.path").write_text("[Path]\n")
        cron = self.home / "cron.txt"
        cron.write_text("# SECRET-IN-COMMENT\n\n0 * * * * /bin/backup --token=SECRET-TOKEN-9\n30 1 * * * /bin/x\n")
        self.env["FAKE_CRONTAB"] = str(cron)
        p = self.run_cli("scan", "--root", str(self.home), "--json", expect=0)
        r = json.loads(p.stdout)
        c = r["classes"]
        self.assertEqual((c["git_stash"], c["local_tag"], c["dirty_worktree"], c["crontab"]), (1, 1, 1, 1), r["rows"])
        self.assertEqual(c["systemd_user_unit"], 3)  # a.service + .socket + .path
        by = {x["class"]: x for x in r["rows"]}
        self.assertEqual(by["crontab"]["count"], 2)
        self.assertNotIn("SECRET", p.stdout.decode() + p.stderr.decode())
        self.assertGreaterEqual(by["dirty_worktree"]["count"], 1)

    def test_untracked_files_visible_despite_showuntracked_no(self):
        git(self.noremote, "config", "status.showUntrackedFiles", "no")
        (self.noremote / "new.txt").write_text("x")
        self.assertEqual(self.scan()["classes"]["dirty_worktree"], 1)

    def test_dirty_decision_stale_after_edit_of_same_file(self):
        git(self.noremote, "remote", "add", "o", "https://remote.example.invalid/n.git")
        f = self.noremote / "n1"
        f.write_text("edit one")
        self.scan()
        path = "%s::dirty" % self.noremote
        self.run_cli("decide", "--row", path, "--decision", "moved", "--ticket", "t#1", expect=0)
        f.write_text("edit two, longer")
        self.scan()
        und = [x["path"] for x in json.loads(self.run_cli("report", "--json", expect=1).stdout)["undecided"]]
        self.assertIn(path, und)

    def test_dirty_decision_stale_for_quoted_filename(self):
        f = self.noremote / ("caf\u00e9 tab\t.txt")
        f.write_text("one")
        self.scan()
        path = "%s::dirty" % self.noremote
        self.run_cli("decide", "--row", path, "--decision", "moved", "--ticket", "t#1", expect=0)
        with open(str(f), "a") as fh:
            fh.write("more content appended")
        self.scan()
        und = [x["path"] for x in json.loads(self.run_cli("report", "--json", expect=1).stdout)["undecided"]]
        self.assertIn(path, und)

    def test_string_min_db_in_saved_scan_does_not_traceback(self):
        self.scan()
        d = json.loads(self.saved().read_text())
        d["min_db_bytes"] = "1000"
        self.saved().write_text(json.dumps(d))
        p = self.run_cli("report", expect=1)
        self.assertNotIn("Traceback", p.stderr.decode())

    def test_crontab_failure_is_an_error_not_empty(self):
        ct = self.fakebin / "crontab"
        ct.write_text('#!/bin/sh\necho "crontab: permission denied" >&2\nexit 1\n')
        r = self.scan()
        self.assertTrue(any(e["path"] == "crontab" for e in r["errors"]), r["errors"])
        self.decide_all()
        self.run_cli("report", expect=1)
        r = json.loads(self.run_cli("scan", "--root", str(self.home), "--no-crontab", "--json", expect=0).stdout)
        self.assertFalse(any(e["path"] == "crontab" for e in r["errors"]))
        self.assertIn("NO_CRONTAB", self.run_cli("report", expect=1).stdout.decode())

    def test_missing_crontab_binary_is_an_error(self):
        env = dict(self.env, PATH="/nonexistent-dir")
        p = subprocess.run([sys.executable, str(SCRIPT), "scan", "--root", str(self.home), "--json"], env=env,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        r = json.loads(p.stdout)
        self.assertTrue(any(e["path"] == "crontab" for e in r["errors"]), r["errors"])

    def test_report_expect_host_and_db_threshold(self):
        self.scan()
        self.decide_all()
        self.run_cli("report", "--expect-host", json.loads(self.saved().read_text())["host"], expect=0)
        self.assertIn("HOST", self.run_cli("report", "--expect-host", "t2-dev", expect=1).stdout.decode())
        self.run_cli("scan", "--root", str(self.home), "--min-db-bytes", "1000000000000", "--json", expect=0)
        self.assertIn("DB_THRESHOLD", self.run_cli("report", expect=1).stdout.decode())

    def test_loopback_and_helper_remotes_are_local(self):
        for url in ("http://127.0.1.1/r.git", "ssh://127.5.5.5/r.git", "gcrypt::/mnt/backup/y", "git@[::1]:r.git",
                    "http://0.0.0.0/r.git"):
            git(self.work, "remote", "set-url", "origin", url)
            self.assertEqual(self.scan()["classes"]["no_remote_repo"], 2, url)

    def test_symlink_into_pruned_dir_is_not_covered(self):
        real = self.home / ".cache" / "real"
        real.mkdir(parents=True)
        os.symlink(str(real), str(self.home / "work"))
        r = self.scan()
        self.assertIn(str(self.home / "work"), [x["path"] for x in r["skipped_symlinks"]])

    def test_literal_pathspec_for_tracked_check(self):
        sub = self.noremote
        shutil.copy(str(self.db), str(sub / "a.db"))
        git(sub, "add", "a.db")
        git(sub, "commit", "-qm", "a")
        shutil.copy(str(self.db), str(sub / "[ab].db"))  # untracked, but glob-matches tracked a.db
        paths = [x["path"] for x in self.scan()["rows"] if x["class"] == "state_db_outside_git"]
        self.assertIn(str(sub / "[ab].db"), paths)

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
        git(bare, "remote", "set-url", "o2", "https://remote.example.invalid/b.git")  # off-host stand-in
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
    def test_no_remote_decision_goes_stale_on_side_branch_commit(self):
        self.scan()
        path = str(self.noremote)
        self.run_cli("decide", "--row", path, "--decision", "moved", "--ticket", "t#1", expect=0)
        git(self.noremote, "checkout", "-q", "-b", "side")
        commit(self.noremote, "s1")
        git(self.noremote, "checkout", "-q", "main")  # HEAD sha unchanged, work is on side
        self.scan()
        und = [x["path"] for x in json.loads(self.run_cli("report", "--json", expect=1).stdout)["undecided"]]
        self.assertIn(path, und)

    def test_accepted_loss_survives_db_churn(self):
        self.scan()
        path = str(self.db)
        self.run_cli("decide", "--row", path, "--decision", "accepted-loss", "--ticket", "t#1", expect=0)
        con = sqlite3.connect(path)
        con.execute("insert into t values (?)", (b"y" * 10,))
        con.commit()
        con.close()
        self.scan()
        und = [x["path"] for x in json.loads(self.run_cli("report", "--json", expect=1).stdout)["undecided"]]
        self.assertNotIn(path, und)

    def test_excludes_are_recorded_and_shown(self):
        p = self.run_cli("scan", "--root", str(self.home), "--exclude", "data", "--json", expect=0)
        r = json.loads(p.stdout)
        self.assertEqual(r["excludes"], ["data"])
        self.assertEqual(r["classes"]["state_db_outside_git"], 0)
        self.assertIn("EXCLUDED_DIR_NAMES", self.run_cli("report", expect=1).stdout.decode())

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
        needle = 'if not self.contained_in(repo, sha, *ns):'
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
