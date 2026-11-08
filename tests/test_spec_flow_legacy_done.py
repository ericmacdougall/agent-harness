"""spec_flow.py done --legacy: READY from merge + deploy + REALLY_TESTED evidence, no spec (goodqa#15253, B3.14)."""

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import spec_flow as sf  # noqa: E402

TICKET = "GoodQA goodqa#123"


def git(repo, *args):
    env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@e", GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@e")
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True, env=env).stdout.strip()


class FakeAdapter:
    def __init__(self):
        self.closed_with = []

    def close_done(self, issue_id, note):
        self.closed_with.append((issue_id, note))
        return True, "done"


class FakeSession:
    adapter = None

    def __init__(self, ref, spec_policy):
        self.ticket = mock.Mock(id="issue-1", label=TICKET, closed=False, status="open")
        self.adapter = FakeSession.adapter


class LegacyDone(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="legacy-done-"))
        self.repo = self.tmp / "repo"
        self.repo.mkdir()
        git(self.repo, "init", "-q", "-b", "main")
        (self.repo / "a").write_text("a")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "one\n\nRefs: GoodQA goodqa#123")
        self.merged = git(self.repo, "rev-parse", "HEAD")
        git(self.repo, "checkout", "-q", "-b", "feature")
        (self.repo / "b").write_text("b")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "two\n\nRefs: GoodQA goodqa#123")
        self.unmerged = git(self.repo, "rev-parse", "HEAD")
        git(self.repo, "checkout", "-q", "main")
        (self.repo / "c").write_text("c")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "three, cites nothing")
        self.uncited = git(self.repo, "rev-parse", "HEAD")
        walroot = self.tmp / "wals"
        (walroot / "sess").mkdir(parents=True)
        self.wal = walroot / "sess" / "main.jsonl"
        rows = [{"id": "wdeploy1", "note": "DEPLOYED goodqa#123 to live host"},
                {"id": "wtest1", "note": "REALLY_TESTED RT1: ran the live check for 123, exit 0"},
                {"id": "wdeploy2", "note": "DEPLOYED to live host"},
                {"id": "wdeploy3", "note": "DEPLOYED %s to live host"},
                {"id": "wtest2", "note": "REALLY_TESTED RT2: ran the live check, exit 0"},
                {"id": "wplain1", "note": "ran some unit tests"},
                {"id": "wnotlive", "note": "deployed to staging, not live"}]
        self.wal.write_text(("\n".join(json.dumps(r) for r in rows) + "\n").replace("%s", self.merged[:7]))
        patch = mock.patch.object(sf, "wal_root", lambda: walroot)
        patch.start()
        self.addCleanup(patch.stop)
        self.addCleanup(__import__("shutil").rmtree, self.tmp, True)

    def run_done(self, *, merge=None, deploy="wdeploy1", tested="wtest1", apply=False, session=None):
        argv = ["done", "--ticket", TICKET, "--legacy", "--repo", str(self.repo), "--merge", merge or self.merged,
                "--deploy", deploy, "--really-tested", tested, "--wal", str(self.wal)]
        if apply:
            argv.append("--apply")
        out, err = io.StringIO(), io.StringIO()
        patches = [mock.patch.object(sf, "load_spec_policy", lambda *a: {})]
        if session:
            patches.append(mock.patch.object(sf, "Session", session))
        with contextlib.ExitStack() as stack:
            for p in patches:
                stack.enter_context(p)
            stack.enter_context(contextlib.redirect_stdout(out))
            stack.enter_context(contextlib.redirect_stderr(err))
            code = sf.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_all_three_present_is_ready(self):
        code, out, _ = self.run_done()
        self.assertEqual(code, sf.EXIT_OK, out)
        self.assertIn("READY", out)
        self.assertNotIn("NOT READY", out)

    def test_unmerged_sha_is_missing_and_named(self):
        code, out, _ = self.run_done(merge=self.unmerged)
        self.assertEqual(code, sf.EXIT_MISSING)
        self.assertIn(f"merge sha {self.unmerged} is not on main", out)

    def test_missing_wal_ids_are_named(self):
        code, out, _ = self.run_done(deploy="wnope", tested="wnope2")
        self.assertEqual(code, sf.EXIT_MISSING)
        self.assertIn("deploy WAL entry wnope was not found", out)
        self.assertIn("REALLY_TESTED WAL entry wnope2 was not found", out)

    def test_wrong_kind_of_wal_entry_is_missing(self):
        code, out, _ = self.run_done(deploy="wplain1", tested="wplain1")
        self.assertEqual(code, sf.EXIT_MISSING)
        self.assertIn("deploy WAL entry wplain1 does not mention LIVE or DEPLOYED", out)
        self.assertIn("WAL entry wplain1 does not start with REALLY_TESTED", out)
        code, out, _ = self.run_done(deploy="wnotlive")
        self.assertEqual(code, sf.EXIT_MISSING, out)

    def test_merge_commit_must_cite_ticket(self):
        code, out, _ = self.run_done(merge=self.uncited)
        self.assertEqual(code, sf.EXIT_MISSING)
        self.assertIn(f"merge sha {self.uncited} does not cite {TICKET}", out)

    def test_deploy_note_must_name_ticket_or_sha(self):
        code, out, _ = self.run_done(deploy="wdeploy2")
        self.assertEqual(code, sf.EXIT_MISSING)
        self.assertIn(f"deploy entry wdeploy2 names neither 123 nor {self.merged[:7]}", out)
        code, out, _ = self.run_done(deploy="wdeploy3")  # the sha7 form is accepted
        self.assertEqual(code, sf.EXIT_OK, out)

    def test_really_tested_note_must_name_ticket_or_sha(self):
        code, out, _ = self.run_done(tested="wtest2")
        self.assertEqual(code, sf.EXIT_MISSING)
        self.assertIn(f"REALLY_TESTED entry wtest2 names neither 123 nor {self.merged[:7]}", out)

    def test_unknown_commit_is_missing(self):
        code, out, _ = self.run_done(merge="deadbeef" * 5)
        self.assertEqual(code, sf.EXIT_MISSING)
        self.assertIn("is not a commit in", out)

    def test_apply_is_refused_even_when_ready(self):
        # review F4: `done --legacy --apply` was a spec-gate bypass; the legacy path is a report only
        FakeSession.adapter = FakeAdapter()
        code, out, _ = self.run_done(apply=True, session=FakeSession)
        self.assertEqual(code, sf.EXIT_MISSING, out)
        self.assertIn("REFUSED", out)
        self.assertEqual(FakeSession.adapter.closed_with, [])
        code, out, _ = self.run_done()
        self.assertEqual(code, sf.EXIT_OK, out)
        self.assertIn("report only", out)

    def test_apply_not_called_when_missing(self):
        FakeSession.adapter = FakeAdapter()
        code, _, _ = self.run_done(merge=self.unmerged, apply=True, session=FakeSession)
        self.assertEqual(code, sf.EXIT_MISSING)
        self.assertEqual(FakeSession.adapter.closed_with, [])

    def test_missing_flags_are_reported_not_crashed(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), mock.patch.object(sf, "load_spec_policy", lambda *a: {}):
            code = sf.main(["done", "--ticket", TICKET, "--legacy"])
        self.assertEqual(code, sf.EXIT_MISSING)
        self.assertIn("--merge", out.getvalue())


if __name__ == "__main__":
    unittest.main()
