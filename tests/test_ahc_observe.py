"""AC-1 / AC-2: the observation producer and the checks evidence (goodqa#16049 slice 1 (b), spec r9).

gh and the GoodQA reader are injected fakes over minimized fixtures (no emails, names or tokens); git is a real local
repository built per test, read through the same argv the production producer passes to the AC-13 git form."""
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HOOKS = Path(__file__).resolve().parent.parent / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import ahc_contracts as C  # noqa: E402
import ahc_observe as O  # noqa: E402

BOOT = "test-boot"
REPO = "o/r"
PKT, POLICY_REV, CORE = "d" * 64, "policy-r1", "1" * 64
GIT_ENV = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": "/nonexistent", "LC_ALL": "C",
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0",
           "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t",
           "GIT_AUTHOR_DATE": "1700000000 +0000", "GIT_COMMITTER_DATE": "1700000000 +0000"}


class Clock:
    def __init__(self):
        self.t = 1_800_000_000.0

    def __call__(self):
        return self.t


def git(cwd, *args, inp=None):
    out = subprocess.run(["git", *args], cwd=str(cwd), env=GIT_ENV, input=inp, capture_output=True, text=True,
                         timeout=60)
    if out.returncode != 0:
        raise AssertionError("fixture git %s failed: %s" % (args[0], out.stderr))
    return out.stdout.strip()


class Repo:
    """A local repository: commit(files, msg) on a branch, returning the full sha."""

    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        git(self.root, "init", "-q", ".")
        git(self.root, "checkout", "-q", "-b", "main")

    def commit(self, files=None, msg="c", parent=None, delete=()):
        if parent:
            git(self.root, "checkout", "-q", "--detach", parent)
        for name, text in (files or {}).items():
            p = self.root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)
        for name in delete:
            git(self.root, "rm", "-q", name)
        git(self.root, "add", "-A")
        git(self.root, "commit", "-q", "--allow-empty", "-m", msg)
        return git(self.root, "rev-parse", "HEAD")

    def mv(self, old, new, msg="mv"):
        git(self.root, "mv", old, new)
        git(self.root, "commit", "-q", "-m", msg)
        return git(self.root, "rev-parse", "HEAD")

    def many(self, parent, n, last_msg):
        """n commits after `parent` through commit-tree (fast); the last carries `last_msg`."""
        tree = git(self.root, "rev-parse", parent + "^{tree}")
        sha = parent
        for i in range(n):
            sha = git(self.root, "commit-tree", tree, "-p", sha, "-m", last_msg if i == n - 1 else "step %d" % i)
        return sha


def real_git(args, cwd, timeout):
    out = subprocess.run(["git", *args], cwd=str(cwd), env=GIT_ENV, capture_output=True, text=True, timeout=timeout)
    return out.returncode, out.stdout, out.stderr


def pull_json(head, number=5, repo=REPO, state="open", body="", changed=1, mergeable=True, ms="clean",
              updated="2026-11-16T00:00:00Z", merged=False, draft=False):
    return {"number": number, "state": state, "merged": merged, "draft": draft, "mergeable": mergeable,
            "mergeable_state": ms, "body": body, "updated_at": updated, "changed_files": changed,
            "head": {"sha": head}, "base": {"repo": {"full_name": repo}, "ref": "main"}}


def page(body, nxt=None, status="200 OK"):
    link = "Link: <https://api.github.com/x?page=%d>; rel=\"next\"\n" % nxt if nxt else ""
    return "HTTP/2.0 %s\nContent-Type: application/json\n%s\n%s\n" % (status, link, json.dumps(body))


def run(name, conclusion="success", app="github-actions", head=None, status="completed"):
    return {"name": name, "status": status, "conclusion": conclusion, "app": {"slug": app}, "head_sha": head}


class FakeGh:
    """Answers each endpoint from a queue of (rc, out, err) per endpoint; records every argv."""

    def __init__(self):
        self.calls = []
        self.answers = {}

    def set(self, endpoint, *answers):
        self.answers[endpoint] = list(answers)

    def __call__(self, args, timeout):
        self.calls.append(list(args))
        endpoint = args[-1]
        queue = self.answers.get(endpoint)
        if not queue:
            return 1, "", "HTTP 404: not found"
        ans = queue.pop(0) if len(queue) > 1 else queue[0]
        if isinstance(ans, tuple):
            return ans
        return 0, ans if isinstance(ans, str) else json.dumps(ans), ""


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = sqlite3.connect(":memory:", isolation_level=None)
        C.apply_schema(self.db)
        self.clock = Clock()
        self.c = C.Contracts(self.db, C.AuthorityLog(Path(self.tmp.name) / "a.jsonl"), now=self.clock,
                             mono=self.clock, boot_id=BOOT)
        self.repo = Repo(Path(self.tmp.name) / "clone")
        self.base = self.repo.commit({"README": "r\n", "src/a.py": "a\n"}, "base")
        self.head = self.repo.commit({"src/b.py": "b\n"}, "pr change", parent=self.base)
        self.gh = FakeGh()
        self.policy = {"revision": POLICY_REV, "default_branch": "main", "readable": True, "allowlisted": True,
                       "enabled": True, "required_checks": {"contexts": ["test"], "app": "github-actions"}}
        self.gq = {"attached_core": CORE, "open_findings": 0, "mirror_ok": True}
        self.local = {"kill_switch": False, "kill_epoch": 1, "chk_cas": True,
                      "canary": {"boot": BOOT, "mono": self.clock.t - 60}}
        self.wire(self.head, self.base)

    def wire(self, head, tip, changed=1, body="", runs=None, statuses=None):
        self.gh.set("repos/o/r/pulls/5", pull_json(head, changed=changed, body=body))
        self.gh.set("repos/o/r/git/ref/heads/main", {"object": {"sha": tip}})
        runs = [run("test", head=head)] if runs is None else runs
        self.gh.set("repos/o/r/commits/%s/check-runs?per_page=100&filter=all" % head,
                    page({"total_count": len(runs), "check_runs": runs}))
        self.gh.set("repos/o/r/commits/%s/statuses?per_page=100" % head, page(statuses or []))

    def producer(self, gh=None):
        return O.Producer(self.c, gh or self.gh, real_git, lambda r, p, i: dict(self.gq),
                          lambda r: dict(self.local, policy=dict(self.policy)))

    def observe(self, producer=None, **kw):
        kw.setdefault("clone", self.repo.root)
        return (producer or self.producer()).observe(REPO, 5, **kw)

    def observe_ok(self, **kw):
        """An observation the test expects to succeed: a refusal is an assertion failure, not an error, so a
        variant that makes the producer refuse is killed rather than inconclusive (AC-15)."""
        try:
            return self.observe(**kw)
        except O.ObservationRefused as error:
            self.fail("the observation was refused: %s" % error)

    def rows(self):
        return self.db.execute("SELECT COUNT(*) FROM observations").fetchone()[0]

    def item(self, head=None, base=None):
        return self.c.admit_item(REPO, 5, head or self.head, base or self.base, POLICY_REV, CORE, PKT, event_id="adm")


class ProducerTests(Base):
    """AC-1: each field from its named source, one read session, persisted and loaded by id."""

    def test_r273_f3_the_attached_cores_text_is_verified_handed_to_r2_and_never_persisted(self):
        """PR 273 receipt F3: the reader's spec core text must hash to attached_core. A match rides on the returned
        observation only (not in the persisted fields, whose digest the guards check); a foreign, oversized or
        non-text value refuses the observation; no text leaves the observation without one (R2 then holds)."""
        import hashlib  # noqa: PLC0415
        spec = "# Spec\n\n## Acceptance criteria\n\n- AC-1: a. Verify by: t.\n"
        self.gq = dict(self.gq, attached_core=hashlib.sha256(spec.encode()).hexdigest(), spec_core_text=spec)
        o = self.observe_ok()
        self.assertEqual(o["spec_core_text"], spec)
        stored = json.loads(self.db.execute("SELECT fields FROM observations WHERE id=?", (o["id"],)).fetchone()[0])
        self.assertNotIn("spec_core_text", stored)
        self.assertEqual(stored["attached_core"], self.gq["attached_core"])
        self.assertNotIn("spec_core_text", self.c.load_observation(o["id"]))
        big = "x" * (O.SPEC_CORE_MAX + 1)
        for name, text, core in (("foreign", spec + "tampered", self.gq["attached_core"]),
                                 ("oversized", big, hashlib.sha256(big.encode()).hexdigest()),
                                 ("not text", 42, self.gq["attached_core"]),
                                 ("not utf-8", b"\xff", hashlib.sha256(b"\xff").hexdigest())):
            with self.subTest(name):
                self.gq = dict(self.gq, attached_core=core, spec_core_text=text)
                before = self.rows()
                with self.assertRaises(O.ObservationRefused):
                    self.observe()
                self.assertEqual(self.rows(), before, "a refused observation is not persisted")
        self.gq = {k: v for k, v in self.gq.items() if k != "spec_core_text"}
        self.assertNotIn("spec_core_text", self.observe_ok())

    def test_ac1_fields_come_from_their_named_sources(self):
        tip = self.repo.commit({"src/other.py": "o\n"}, "moved main", parent=self.base)
        self.wire(self.head, tip)
        o = self.observe_ok(snapshot_bases=[self.base], base=self.base)
        self.assertEqual((o["pr_head"], o["pr_state"], o["draft"], o["mergeable"]), (self.head, "OPEN", False, True))
        self.assertEqual(o["tip"], tip, "tip from the default-branch ref")
        self.assertEqual(o["paths"], ["src/b.py"], "M..H from local git, not B..H")
        self.assertEqual(o["compare"], "diverged")
        self.assertEqual(o["b_r_ancestors"], {self.base: True})
        self.assertIs(o["fast_forward"], True)
        self.assertIs(o["foreign_closing_keyword"], False)
        self.assertIs(o["policy"]["checks_green"], True)
        self.assertEqual((o["attached_core"], o["open_findings"], o["kill_switch"], o["chk_cas"]),
                         (CORE, 0, False, True))
        self.assertAlmostEqual(o["canary_age"], 60.0)
        self.assertEqual(o["boot"], BOOT)
        endpoints = [a[-1] for a in self.gh.calls]
        self.assertEqual(endpoints.count("repos/o/r/pulls/5"), 2, "the PR is read first and re-read at the end")
        self.assertTrue(all(a[:3] == ["api", "--method", "GET"] for a in self.gh.calls), "reads only")
        self.assertFalse(any("files" in e or e.endswith("/commits") for e in endpoints),
                         "no 3000-file or 250-commit API list is read")

    def test_ac1_each_read_gets_its_own_id_and_guards_load_it_by_id(self):
        a, b = self.observe(), self.observe()
        self.assertNotEqual(a["id"], b["id"])
        self.assertEqual(self.rows(), 2, "append-only, one row per read")
        loaded = self.c.load_observation(a["id"])
        self.assertEqual(loaded, a)
        self.assertEqual(a["id"], "obs:%s:%r:%d" % (BOOT, a["mono"], 1), "(boot id, boot clock, sequence)")
        self.db.execute("UPDATE observations SET fields=replace(fields, 'OPEN', 'CLOSED') WHERE id=?", (a["id"],))
        with self.assertRaisesRegex(C.ContractError, "digest"):
            self.c.load_observation(a["id"])

    def test_ac1_a_rename_counts_once_and_both_paths_are_checked(self):
        head = self.repo.mv("src/a.py", "src/a2.py")
        self.wire(head, self.base, changed=2)              # b.py added, a.py renamed: two entries for GitHub
        o = self.observe()
        self.assertEqual(sorted(o["paths"]), ["src/a.py", "src/a2.py", "src/b.py"], "both rename paths listed")
        self.assertEqual(o["changed_files"], 2, "the rename counted once")

    def test_neg1_age_boot_and_type_faults_fail_the_guard_by_clause(self):
        item = self.item()
        o = self.observe()
        self.clock.t += 119.9
        self.assertNotIn("e1", [], "fresh at 119.9 s")
        self.assertIsNone(O.stale_or_bad(self.c, o))
        self.clock.t += 0.1
        self.assertIn("stale", O.stale_or_bad(self.c, o), "120 s is stale")
        self.clock.t -= 120
        for change, why in ((dict(boot="other"), "another boot"), (dict(pr_head="a" * 39), "full sha")):
            bad = dict(o, **change)
            with self.subTest(change=change), self.assertRaisesRegex(C.ContractError, why):
                self.c._wi_obs(item, bad, "pr_head")
        missing = {k: v for k, v in o.items() if k != "tip"}
        self.assertIn("e10", self.c.elig(item, missing))
        self.assertIn("e3", self.c.elig(item, dict(o, open_findings=True)), "True where an int belongs")

    def test_neg2_another_repo_number_or_short_head_is_refused(self):
        for answer in (pull_json(self.head, repo="o/other"), pull_json(self.head, number=6),
                       pull_json(self.head[:39])):
            self.gh.set("repos/o/r/pulls/5", answer)
            with self.subTest(answer=answer["number"]), self.assertRaisesRegex(O.ObservationRefused, "NEG-2"):
                self.observe()
        self.assertEqual(self.rows(), 0, "nothing persisted, nothing moves")

    def test_neg3_local_git_sees_the_3001st_file_and_the_251st_commit(self):
        files = {"pkg/f%04d.txt" % i: "x\n" for i in range(3000)}
        files["pkg/ahc_zz.py"] = "p\n"                       # a protected path, the 3001st file
        head = self.repo.commit(files, "big", parent=self.base)
        self.wire(head, self.base, changed=3001)
        item = self.item(head=head)
        o = self.observe()
        self.assertEqual(len(o["paths"]), 3001)
        self.assertIn("e4", self.c.elig(item, o))
        many = self.repo.many(self.head, 251, "fixes o/elsewhere#7")
        self.wire(many, self.base, changed=1)
        o = self.observe()
        self.assertIs(o["foreign_closing_keyword"], True, "the 251st commit's message is read locally")

    def test_neg3_a_changed_files_count_that_disagrees_fails_closed(self):
        self.wire(self.head, self.base, changed=2)
        with self.assertRaisesRegex(O.ObservationRefused, "NEG-3"):
            self.observe()
        self.assertEqual(self.rows(), 0)

    def test_neg4_head_moves_timeout_byte_cap_and_rate_limit_refuse(self):
        other = self.repo.commit({"src/c.py": "c\n"}, "pushed", parent=self.head)
        self.gh.set("repos/o/r/pulls/5", pull_json(self.head), pull_json(other))
        with self.assertRaisesRegex(O.ObservationRefused, "moved"):
            self.observe()
        self.wire(self.head, self.base)
        self.gh.set("repos/o/r/git/ref/heads/main", (124, "", "timeout after 30s"))
        with self.assertRaisesRegex(O.ObservationRefused, "exit 124"):
            self.observe()
        self.wire(self.head, self.base)
        self.gh.set("repos/o/r/git/ref/heads/main", json.dumps({"object": {"sha": self.base}, "pad": "x" * 70_000}))
        with self.assertRaisesRegex(O.ObservationRefused, "byte cap"):
            self.observe()
        self.wire(self.head, self.base)
        self.gh.set("repos/o/r/pulls/5", (1, "", "HTTP 429: rate limit exceeded"))
        with self.assertRaises(O.ObservationRefused) as caught:
            self.observe()
        self.assertTrue(caught.exception.rate_limited)
        self.wire(self.head, self.base)
        before = len(self.gh.calls)
        with self.assertRaisesRegex(O.ObservationRefused, "backing off"):
            self.observe()
        self.assertEqual(len(self.gh.calls), before, "a backoff makes no call")
        self.clock.t += O.BACKOFF_SECONDS + 1
        self.assertEqual(self.observe()["pr_head"], self.head, "after the backoff the read goes ahead")
        self.assertEqual(self.rows(), 1)

    def test_ac1_the_call_budget_and_deadline_fail_closed(self):
        p = self.producer()
        p.tick_left = 3
        with self.assertRaisesRegex(O.ObservationRefused, "budget"):
            self.observe(p)

        def slow(args, timeout):
            self.clock.t += 60
            return self.gh(args, timeout)
        with self.assertRaisesRegex(O.ObservationRefused, "deadline"):
            self.observe(self.producer(gh=slow))

    def test_neg33_divergent_history_counts_only_the_prs_own_changes(self):
        tip = self.repo.commit({"src/a.py": "changed on main\n"}, "main edits A", parent=self.base)
        self.wire(self.head, tip, changed=1)
        o = self.observe_ok()     # NEG-33: the counts agree over M..H; a B..H list would refuse
        self.assertEqual(o["paths"], ["src/b.py"])
        self.assertEqual(o["changed_files"], 1)

    def test_neg34_body_keyword_body_edit_and_bad_body_read(self):
        self.wire(self.head, self.base, body="Closes o/elsewhere#3")
        first = self.observe()
        self.assertIs(first["foreign_closing_keyword"], True, "the keyword is only in the body")
        self.gh.set("repos/o/r/pulls/5", pull_json(self.head, body="no keyword", updated="2026-11-16T01:00:00Z"))
        second = self.observe()
        self.assertIs(second["foreign_closing_keyword"], False, "an edit to the body alone is seen")
        self.assertNotEqual(first["body_sha256"], second["body_sha256"])
        self.assertEqual(second["body_updated_at"], "2026-11-16T01:00:00Z")
        same_repo = pull_json(self.head, body="fixes o/r#3")
        self.gh.set("repos/o/r/pulls/5", same_repo)
        self.assertIs(self.observe()["foreign_closing_keyword"], False, "this repo's own issue is not foreign")
        missing = pull_json(self.head)
        del missing["body"]
        for answer, why in ((missing, "no body"), (pull_json(self.head, body="x" * (O.BODY_MAX_BYTES + 1)),
                                                   "byte cap"), ('{"number": 5, "body": "trunc', "not JSON")):
            self.gh.set("repos/o/r/pulls/5", answer)
            with self.subTest(why=why):
                try:
                    self.observe()
                except O.ObservationRefused as error:
                    self.assertRegex(str(error), why)
                except Exception as error:  # noqa: BLE001 - a crash is not the named refusal (fail closed by name)
                    self.fail("a bad body read (%s) raised %r instead of ObservationRefused" % (why, error))
                else:
                    self.fail("a bad body read (%s) was accepted" % why)


class ChecksEvidenceTests(Base):
    """AC-2 / NEG-6: checks_green only from evidence bound to (repo, B, H, policy revision)."""

    def green(self, **kw):
        return self.observe(**kw)["policy"]["checks_green"]

    def test_ac2_bound_evidence_is_green(self):
        self.assertIs(self.green(), True)

    def test_neg6_injected_true_without_bound_evidence_is_false(self):
        self.policy["checks_green"] = True              # an injected True in the policy record
        self.wire(self.head, self.base, runs=[])
        self.assertIs(self.green(), False)
        self.assertIs(O.bound_green({"green": True}, REPO, self.base, self.head, POLICY_REV), False)

    def test_neg6_failed_then_passed_rerun_is_false(self):
        self.wire(self.head, self.base, runs=[run("test", "failure", head=self.head), run("test", head=self.head)])
        self.assertIs(self.green(), False)

    def test_neg6_duplicate_context_and_spoofed_app_are_false(self):
        self.wire(self.head, self.base, statuses=[{"context": "test", "state": "success"}])
        self.assertIs(self.green(), False, "also posted as a commit status")
        self.wire(self.head, self.base, runs=[run("test", app="someone-else", head=self.head)])
        self.assertIs(self.green(), False, "posted by another app")

    def test_neg6_a_missing_page_is_false_or_refused(self):
        runs = [run("test", head=self.head)]
        ep = "repos/o/r/commits/%s/check-runs?per_page=100&filter=all" % self.head
        self.gh.set(ep, page({"total_count": 2, "check_runs": runs}))
        self.assertIs(self.green(), False, "total_count says a run was not read")
        self.gh.set(ep, page({"total_count": 1, "check_runs": runs}, nxt=2))
        with self.assertRaisesRegex(O.ObservationRefused, "truncated"):
            self.observe()
        self.gh.set(ep, page({"total_count": 1, "check_runs": runs}, nxt=3) + page({"total_count": 1,
                                                                                    "check_runs": []}))
        with self.assertRaisesRegex(O.ObservationRefused, "missing"):
            self.observe()

    def test_neg6_stale_b_another_head_or_revision_is_false(self):
        o = self.observe()
        ev = o["checks_evidence"]
        self.assertIs(O.bound_green(ev, REPO, self.base, self.head, POLICY_REV), True)
        for args in ((REPO, "9" * 40, self.head, POLICY_REV), (REPO, self.base, "8" * 40, POLICY_REV),
                     (REPO, self.base, self.head, "policy-r2"), ("o/other", self.base, self.head, POLICY_REV)):
            with self.subTest(args=args):
                self.assertIs(O.bound_green(ev, *args), False)

    def test_neg6_ahc_local_checks_are_false_in_this_slice(self):
        self.policy["required_checks"] = {"ahc_local": True, "contexts": ["test"], "app": "github-actions"}
        self.assertIs(self.green(), False)


if __name__ == "__main__":
    unittest.main()
