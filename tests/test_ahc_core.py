"""ahc core: submit validation (AC-1, NEG-1), live PR resolution (AC-2, NEG-2) and receipt verification (AC-5,
NEG-5). Scratch HOME per test, fake gh runner, no network. GoodQA goodqa#16034."""
import hashlib
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import ahc_core as core  # noqa: E402

HEAD = "a" * 40
BASE = "b" * 40
REPO = "ericmacdougall/agent-harness"


class Fake:
    """gh stand-in: returns the configured PR JSON and records argv."""
    def __init__(self, pr=None, rc=0):
        self.pr, self.rc, self.calls = pr, rc, []

    def __call__(self, argv, timeout):
        self.calls.append(argv)
        return self.rc, json.dumps(self.pr or {}), ""


def live_pr(**over):
    pr = {"number": 7, "state": "OPEN", "headRefOid": HEAD, "baseRefOid": BASE, "baseRefName": "main",
          "isCrossRepository": False}
    pr.update(over)
    return pr


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)
        self.paths = core.Paths(self.home)
        self.work = self.home / ".agent-harness" / "work" / "s1"
        self.work.mkdir(parents=True)
        self.packet = self.work / "packet.md"
        self.packet.write_text("packet " + HEAD + "\n")
        self.config = {"repos": [REPO], "work_roots": [str(self.home / ".agent-harness" / "work")]}

    def tearDown(self):
        self.tmp.cleanup()

    def request(self, **over):
        req = {"repo": REPO, "pr": 7, "head": HEAD, "base": BASE, "packet": str(self.packet),
               "ticket": "GoodQA goodqa#16034", "owner": "agent-abc123"}
        req.update(over)
        return req


REPOS4 = [REPO, "ericmacdougall/agent-fabric", "ericmacdougall/bugtracker", "ericmacdougall/Android-security"]


def _race_submit(job):
    """One child process of the admission race: a real core.submit against the shared ledger."""
    home, repo, pr, start = job
    sys.path.insert(0, str(HOOKS))
    import time as _time
    import ahc_core as _core
    paths = _core.Paths(home)
    config = {"repos": REPOS4, "work_roots": [str(Path(home) / ".agent-harness" / "work")]}
    req = {"repo": repo, "pr": pr, "head": HEAD, "base": BASE,
           "packet": str(Path(home) / ".agent-harness" / "work" / "s1" / "packet.md"),
           "ticket": "GoodQA goodqa#16034", "owner": "agent-abc123"}
    while _time.time() < start:   # release every child at once so they really race
        _time.sleep(0.001)
    try:
        return "dup" if _core.submit(paths, config, req)["duplicate"] else "ok"
    except _core.Refused as error:
        return "refused: %s" % error


class SubmitLimitTests(Base):
    """NEG-52 / spec v4 F2: admission is one BEGIN IMMEDIATE ledger transaction. Concurrent submits never exceed
    the queue cap or the per-repo hourly limit; a repo off the allowlist is refused; a file placed in the queue
    directory admits nothing."""

    def setUp(self):
        super().setUp()
        self.config["repos"] = REPOS4
        import ahc_runner
        self.runner = ahc_runner

    def prefill(self, n, submitted=1_000.0):
        """n waiting items admitted long ago (outside the hourly window), straight into the ledger."""
        ledger = self.runner.Ledger(self.paths)
        try:
            with ledger.tx():
                for i in range(n):
                    ledger.db.execute(
                        "INSERT INTO items(id, lineage, owner, ticket, state, next_action_at, submitted, request)"
                        " VALUES (?,?,?,?,?,?,?,?)", ("ahc-old%d" % i, "x/y|%d" % i, "o", "t", "queued", 0, submitted,
                                                      "{}"))
        finally:
            ledger.close()

    def race(self, jobs):
        import multiprocessing
        import time
        self.runner.Ledger(self.paths).close()   # the schema exists before the children race
        start = time.time() + 1.5
        ctx = multiprocessing.get_context("spawn")
        with ctx.Pool(len(jobs)) as pool:
            return pool.map(_race_submit, [(str(self.home), repo, pr, start) for repo, pr in jobs])

    def count(self, where="1=1", args=()):
        ledger = self.runner.Ledger(self.paths)
        try:
            return ledger.db.execute("SELECT COUNT(*) FROM items WHERE " + where, args).fetchone()[0]
        finally:
            ledger.close()

    def test_twenty_racers_against_ten_free_slots_admit_exactly_ten(self):
        self.prefill(40)
        jobs = [(REPOS4[i % 4], 100 + i) for i in range(20)]   # 5 per repo: the hourly limit never binds
        results = self.race(jobs)
        self.assertEqual(results.count("ok"), 10, results)
        self.assertTrue(all(r == "ok" or "queue is full" in r for r in results), results)
        self.assertEqual(self.count("state='queued'"), 50)

    def test_seven_racers_for_one_repo_admit_six(self):
        results = self.race([(REPO, 200 + i) for i in range(7)])
        self.assertEqual(results.count("ok"), 6, results)
        self.assertEqual(len([r for r in results if "in the last hour" in r]), 1, results)
        self.assertEqual(self.count(), 6)

    def test_hourly_window_rolls(self):
        import time
        for i in range(6):
            core.submit(self.paths, self.config, self.request(pr=300 + i), now=time.time() - 3700)
        core.submit(self.paths, self.config, self.request(pr=399))   # the six are older than an hour
        with self.assertRaises(core.Refused):
            for i in range(6):
                core.submit(self.paths, self.config, self.request(pr=400 + i))
        self.assertEqual(self.count("submitted > ?", (time.time() - 3600,)), 6)

    def test_repo_off_the_allowlist_is_refused(self):
        with self.assertRaises(core.Refused):
            core.submit(self.paths, self.config, self.request(repo="someone/else"))
        self.assertEqual(self.count() if (self.paths.root / "ledger.sqlite3").exists() else 0, 0)

    def test_duplicate_is_not_counted_against_the_limit(self):
        for _ in range(8):
            core.submit(self.paths, self.config, self.request(pr=500))
        self.assertEqual(self.count(), 1)

    def test_planted_queue_file_admits_nothing(self):
        good = core.submit(self.paths, self.config, self.request(pr=600))["id"]
        rec = json.loads(self.runner.Ledger(self.paths).item(good)["request"])
        forged = dict(rec, pr=601)
        forged["id"] = core.item_id(forged, forged["packet_sha256"])
        self.paths.queue.mkdir(parents=True, exist_ok=True)
        (self.paths.queue / (forged["id"] + ".json")).write_text(json.dumps(forged))
        calls = []

        class Deps:
            now = 2_000_000_000.0

            def clock(self):
                return self.now

            def ah(self, argv, timeout):
                calls.append(argv)
                return 0, "{}", ""

            def ops_watch(self, argv, timeout):
                return 1, "", ""

            def gh(self, argv, timeout):
                return 1, "", ""
        self.runner.tick(self.paths, self.config, Deps(), role="core")
        self.assertEqual(self.count("id=?", (forged["id"],)), 0, "a well-formed planted file must not be admitted")
        self.assertTrue(list((self.paths.root / "rejected").glob(forged["id"] + ".json")))
        self.assertTrue([a for a in calls if a[:3] == ["ah", "alert", "raise"]
                         and a[a.index("--alert-key") + 1].startswith("ahc:rejected:")])


class StdinPacketTests(Base):
    """adv-3 F2: `ahc submit --packet -` reads capped stdin into the private staging root and echoes its SHA-256."""

    def setUp(self):
        super().setUp()
        import ahc_runner
        self.runner = ahc_runner

    def stream(self, data):
        import io
        return io.BytesIO(data)

    def test_stage_writes_private_file_and_returns_sha(self):
        data = ("packet " + HEAD + "\n").encode()
        path, sha = self.runner.stage_packet(self.paths, self.stream(data))
        self.assertEqual(sha, hashlib.sha256(data).hexdigest())
        self.assertEqual(path.read_bytes(), data)
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(self.paths.packets).st_mode & 0o777, 0o700)
        self.assertEqual(self.runner.stage_packet(self.paths, self.stream(data))[0], path, "idempotent")

    def test_over_the_cap_is_refused_and_nothing_staged(self):
        with self.assertRaises(core.Refused):
            self.runner.stage_packet(self.paths, self.stream(b"x" * (core.PACKET_MAX_BYTES + 1)))
        self.assertFalse(self.paths.packets.exists() and list(self.paths.packets.iterdir()))

    def test_sha_mismatch_is_refused(self):
        with self.assertRaises(core.Refused) as caught:
            self.runner.stage_packet(self.paths, self.stream(b"abc"), expect_sha="0" * 64)
        self.assertIn("not the expected", str(caught.exception))
        self.assertFalse(self.paths.packets.exists() and list(self.paths.packets.iterdir()))

    def test_cli_submit_from_stdin_admits_and_echoes_sha(self):
        import contextlib
        import io
        from unittest import mock
        data = ("head %s\n```\n$ python3 -m unittest\nRan 1 test\nOK\nexit 0\n```\n" % HEAD).encode()
        stdin = mock.Mock()
        stdin.buffer = io.BytesIO(data)
        out = io.StringIO()
        argv = ["submit", "--repo", REPO, "--pr", "7", "--head", HEAD, "--base", BASE, "--packet", "-",
                "--ticket", "GoodQA goodqa#16034", "--owner", "agent-abc123",
                "--expect-sha", hashlib.sha256(data).hexdigest()]
        (self.paths.root).mkdir(parents=True, exist_ok=True)
        (self.paths.root / "config.json").write_text(json.dumps(self.config))
        with mock.patch.object(Path, "home", return_value=self.home), mock.patch.object(sys, "stdin", stdin), \
                contextlib.redirect_stdout(out):
            rc = self.runner.main(argv)
        self.assertEqual(rc, 0, out.getvalue())
        result = json.loads(out.getvalue())
        self.assertEqual(result["packet_sha256"], hashlib.sha256(data).hexdigest())
        self.assertFalse(result["duplicate"])


class SubmitTests(Base):
    def test_valid_request_is_queued_once(self):
        first = core.submit(self.paths, self.config, self.request())
        again = core.submit(self.paths, self.config, self.request())
        self.assertEqual(first["id"], again["id"])
        self.assertTrue(again["duplicate"])
        self.assertEqual(self.admitted(), [first["id"]])
        self.assertEqual(list(self.paths.queue.glob("*.json")) if self.paths.queue.exists() else [], [],
                         "v4 F2: admission is a ledger row, never a queue file")

    def admitted(self):
        import ahc_runner
        ledger = ahc_runner.Ledger(self.paths)
        try:
            return [r["id"] for r in ledger.db.execute("SELECT id FROM items ORDER BY id")]
        finally:
            ledger.close()

    def test_ledger_is_private(self):
        core.submit(self.paths, self.config, self.request())
        mode = os.stat(self.paths.root / "ledger.sqlite3").st_mode & 0o777
        self.assertEqual(mode, 0o600)

    def refused(self, **over):
        with self.assertRaises(core.Refused):
            core.submit(self.paths, self.config, self.request(**over))
        self.assertEqual(self.admitted() if (self.paths.root / "ledger.sqlite3").exists() else [], [])

    def test_short_head_refused(self):
        self.refused(head="abc1234")

    def test_uppercase_or_newline_head_refused(self):
        self.refused(head=HEAD.upper())
        self.refused(head=HEAD + "\n")

    def test_repo_not_allowlisted_refused(self):
        self.refused(repo="someone/else")

    def test_packet_outside_work_roots_refused(self):
        outside = self.home / "elsewhere.md"
        outside.write_text(HEAD)
        self.refused(packet=str(outside))

    def test_symlinked_packet_refused(self):
        link = self.work / "link.md"
        link.symlink_to(self.packet)
        self.refused(packet=str(link))

    def test_oversized_packet_refused(self):
        self.packet.write_text("x" * 150_001)
        self.refused()

    def test_bad_ticket_and_owner_refused(self):
        self.refused(ticket="#16034; rm -rf /")
        self.refused(owner="agent abc")


class ResolveTests(Base):
    def test_matching_live_pr_resolves(self):
        got = core.resolve(self.request(), Fake(live_pr()))
        self.assertEqual((got["head"], got["base"]), (HEAD, BASE))

    def test_head_moved_is_stale(self):
        with self.assertRaises(core.Stale):
            core.resolve(self.request(), Fake(live_pr(headRefOid="c" * 40)))

    def test_closed_pr_refused(self):
        with self.assertRaises(core.Refused):
            core.resolve(self.request(), Fake(live_pr(state="MERGED")))

    def test_base_moved_is_repaired_with_a_note(self):
        # D4 ruling: main advancing after submit is not the owner's error; the live base wins and is recorded.
        got = core.resolve(self.request(), Fake(live_pr(baseRefOid="d" * 40)))
        self.assertEqual(got["base"], "d" * 40)
        self.assertIn(BASE[:12], got["base_repaired_from"])

    def test_gh_failure_is_retryable_not_pass(self):
        with self.assertRaises(core.Retry):
            core.resolve(self.request(), Fake(rc=1))

    def test_gh_argv_has_no_shell(self):
        fake = Fake(live_pr())
        core.resolve(self.request(), fake)
        self.assertEqual(fake.calls[0][:4], ["gh", "pr", "view", "7"])
        self.assertIn("-R", fake.calls[0])


def report(head=HEAD, packet_sha="0" * 64, stage="pr", verdict="PASS"):
    return (f"Reviewer: Codex x\nStage: {stage}\nReviewed HEAD: {head}\nReviewed repository: {REPO}\n"
            f"Reviewed PR: 7\nReviewed packet SHA-256: {packet_sha}\n\nVERDICT: {verdict}\n\nbody\n")


class ReceiptTests(Base):
    def setUp(self):
        super().setUp()
        self.sha = hashlib.sha256(self.packet.read_bytes()).hexdigest()

    def check(self, text, rc=0):
        out = self.work / "r.md"
        out.write_text(text)
        return core.verify_receipt(rc, out, HEAD, self.packet)

    def test_pass_receipt_accepted(self):
        self.assertEqual(self.check(report(packet_sha=self.sha))["verdict"], "PASS")

    def test_block_receipt_is_block(self):
        self.assertEqual(self.check(report(packet_sha=self.sha, verdict="BLOCK"))["verdict"], "BLOCK")

    def test_wrong_head_invalid(self):
        self.assertEqual(self.check(report(head="c" * 40, packet_sha=self.sha))["verdict"], "INVALID")

    def test_wrong_packet_sha_invalid(self):
        self.assertEqual(self.check(report(packet_sha="1" * 64))["verdict"], "INVALID")

    def test_wrong_stage_invalid(self):
        self.assertEqual(self.check(report(packet_sha=self.sha, stage="plan"))["verdict"], "INVALID")

    def test_nonzero_exit_never_pass(self):
        self.assertEqual(self.check(report(packet_sha=self.sha), rc=1)["verdict"], "ERROR")

    def test_pass_with_tickets_is_not_pass(self):
        got = self.check(report(packet_sha=self.sha, verdict="PASS-WITH-TICKETS"))
        self.assertEqual(got["verdict"], "PASS-WITH-TICKETS")

    def test_real_block_exit_3_is_block_not_error(self):
        self.assertEqual(self.check(report(packet_sha=self.sha, verdict="BLOCK"), rc=3)["verdict"], "BLOCK")

    def test_pass_verdict_with_exit_3_is_never_pass(self):
        self.assertEqual(self.check(report(packet_sha=self.sha), rc=3)["verdict"], "ERROR")

    def test_advisory_exit_4_is_advisory(self):
        self.assertEqual(self.check(report(packet_sha=self.sha), rc=4)["verdict"], "ADVISORY")

    def test_exit_2_is_error_even_with_a_report(self):
        self.assertEqual(self.check(report(packet_sha=self.sha), rc=2)["verdict"], "ERROR")

    def test_block_with_wrong_head_is_invalid(self):
        self.assertEqual(self.check(report(head="c" * 40, packet_sha=self.sha, verdict="BLOCK"), rc=3)["verdict"],
                         "INVALID")

    # code-inspection r1 F4: only the authoritative verdict line after the header block counts
    def test_pr_result_marker_is_not_a_verdict(self):
        text = report(packet_sha=self.sha).replace("VERDICT: PASS", "PR_RESULT: PASS")
        self.assertEqual(self.check(text)["verdict"], "INVALID")

    def test_quoted_pass_further_down_is_not_a_verdict(self):
        text = report(packet_sha=self.sha).replace("VERDICT: PASS", "Summary first") + "Example:\nVERDICT: PASS\n"
        self.assertEqual(self.check(text)["verdict"], "INVALID")

    def test_pass_with_trailing_text_is_not_pass(self):
        text = report(packet_sha=self.sha).replace("VERDICT: PASS", "VERDICT: PASS / BLOCK")
        self.assertNotEqual(self.check(text)["verdict"], "PASS")

    def test_prefixed_pass_is_not_pass(self):
        text = report(packet_sha=self.sha).replace("VERDICT: PASS", "[marker omitted] VERDICT: PASS")
        self.assertEqual(self.check(text)["verdict"], "INVALID")

    def test_duplicate_header_is_invalid(self):
        text = report(packet_sha=self.sha).replace("Stage: pr\n", "Stage: pr\nReviewed HEAD: " + "c" * 40 + "\n")
        self.assertEqual(self.check(text)["verdict"], "INVALID")

    def test_header_in_body_does_not_count(self):
        text = report(head="c" * 40, packet_sha=self.sha).replace("body\n", "Reviewed HEAD: %s\n" % HEAD)
        self.assertEqual(self.check(text)["verdict"], "INVALID")

    def test_block_with_trailing_text_is_block(self):
        text = report(packet_sha=self.sha, verdict="BLOCK - see F1")
        self.assertEqual(self.check(text, rc=3)["verdict"], "BLOCK")

    def test_missing_report_is_error(self):
        self.assertEqual(core.verify_receipt(0, self.work / "none.md", HEAD, self.packet)["verdict"], "ERROR")


class ReadRegularTests(Base):
    """r3 class fix: read_regular never follows a link, never blocks on a FIFO and never reads past its cap."""

    def setUp(self):
        super().setUp()
        import signal

        def blocked(signum, frame):
            raise AssertionError("read_regular blocked")
        self._old = signal.signal(signal.SIGALRM, blocked)
        signal.alarm(10)

    def tearDown(self):
        import signal
        signal.alarm(0)
        signal.signal(signal.SIGALRM, self._old)
        super().tearDown()

    def kind(self, path, cap=100, **kw):
        with self.assertRaises(core.Unreadable) as ctx:
            core.read_regular(path, cap, **kw)
        return ctx.exception.kind

    def test_regular_file_within_cap_is_read(self):
        self.assertEqual(core.read_regular(self.packet, 1000), self.packet.read_bytes())

    def test_absent_symlink_fifo_and_oversize_are_refused(self):
        self.assertEqual(self.kind(self.work / "missing"), "absent")
        link = self.work / "link"
        link.symlink_to(self.packet)
        self.assertEqual(self.kind(link, 1000), "symlink")
        fifo = self.work / "fifo"
        os.mkfifo(fifo)
        self.assertEqual(self.kind(fifo), "non-regular")
        self.assertEqual(self.kind(self.work), "non-regular")
        self.assertEqual(self.kind(self.packet, cap=5), "oversize")

    def test_dir_fd_relative_read(self):
        fd = os.open(str(self.work), os.O_RDONLY)
        try:
            self.assertEqual(core.read_regular("packet.md", 1000, dir_fd=fd), self.packet.read_bytes())
            os.mkfifo(self.work / "f2")
            self.assertEqual(self.kind("f2", dir_fd=fd), "non-regular")
        finally:
            os.close(fd)

    def test_fifo_report_is_not_a_verdict(self):
        fifo = self.work / "r.md"
        os.mkfifo(fifo)
        self.assertEqual(core.verify_receipt(0, fifo, HEAD, self.packet)["verdict"], "INVALID")


def _lands_a_pr(argv):
    """True when a child argv would land (merge) a PR or push to a branch: the AC-31 surface P0 must never reach."""
    words = [str(a) for a in argv]
    for i, word in enumerate(words[:-1]):
        if word == "pr" and words[i + 1] == "merge":
            return True
    if "api" in words and any(re.search(r"/pulls/\d+/merge\b|/merges\b", w) for w in words):
        return True
    if words and os.path.basename(words[0]) == "git" and ("push" in words or "merge" in words):
        return True
    return False


class P0SurfaceTests(unittest.TestCase):
    """AC-31 (P0): P0 never executes a merge and has no `authority enable` subcommand. A suggested merge command in the
    notice for main is text inside a ticket-comment body, never an argv."""

    ALLOWED_AH = {("ticket", "comment"), ("alert", "raise"), ("alert", "clear"), ("heartbeat", "beat")}

    class Recorder:
        def __init__(self, verdict="PASS", review_rc=0, code=None, pr_head=HEAD):
            self.verdict, self.review_rc, self.code, self.pr_head = verdict, review_rc, code, pr_head
            self.argvs = []
            self.now = 1_800_000_000.0

        def gh(self, argv, timeout):
            self.argvs.append(list(argv))
            return 0, json.dumps(live_pr(headRefOid=self.pr_head)), ""

        def clone(self, repo, head, base):
            self.argvs.append(["git", "clone", repo])
            return "/clones/x"

        def merge_base(self, clone, head, base):
            self.argvs.append(["git", "merge-base", head, base])
            return base

        def changed_paths(self, clone, merge_base, head):
            self.argvs.append(["git", "diff", "--name-only", merge_base, head])
            return ["docs/x.md"]

        def review(self, argv, timeout):
            self.argvs.append(list(argv))
            if self.code:
                return 2, "REVIEW_DIAGNOSTIC code=%s reason=x" % self.code
            out = Path(argv[argv.index("--output") + 1])
            packet = Path(argv[argv.index("--packet") + 1])
            sha = hashlib.sha256(packet.read_bytes()).hexdigest()
            out.write_text(f"Stage: pr\nReviewed HEAD: {HEAD}\nReviewed packet SHA-256: {sha}\n\n"
                           f"VERDICT: {self.verdict}\n\nF1 - High - x\n")
            return self.review_rc

        def ah(self, argv, timeout):
            self.argvs.append(list(argv))
            return 0, "{}", ""

        def clock(self):
            return self.now

    def setUp(self):
        import ahc_runner
        self.runner = ahc_runner
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)
        self.paths = core.Paths(self.home)
        work = self.home / ".agent-harness" / "work" / "s"
        work.mkdir(parents=True)
        self.packet = work / "p.md"
        self.packet.write_text(f"head {HEAD}\n```\n$ python3 -m unittest\nRan 1 test\nOK\nexit 0\n```\n")
        self.config = {"repos": [REPO], "work_roots": [str(work.parent)]}

    def tearDown(self):
        self.tmp.cleanup()

    def drive(self, rec, ticks=3):
        req = {"repo": REPO, "pr": 7, "head": HEAD, "base": BASE, "packet": str(self.packet),
               "ticket": "GoodQA goodqa#16034", "owner": "agent-abc123"}
        core.submit(self.paths, self.config, req)
        for _ in range(ticks):
            self.runner.tick(self.paths, self.config, rec)
            rec.now += 5 * 3600   # cross retry, ack and routed escalation deadlines
        return rec.argvs

    def assert_no_merge(self, argvs):
        self.assertTrue(argvs, "the fake recorded nothing; the test would be vacuous")
        for argv in argvs:
            self.assertFalse(_lands_a_pr(argv), "P0 executed a merge/landing argv: %r" % (argv,))
            if argv and argv[0] == "ah":
                self.assertIn(tuple(argv[1:3]), self.ALLOWED_AH, "unexpected ah call %r" % (argv[:3],))

    def test_pass_flow_never_merges_and_only_suggests_text(self):
        argvs = self.drive(self.Recorder(verdict="PASS"))
        self.assert_no_merge(argvs)
        bodies = [a[a.index("--body") + 1] for a in argvs if a[:3] == ["ah", "ticket", "comment"]]
        self.assertTrue(any("--match-head-commit" in b for b in bodies) or
                        "--match-head-commit" in self.paths.digest.read_text(),
                        "the suggested command for main should still be offered as text")

    def test_block_stale_and_error_flows_never_merge(self):
        for rec in (self.Recorder(verdict="BLOCK", review_rc=3), self.Recorder(pr_head="c" * 40),
                    self.Recorder(code="PROVIDER_AUTH"), self.Recorder(code="PROVIDER_INVALID_OUTPUT"),
                    self.Recorder(verdict="PASS-WITH-TICKETS")):
            with self.subTest(verdict=rec.verdict, code=rec.code, head=rec.pr_head[:4]):
                self.tearDown()
                self.setUp()
                self.assert_no_merge(self.drive(rec))

    def test_source_has_no_merge_argv_literal(self):
        import ast
        for name in ("ahc_core.py", "ahc_runner.py", "ahc_clone.py", "ahc_packet.py"):
            tree = ast.parse((HOOKS / name).read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    self.assertNotEqual(node.value.strip(), "merge", "%s has a bare 'merge' argv element" % name)
                    self.assertIsNone(re.search(r"/pulls/[^ ]*/merge\b", node.value), name)
                    self.assertNotEqual(node.value.strip(), "push", "%s has a bare 'push' argv element" % name)

    def test_cli_has_no_enable_or_merge_subcommand(self):
        parser = self.runner.build_parser()
        actions = [a for a in parser._actions if a.__class__.__name__ == "_SubParsersAction"]
        self.assertEqual(len(actions), 1)
        commands = set(actions[0].choices)
        self.assertEqual(commands, {"submit", "ack", "status", "run", "install", "uninstall"})
        for word in ("enable", "authority", "merge"):
            self.assertNotIn(word, commands)
        with self.assertRaises(SystemExit):
            with open(os.devnull, "w") as devnull:
                stderr, sys.stderr = sys.stderr, devnull
                try:
                    parser.parse_args(["authority", "enable"])
                finally:
                    sys.stderr = stderr

    AHC_SOURCES = ("ahc_core.py", "ahc_runner.py", "ahc_clone.py", "ahc_packet.py", "ahc_install.py",
                   "ahc_contracts.py")

    def stamp_violations(self, sources):
        """Narrowed AC-31 rule (spec owner ruling): ahc_* never puts a stamp, never adds a review waiver, never imports
        merge_gate or names its state, and takes only its own `ahc-dispose` stamp through core.DISPOSE_STAMP."""
        import ast
        bad = []
        for name, text in sources.items():
            tree = ast.parse(text)
            for node in ast.walk(tree):
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    mods = [a.name for a in node.names] + ([node.module] if isinstance(node, ast.ImportFrom) else [])
                    if any(m and m.split(".")[0] == "merge_gate" for m in mods):
                        bad.append("%s imports merge_gate" % name)
                if isinstance(node, ast.Constant) and isinstance(node.value, str) and (
                        node.value in ("review-auth", "mission-main") or "waiver" in node.value.lower()):
                    bad.append("%s names %r" % (name, node.value))
                if not isinstance(node, ast.Call):
                    continue
                func = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
                if func in ("put_stamp", "add_review_waiver", "drop_tool_stamps"):
                    bad.append("%s calls %s" % (name, func))
                if func == "take_stamp":
                    purpose = node.args[0] if node.args else None
                    ok = (isinstance(purpose, ast.Attribute) and purpose.attr == "DISPOSE_STAMP"
                          and isinstance(purpose.value, ast.Name) and purpose.value.id == "core")
                    if not ok:
                        bad.append("%s takes a stamp whose purpose is not core.DISPOSE_STAMP" % name)
        return bad

    def test_ahc_never_puts_stamps_or_waivers_and_takes_only_its_own(self):
        sources = {n: (HOOKS / n).read_text(encoding="utf-8") for n in self.AHC_SOURCES}
        self.assertEqual(self.stamp_violations(sources), [])
        self.assertEqual(core.DISPOSE_STAMP, "ahc-dispose")
        self.assertIn("take_stamp(core.DISPOSE_STAMP", sources["ahc_runner.py"], "the scan must see the one take")

    def test_stamp_scan_is_not_vacuous(self):
        runner_text = (HOOKS / "ahc_runner.py").read_text(encoding="utf-8")
        for broken in (runner_text.replace("take_stamp(core.DISPOSE_STAMP", 'take_stamp("review-auth"', 1),
                       runner_text.replace("take_stamp(core.DISPOSE_STAMP", "take_stamp(PURPOSE", 1),
                       runner_text + "\ndef _x():\n    caller_identity.put_stamp(core.DISPOSE_STAMP, [])\n",
                       runner_text + "\nimport merge_gate\n"):
            self.assertTrue(self.stamp_violations({"ahc_runner.py": broken}))

    def test_runtime_flow_leaves_main_stamps_unconsumed(self):
        """Put main's review-auth stamp for this PR and a mission-main stamp; run submit, review, BLOCK, ack and a
        disposition attempt through the real CLI claim path; both stamps must still be there."""
        import caller_identity
        os.environ["AH_HOME"] = str(self.home)
        self.addCleanup(os.environ.pop, "AH_HOME", None)
        caller_identity.put_stamp("review-auth", [REPO, 7], home=self.home)
        caller_identity.put_stamp("mission-main", ["set", "k"], home=self.home)
        folder = caller_identity.stamp_dir(self.home)
        before = sorted(p.name for p in folder.glob("*.json"))
        self.assertEqual(len(before), 2)
        rec = self.Recorder(verdict="BLOCK", review_rc=3)
        self.drive(rec, ticks=2)
        ledger = self.runner.Ledger(self.paths)
        try:
            iid, state = ledger.db.execute("SELECT id, state FROM items").fetchone()
        finally:
            ledger.close()
        self.assertEqual(state, "block-delivered", "the flow must reach BLOCK for the test to mean anything")
        self.runner.ack(self.paths, iid, "agent-abc123", now=rec.now)
        argv = ["ack", iid, "--owner", "main", "--disposition", "x"]
        self.assertFalse(self.runner.claim_main(argv), "no ahc-dispose stamp was put, so not main")
        self.assertEqual(sorted(p.name for p in folder.glob("*.json")), before, "main's stamps were consumed")
        # M-1 (goodqa#16049): the daemon's review is bound and unstamped, and the flow wrote no merge_gate waiver state
        reviews = [a for a in rec.argvs if "pr" in a and "--packet" in a]
        self.assertTrue(reviews, "the flow must have launched a review for this to mean anything")
        for argv in reviews:
            self.assertIn("--no-main-stamp", argv)
            self.assertEqual(argv[argv.index("--github-repo") + 1], REPO)
            self.assertNotIn("--author-harness", argv)
        state = self.home / ".agent-harness" / "state"
        self.assertFalse((state / "merge-gate-waivers.jsonl").exists(), "ahc never writes merge_gate waiver state")

    def test_detector_is_not_vacuous(self):
        self.assertTrue(_lands_a_pr(["gh", "pr", "merge", "7", "-R", REPO, "--merge"]))
        self.assertTrue(_lands_a_pr(["gh", "api", "-X", "PUT", "repos/%s/pulls/7/merge" % REPO]))
        self.assertTrue(_lands_a_pr(["git", "push", "origin", "HEAD:main"]))
        self.assertFalse(_lands_a_pr(["git", "merge-base", HEAD, BASE]))
        self.assertFalse(_lands_a_pr(["ah", "ticket", "comment", "t", "--body", "gh pr merge 7 --match-head-commit x"]))


if __name__ == "__main__":
    unittest.main()
