"""takeover.py: the retired-session predicate, claim and tombstone, candidates, recheck and secret hygiene (goodqa#16441).

Fake home directories, fake probes and fake remote evidence only: nothing here reaches ssh, ps or the real home."""
import datetime as dt
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
import ah_kill as ak  # noqa: E402
import takeover as tk  # noqa: E402

OLD = "01a2012f-bca0-78b0-8fc7-162587de5ee7"
CALLER = "6df7b63f-b062-4fa8-834a-f6bd857d0c54"
OTHER = "11111111-2222-3333-4444-555555555555"
NOW = dt.datetime(2026, 11, 23, 2, 9, 0, tzinfo=dt.timezone.utc).timestamp()
HOUR = 3600


def iso(epoch):
    return dt.datetime.fromtimestamp(epoch, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


EMPTY_REMOTE = {"version": 1, "host": "t2-dev", "flavors": [], "problems": [], "live": [], "worktrees": [],
                "walless": {"exists": False}, "transcript": False}


def row(pid, ppid=100, start=NOW - 10 * HOUR, command="/usr/bin/sleep 300", comm=None):
    return {"ppid": ppid, "start": start, "command": command, "comm": comm if comm is not None else command.split(" ")[0]}


class FakeHost:
    """The takeover probe interface plus the ah_kill.Probe calls the candidate predicate makes."""
    host = "local"

    def __init__(self, table=None, cwds=None, pairs=None, fail=False):
        self.table, self.cwds, self.pairs, self.fail = dict(table or {}), dict(cwds or {}), dict(pairs or {}), fail
        self.sent = []

    def proc_table(self):
        if self.fail:
            raise tk.ProbeFailed("ps")
        return {pid: dict(r) for pid, r in self.table.items()}

    def cwd_scan(self):
        if self.fail:
            raise tk.ProbeFailed("lsof")
        return dict(self.cwds)

    def env_pairs(self, pids):
        return {p: set(self.pairs.get(p, ())) for p in pids}

    def session_pairs(self, pid):
        return set(self.pairs.get(pid, ()))

    def info(self, pid):
        r = self.table.get(pid)
        if not r:
            return None
        return {"pid": pid, "ppid": r["ppid"], "uid": os.getuid(), "stat": "S", "comm": r["comm"], "command": r["command"],
                "start": __import__("time").strftime("%a %b %e %H:%M:%S %Y", __import__("time").localtime(r["start"]))}


class TakeoverCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(os.path.realpath(self.tmp.name))
        self.tasks = []
        self.probe = FakeHost()

    # ---- fixtures
    def touch(self, path, epoch):
        os.utime(path, (epoch, epoch))

    def jsonl(self, path, rows, epoch):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("".join(json.dumps(r) + "\n" for r in rows))
        self.touch(path, epoch)

    def append(self, path, rows, epoch=None):
        with open(path, "a") as handle:
            for r in rows:
                handle.write(json.dumps(r) + "\n")
        self.touch(path, NOW - 2 * HOUR if epoch is None else epoch)

    def claude_session(self, sid=OLD, last_event="handoff", at=NOW - 2 * HOUR, transcript=True, transcript_at=None):
        wal = self.home / ".claude" / "wals" / sid
        self.jsonl(wal / "main.jsonl", [{"at": iso(at - 60), "event": "intent"}, {"at": iso(at), "event": last_event}], at)
        if transcript:
            when = at if transcript_at is None else transcript_at
            self.jsonl(self.home / ".claude" / "projects" / "-p" / (sid + ".jsonl"), [{"timestamp": iso(when)}], at)
        (self.home / ".agent-harness" / "work" / sid).mkdir(parents=True, exist_ok=True)
        return wal

    def codex_session(self, sid=OLD, state="handoff", at=NOW - 2 * HOUR, rollout=True, rollout_stamp=None, rollout_mtime=None):
        wal = self.home / ".agent-harness" / "codex-wals" / sid
        self.jsonl(wal / "main.jsonl", [{"at": iso(at), "event": "PreToolUse"}], at)
        (wal / "continuation.json").write_text(json.dumps({"interrupt": None, "state": state, "used": False}))
        self.touch(wal / "continuation.json", at)
        if rollout:
            path = self.home / ".codex" / "sessions" / "2026" / "11" / "21" / ("rollout-2026-11-21T19-57-15-%s.jsonl" % sid)
            self.jsonl(path, [{"timestamp": iso(rollout_stamp if rollout_stamp is not None else at)}],
                       rollout_mtime if rollout_mtime is not None else at)
        (self.home / ".agent-harness" / "work" / sid).mkdir(parents=True, exist_ok=True)
        return wal

    def state(self, action="worktrees", old=OLD, now=NOW, remote=EMPTY_REMOTE, **kw):
        kw.setdefault("tasks_fn", lambda home: list(self.tasks))
        return tk.session_state(old, action, self.home, self.probe, now, remote, **kw)


class Predicate(TakeoverCase):
    def test_codex_handoff_older_than_an_hour_is_retired_for_worktrees_but_not_processes(self):
        self.codex_session()
        out = self.state("worktrees")
        self.assertEqual((out["state"], out["reasons"]), ("retired", []), out)
        out = self.state("processes")
        self.assertEqual((out["state"], out["reasons"]), ("live", ["recent_activity"]), out)
        self.assertEqual(out["eligible_at"], iso(NOW - 2 * HOUR + 4 * HOUR))
        self.assertEqual(self.state("processes", now=NOW + 3 * HOUR)["state"], "retired")

    def test_the_incident_timestamps_give_the_documented_eligibility(self):
        at = dt.datetime(2026, 11, 23, 1, 26, 9, tzinfo=dt.timezone.utc).timestamp()
        self.codex_session(at=at)
        out = self.state("worktrees")
        self.assertEqual(out["reasons"], ["recent_activity"])
        self.assertEqual(out["eligible_at"], "2026-11-23T02:26:09Z")
        self.assertEqual(self.state("processes")["eligible_at"], "2026-11-23T05:26:09Z")

    def test_claude_needs_a_handoff_row_or_a_claim_and_a_result_row_never_counts(self):
        self.claude_session(last_event="result")
        self.assertEqual(self.state()["reasons"], ["not_stopped"])
        self.claude_session(last_event="handoff")
        self.assertEqual(self.state()["state"], "retired")

    def test_hook_rows_after_a_handoff_do_not_hide_it(self):
        wal = self.claude_session(last_event="handoff")
        self.append(wal / "main.jsonl", [{"at": iso(NOW - 2 * HOUR), "event": "prompt"}])
        self.assertEqual(self.state()["state"], "retired")

    def test_active_blocked_and_paused_checkpoints_are_not_stopped(self):
        for value in ("active", "blocked", "paused"):
            self.codex_session(state=value)
            self.assertEqual(self.state()["reasons"], ["not_stopped"], value)

    def test_missing_transcript_is_unknown(self):
        self.codex_session(rollout=False)
        out = self.state()
        self.assertEqual((out["state"], out["reasons"]), ("unknown", ["transcript_missing"]), out)

    def test_each_activity_source_counts(self):
        # the newest of WAL, continuation, rollout mtime and the rollout's last-line stamp decides
        self.codex_session(rollout_stamp=NOW - 10 * 60)
        self.assertEqual(self.state()["reasons"], ["recent_activity"], "a backdated mtime cannot hide a newer last-line stamp")
        self.codex_session(rollout_mtime=NOW - 10 * 60)
        self.assertEqual(self.state()["reasons"], ["recent_activity"])
        wal = self.codex_session()
        self.touch(wal / "continuation.json", NOW - 5 * 60)
        self.assertEqual(self.state()["reasons"], ["recent_activity"])
        wal = self.codex_session()
        self.jsonl(wal / "agent-x.jsonl", [{"at": iso(NOW - 60)}], NOW - 60)
        self.assertEqual(self.state()["reasons"], ["recent_activity"])

    def test_claude_transcript_and_subagent_transcripts_count(self):
        self.claude_session(transcript_at=NOW - 60)
        self.assertEqual(self.state()["reasons"], ["recent_activity"])
        self.claude_session()
        self.jsonl(self.home / ".claude" / "projects" / "-p" / OLD / "subagents" / "a.jsonl", [{"timestamp": iso(NOW - 30)}], NOW - 30)
        self.assertEqual(self.state()["reasons"], ["recent_activity"])

    def test_future_timestamps_are_clock_skew(self):
        self.codex_session(rollout_stamp=NOW + 3600)
        out = self.state()
        self.assertEqual((out["state"], "clock_skew" in out["reasons"]), ("unknown", True), out)

    def test_marker_process_under_an_agent_host_is_live_whatever_else_it_carries(self):
        self.codex_session()
        self.probe = FakeHost(
            table={50: row(50, 1, command="/Applications/ChatGPT.app/Contents/MacOS/ChatGPT"), 51: row(51, 50, command="/bin/zsh -c x")},
            pairs={51: {("codex", OLD)}})
        with mock.patch.object(ak, "PLATFORM", "darwin"):
            out = self.state()
            self.assertEqual((out["state"], out["reasons"]), ("live", ["session_live"]), out)
            self.probe.pairs[51] = {("codex", OLD), ("claude", CALLER)}
            self.assertEqual(self.state()["reasons"], ["session_live"],
                             "no caller exemption: a second marker on the process does not hide the first")

    def test_a_cwd_inside_the_work_dir_alone_never_makes_a_session_live(self):
        self.codex_session()
        self.probe = FakeHost(table={60: row(60, 1)}, cwds={60: str(self.home / ".agent-harness/work" / OLD / "x")})
        self.assertEqual(self.state()["state"], "retired")

    def test_open_ask_task_or_job_is_open_work(self):
        wal = self.codex_session()
        self.append(wal / "main.jsonl", [{"at": iso(NOW - 3 * HOUR), "event": "ask", "id": "wask1"}])
        out = self.state()
        self.assertEqual((out["state"], out["reasons"]), ("live", ["open_work"]), out)
        self.assertEqual(out["open_work"]["asks"], ["wask1"])
        self.append(wal / "main.jsonl", [{"at": iso(NOW - 3 * HOUR), "event": "ask_resolved", "ref": "wask1"}])
        self.assertEqual(self.state()["state"], "retired")
        self.tasks = [{"task": "t1", "session": OLD, "latest_actor": "someone"}]
        self.assertEqual(self.state()["reasons"], ["open_work"])
        self.tasks = [{"task": "t1", "session": OLD, "latest_actor": "agent of " + CALLER}]
        self.assertEqual(self.state()["reasons"], ["open_work"], "an open task of the session blocks until it is disposed")
        self.tasks = [{"task": "t2", "session": OTHER, "latest_actor": None}]
        self.assertEqual(self.state()["state"], "retired")

    def test_unreadable_task_ledger_is_unknown(self):
        self.codex_session()

        def boom(home):
            raise OSError("no ledger")
        out = self.state(tasks_fn=boom)
        self.assertEqual((out["state"], "tasks_unreadable" in out["reasons"]), ("unknown", True), out)

    def test_probe_failure_is_unknown(self):
        self.codex_session()
        self.probe = FakeHost(fail=True)
        out = self.state()
        self.assertEqual((out["state"], out["reasons"]), ("unknown", ["probe_failed"]), out)

    def test_ambiguous_sessions_and_hosts(self):
        self.codex_session()
        self.claude_session()
        self.assertEqual(self.state()["reasons"], ["ambiguous_session"])
        self.tmp.cleanup()
        self.setUp()
        self.codex_session()
        remote = dict(EMPTY_REMOTE, flavors=["claude"])
        self.assertEqual(self.state(remote=remote)["reasons"], ["ambiguous_session"])

    def test_identity_rules(self):
        self.codex_session()
        self.assertEqual(self.state(old="Upper-CASE-id-0000")["reasons"], ["bad_id"])
        self.assertEqual(self.state(old="../../etc/passwd")["reasons"], ["bad_id"])

    def test_symlinked_work_dir_or_wal_dir_is_bad_dir(self):
        self.codex_session()
        work = self.home / ".agent-harness" / "work" / OLD
        work.rmdir()
        target = self.home / "elsewhere"
        target.mkdir()
        work.symlink_to(target)
        self.assertEqual(self.state()["reasons"], ["bad_dir"])

    def test_remote_must_be_reachable_and_the_same_version(self):
        self.codex_session()
        self.assertEqual(self.state(remote=None)["reasons"], ["origin_unreachable"])
        self.assertEqual(self.state(remote=dict(EMPTY_REMOTE, version=2))["reasons"], ["remote_version"])
        self.assertEqual(self.state(remote=tk.LOCAL_ONLY)["state"], "retired")

    def test_a_live_marker_process_on_the_remote_host_blocks(self):
        self.codex_session()
        remote = dict(EMPTY_REMOTE, live=[{"pid": 9, "start": 1, "ids": [OLD], "agent_host": True}])
        self.assertEqual(self.state(remote=remote)["reasons"], ["session_live"])

    def test_walless_route_for_worktrees_only(self):
        work = self.home / ".agent-harness" / "work" / OLD
        (work / "proj").mkdir(parents=True)
        self.touch(work / "proj", NOW - 2 * 86400)
        self.touch(work, NOW - 2 * 86400)
        out = self.state("worktrees")
        self.assertEqual((out["state"], out["reasons"]), ("walless", []), out)
        self.assertEqual(self.state("processes")["state"], "unknown")
        self.touch(work / "proj", NOW - 3600)
        self.assertEqual(self.state("worktrees")["reasons"], ["recent_activity"])
        self.touch(work / "proj", NOW - 2 * 86400)
        self.jsonl(self.home / ".claude" / "projects" / "-p" / (OLD + ".jsonl"), [{"timestamp": iso(NOW - 99 * HOUR)}], NOW - 99 * HOUR)
        self.assertEqual(self.state("worktrees")["state"], "unknown", "a transcript means the session existed: not walless")

    def test_a_host_judging_alone_never_calls_an_unseen_session_walless(self):
        # t2-dev holds an old work dir of a MAC session and has no WAL for it: only a two-host judgement may say walless
        work = self.home / ".agent-harness" / "work" / OLD
        (work / "proj").mkdir(parents=True)
        self.touch(work / "proj", NOW - 2 * 86400)
        self.touch(work, NOW - 2 * 86400)
        out = self.state("worktrees", remote=tk.LOCAL_ONLY)
        self.assertEqual((out["state"], out["reasons"]), ("unknown", ["origin_unreachable"]), out)
        self.assertEqual(self.state("worktrees")["state"], "walless", "with the other host's evidence it still is")

    def test_unknown_session_has_no_state(self):
        out = self.state(old="00000000-none-0000")
        self.assertEqual((out["state"], out["reasons"]), ("unknown", ["session_unknown"]))


class ClaimAndTombstone(TakeoverCase):
    TICKET = "GoodQA goodqa#16441"

    def setUp(self):
        super().setUp()
        self.kg = ak._kill_guard()
        self.kg.ensure_key(str(self.home))

    def write(self, **kw):
        return tk.write_claim(str(self.home), OLD, "claude", self.TICKET, NOW, "mac", **kw)

    def test_claim_file_is_private_and_signed(self):
        self.write()
        path = tk.claim_path(str(self.home), OLD)
        self.assertEqual(oct(os.stat(path).st_mode & 0o777), "0o600")
        self.assertEqual(oct(os.stat(os.path.dirname(path)).st_mode & 0o777), "0o700")
        claim, bad = tk.read_claim(str(self.home), OLD)
        self.assertEqual((claim["v"], bad), (2, False))
        self.assertNotIn("caller", claim, "a claim names no claimer: no tool knows its caller")

    def test_a_valid_claim_satisfies_r2_and_starts_the_quiet_clock(self):
        self.claude_session(last_event="result")
        self.assertEqual(self.state()["reasons"], ["not_stopped"])
        self.write()
        self.assertEqual(self.state()["reasons"], ["recent_activity"], "the claim time counts as activity")
        later = self.state(now=NOW + HOUR + 1)
        self.assertEqual(later["state"], "retired", later)

    def test_a_v1_claim_with_a_claimer_is_not_valid(self):
        self.claude_session(last_event="result")
        data = self.write()
        legacy = dict(data, v=1, caller=CALLER)
        legacy.pop("hmac")
        import hashlib
        import hmac as _hmac
        key = self.kg.read_key(str(self.home))
        legacy["hmac"] = _hmac.new(key, tk._canonical(legacy).encode(), hashlib.sha256).hexdigest()
        Path(tk.claim_path(str(self.home), OLD)).write_text(json.dumps(legacy))
        self.assertEqual(tk.read_claim(str(self.home), OLD), (None, True))
        self.assertEqual(self.state(now=NOW + 9 * HOUR)["reasons"], ["not_stopped"])

    def test_tampered_or_extra_field_claims_are_ignored(self):
        self.claude_session(last_event="result")
        self.write()
        path = tk.claim_path(str(self.home), OLD)
        data = json.loads(Path(path).read_text())
        for change in ({"flavor": "codex"}, {"extra": "x"}, {"ticket": "GoodQA x#1; rm -rf /"},
                       {"removed": ["/etc/passwd"]}, {"hmac": "0" * 64}):
            Path(path).write_text(json.dumps(dict(data, **change)))
            claim, bad = tk.read_claim(str(self.home), OLD)
            self.assertEqual((claim, bad), (None, True), change)
            self.assertEqual(self.state(now=NOW + 9 * HOUR)["reasons"], ["not_stopped"], change)
            self.assertIsNone(tk.render_notice(OLD, str(self.home))[0], change)

    def test_removed_paths_must_be_under_the_work_dir(self):
        path = str(self.home / ".agent-harness" / "work" / OLD / "t" / "w")
        self.write(removed=[path])
        claim, _bad = tk.read_claim(str(self.home), OLD)
        self.assertEqual(claim["removed"], [path])

    def test_bad_ticket_or_ids_are_refused(self):
        with self.assertRaises(tk.TakeoverError):
            tk.write_claim(str(self.home), OLD, "claude", "GoodQA x#1 $(id)", NOW, "mac")
        with self.assertRaises(tk.TakeoverError):
            tk.write_claim(str(self.home), "Bad Session", "claude", self.TICKET, NOW, "mac")

    def test_notice_text_is_fixed_and_has_no_free_text(self):
        self.write(removed=[str(self.home / ".agent-harness/work" / OLD / "a" / "b")], stopped=[{"pid": 5, "start": 6}])
        text, digest = tk.render_notice(OLD, str(self.home))
        self.assertIn("another session took over this session's work", text)
        self.assertNotIn(CALLER, text)
        self.assertIn("Stopped pids: 1.", text)
        self.assertEqual(len(digest), 16)
        self.assertNotIn("ignore previous", text)

    def test_update_keeps_the_claim_time_and_appends(self):
        first = self.write()
        later = tk.write_claim(str(self.home), OLD, "claude", self.TICKET, NOW + 500, "mac", claimed=False,
                               removed=[str(self.home / ".agent-harness/work" / OLD / "x")])
        self.assertEqual(later["claimed_at"], first["claimed_at"])
        self.assertEqual(len(later["removed"]), 1)


def git(cwd, *args):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1", GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@e.invalid",
               GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@e.invalid")
    done = subprocess.run(["git", *args], cwd=str(cwd), env=env, capture_output=True, text=True)
    if done.returncode:
        raise AssertionError("git %s: %s" % (" ".join(args), done.stderr))
    return done.stdout.strip()


class Candidates(TakeoverCase):
    def make_repo(self, parent):
        primary = parent / "primary"
        primary.mkdir(parents=True)
        git(primary, "init", "-q", "-b", "main")
        (primary / "a").write_text("1")
        git(primary, "add", "a")
        git(primary, "commit", "-q", "-m", "one")
        return primary

    def test_linked_worktrees_at_depth_one_and_two_only(self):
        work = self.home / ".agent-harness" / "work" / OLD
        primary = self.make_repo(work / "T")
        git(primary, "worktree", "add", "-q", "-b", "w2", str(work / "T" / "w2"))
        git(primary, "worktree", "add", "-q", "-b", "w1", str(work / "w1"))
        git(primary, "worktree", "add", "-q", "-b", "w3", str(work / "a" / "b" / "w3"))
        (work / "kit.json").write_text("{}")
        (work / "main.jsonl").write_text("{}\n")
        found = tk.worktree_candidates(OLD, str(self.home))
        paths = sorted(p for p, _c, _h in found)
        self.assertEqual(paths, sorted([str(work / "T" / "w2"), str(work / "w1")]))
        self.assertTrue(all(len(h) == 40 for _p, _c, h in found))
        self.assertNotIn(str(primary), paths, "a primary checkout is never a candidate")

    def test_symlinks_and_a_symlinked_work_dir_are_never_followed(self):
        work = self.home / ".agent-harness" / "work" / OLD
        primary = self.make_repo(self.home / "elsewhere")
        git(primary, "worktree", "add", "-q", "-b", "w", str(self.home / "elsewhere" / "w"))
        work.mkdir(parents=True)
        (work / "link").symlink_to(self.home / "elsewhere" / "w")
        self.assertEqual(tk.worktree_candidates(OLD, str(self.home)), [])

    def test_missing_work_dir_is_empty(self):
        self.assertEqual(tk.worktree_candidates(OLD, str(self.home)), [])


class ProcessCandidates(TakeoverCase):
    START = NOW - 10 * HOUR

    def table(self, extra=None):
        base = {1: row(1, 0, command="/sbin/launchd"), 2: row(2, 1, command="/usr/bin/zsh"),
                100: row(100, 2, command="/usr/bin/sleep 1", start=self.START),
                101: row(101, 2, command="/usr/bin/sleep 2", start=self.START),
                102: row(102, 2, command="/usr/bin/sleep 3", start=self.START)}
        base.update(extra or {})
        return base

    def cands(self, table, pairs, last=NOW - 2 * HOUR, spawns=None, exclude=(), spawn_start=None):
        self.probe = FakeHost(table=table, pairs=pairs)
        return tk.process_candidates(OLD, str(self.home), self.probe, last, table=table, spawns=spawns,
                                     spawn_start=spawn_start, exclude_pids=exclude)

    def test_marker_match_qualifies_and_nothing_else_does(self):
        found, _pred, basis = self.cands(self.table(), {100: {("codex", OLD)}, 101: {("claude", OTHER)}, 102: set()})
        self.assertEqual(found, {100: int(self.START)})
        self.assertEqual(basis, {100: "marker"})

    def test_cwd_alone_never_qualifies(self):
        work = str(self.home / ".agent-harness" / "work" / OLD / "x")
        self.probe = FakeHost(table=self.table(), cwds={100: work})
        found, _p, _b = tk.process_candidates(OLD, str(self.home), self.probe, NOW, table=self.table())
        self.assertEqual(found, {})

    def test_ledger_match_needs_no_other_marker(self):
        spawns = {(100, "S1"), (101, "S2")}
        found, _p, basis = self.cands(self.table(), {101: {("claude", OTHER)}}, spawns=spawns,
                                      spawn_start=lambda pid: {100: "S1", 101: "S2"}.get(pid))
        self.assertEqual(found, {100: int(self.START)})
        self.assertEqual(basis[100], "ledger")

    def test_started_after_last_activity_caller_marker_and_exclusions(self):
        late = {103: row(103, 2, start=NOW - HOUR)}
        found, _p, _b = self.cands(self.table(late), {100: {("codex", OLD)}, 103: {("codex", OLD)},
                                                       101: {("codex", OLD), ("claude", CALLER)}, 102: {("codex", OLD)}},
                                   exclude={102})
        self.assertEqual(found, {100: int(self.START)})

    def test_an_agent_host_or_a_descendant_of_one_is_never_a_candidate(self):
        table = self.table({200: row(200, 1, command="claude", comm="claude"), 201: row(201, 200, command="/usr/bin/node x")})
        found, _p, _b = self.cands(table, {200: {("claude", OLD)}, 201: {("claude", OLD)}, 100: {("claude", OLD)}})
        self.assertEqual(sorted(found), [100])

    def test_predicate_rechecks_a_fresh_snapshot(self):
        found, pred, _b = self.cands(self.table(), {100: {("codex", OLD)}})
        probe = self.probe
        info = probe.info(100)
        self.assertTrue(pred(probe, info))
        probe.pairs[100] = {("codex", OLD), ("claude", OTHER)}
        self.assertFalse(pred(probe, info), "another session's marker appeared")
        probe.pairs[100] = {("codex", OLD)}
        probe.table[2] = row(2, 1, command="claude", comm="claude")
        self.assertFalse(pred(probe, info), "an agent-host ancestor appeared")
        self.assertFalse(pred(probe, probe.info(101)), "not a candidate at all")

    def test_too_many_processes_is_probe_failed(self):
        table = {i: row(i, 2) for i in range(10, 10 + tk.ENV_READ_CAP + 5)}
        with self.assertRaises(tk.ProbeFailed):
            self.cands(table, {})


class Context(TakeoverCase):
    """cleanup(): plan, apply, recheck. The verifier and ah kill are fakes; their own checks have their own tests."""

    def setUp(self):
        super().setUp()
        ak._kill_guard().ensure_key(str(self.home))
        self.removed, self.kills = [], []
        work = self.home / ".agent-harness" / "work" / OLD
        self.paths = []
        for name in ("a", "b", "c"):
            path = work / "T" / name
            path.mkdir(parents=True)
            self.paths.append(str(path))
        self.codex_session()
        self.hold = {}

    def remove(self, host, path, reason, expect_head=None):
        self.removed.append((host, path, reason, expect_head))
        if self.on_remove:
            self.on_remove(path)
        return {"removed": path not in self.hold, "reason": self.hold.get(path, "")}

    on_remove = None

    def ctx(self, remote=EMPTY_REMOTE, **kw):
        out = tk.Context(self.home, probe=self.probe, now=lambda: NOW, remote_fetch=lambda old: remote,
                         remove=self.remove, kill_local=self.kill_local, kill_remote=self.kill_remote,
                         tasks_fn=lambda home: list(self.tasks), ticket_lookup=lambda t: True, host="mac", **kw)
        return out

    def kill_local(self, pids, reason, **kw):
        self.kills.append(("local", pids, reason, kw))
        return {"ok": True, "results": [{"pid": p, "status": "exited"} for p in pids]}

    def kill_remote(self, host, pids, reason, tree, grace, **kw):
        self.kills.append((host, pids, reason, kw))
        return {"ok": True, "results": []}

    def fake_candidates(self):
        return mock.patch.object(tk, "worktree_candidates", lambda old, home, run=None: [(p, "/repo", "a" * 40) for p in self.paths])

    def test_plan_lists_targets_and_changes_nothing(self):
        with self.fake_candidates():
            out = tk.cleanup(OLD, "worktrees", self.ctx(), "r", "GoodQA goodqa#16441")
        self.assertEqual((out["ok"], len(out["targets"]), self.removed), (True, 3, []))

    def test_apply_removes_through_the_verifier_with_expect_head_and_no_caller(self):
        self.hold[self.paths[1]] = "worktree is not clean"
        with self.fake_candidates():
            out = tk.cleanup(OLD, "worktrees", self.ctx(), "r", "GoodQA goodqa#16441", apply=True)
        self.assertEqual([r[1] for r in self.removed], self.paths)
        self.assertTrue(all(r[3] == "a" * 40 and "takeover of %s" % OLD in r[2] for r in self.removed))
        self.assertEqual(out["removed"], [self.paths[0], self.paths[2]])
        self.assertEqual(out["kept"][0]["why"], "worktree is not clean")
        claim, _bad = tk.read_claim(str(self.home), OLD)
        self.assertEqual(sorted(claim["removed"]), sorted([self.paths[0], self.paths[2]]), "the tombstone records what was removed")
        events = [json.loads(line)["event"] for line in (self.home / ".agent-harness" / "takeover-audit.jsonl").read_text().splitlines()]
        self.assertEqual(events[0], "request")
        self.assertIn("target", events)
        self.assertIn("result", events)

    def test_path_only_narrows(self):
        outside = str(self.home / ".agent-harness" / "work" / OLD / "kit.json")
        with self.fake_candidates():
            out = tk.cleanup(OLD, "worktrees", self.ctx(), "r", "GoodQA goodqa#16441", paths=[self.paths[0], outside, "/etc"], apply=True)
        self.assertEqual([r[1] for r in self.removed], [self.paths[0]])
        self.assertEqual(len(out["refused"]), 2)

    def test_a_session_that_is_not_retired_refuses_before_any_action(self):
        self.codex_session(state="active")
        with self.fake_candidates():
            out = tk.cleanup(OLD, "worktrees", self.ctx(), "r", "GoodQA goodqa#16441", apply=True)
        self.assertEqual((out["ok"], out["state"], self.removed), (False, "live", []))

    def test_recheck_between_targets_stops_the_run(self):
        wal = self.home / ".agent-harness" / "codex-wals" / OLD

        def late_activity(path):
            self.append(wal / "main.jsonl", [{"at": iso(NOW - 10), "event": "PreToolUse"}], NOW - 10)
        self.on_remove = late_activity
        with self.fake_candidates():
            out = tk.cleanup(OLD, "worktrees", self.ctx(), "r", "GoodQA goodqa#16441", apply=True)
        self.assertEqual(len(self.removed), 1, "the second target was refused by the re-check")
        self.assertIn("re-check", out["refused"][0]["why"])

    def test_apply_needs_a_ticket_that_exists(self):
        for ticket in ("nope", "GoodQA x#1; ls"):
            with self.assertRaises(tk.TakeoverError):
                tk.cleanup(OLD, "worktrees", self.ctx(), "r", ticket, apply=True)
        ctx = self.ctx()
        ctx.ticket_lookup = lambda t: False
        with self.assertRaises(tk.TakeoverError):
            tk.cleanup(OLD, "worktrees", ctx, "r", "GoodQA goodqa#16441", apply=True)

        def down(t):
            raise OSError("unreachable")
        ctx.ticket_lookup = down
        with self.assertRaises(tk.TakeoverError) as caught:
            tk.cleanup(OLD, "worktrees", ctx, "r", "GoodQA goodqa#16441", apply=True)
        self.assertEqual(caught.exception.code, "ticket_unreachable")

    def test_processes_use_candidates_expect_and_the_foreign_flag(self):
        self.codex_session(at=NOW - 6 * HOUR)
        table = {1: row(1, 0, command="/sbin/launchd"), 2: row(2, 1, command="/usr/bin/zsh"),
                 100: row(100, 2, start=NOW - 10 * HOUR), 101: row(101, 2, start=NOW - 10 * HOUR)}
        self.probe = FakeHost(table=table, pairs={100: {("codex", OLD)}, 101: {("codex", OTHER)}})
        out = tk.cleanup(OLD, "processes", self.ctx(), "r", "GoodQA goodqa#16441", apply=True)
        self.assertEqual(self.kills[0][1], [100])
        kw = self.kills[0][3]
        self.assertTrue(kw["foreign"])
        self.assertEqual(kw["expect"], {100: int(NOW - 10 * HOUR)})
        self.assertTrue(callable(kw["predicate"]))
        self.assertEqual(out["ok"], True)
        claim, _bad = tk.read_claim(str(self.home), OLD)
        self.assertEqual(claim["stopped"], [{"pid": 100, "start": int(NOW - 10 * HOUR)}])

    def test_processes_before_the_quiet_window_are_refused(self):
        out = tk.cleanup(OLD, "processes", self.ctx(), "r", "GoodQA goodqa#16441", apply=True)
        self.assertEqual((out["state"], self.kills), ("live", []))

    def test_remote_candidates_are_bounded_by_last_activity_and_forwarded_narrowed(self):
        self.codex_session(at=NOW - 6 * HOUR)
        self.probe = FakeHost(table={1: row(1, 0, command="/sbin/launchd")})
        remote = dict(EMPTY_REMOTE, process_candidates=[{"pid": 7, "start": int(NOW - 10 * HOUR)}, {"pid": 8, "start": int(NOW - HOUR)}])
        tk.cleanup(OLD, "processes", self.ctx(remote=remote), "r", "GoodQA goodqa#16441", apply=True)
        host, pids, _r, kw = self.kills[0]
        self.assertEqual((host, pids, kw["takeover_of"], kw["expect"]), ("t2-dev", [7], OLD, {7: int(NOW - 10 * HOUR)}))

    def test_stale_helpers_need_no_session(self):
        table = {1: row(1, 0), 300: row(300, 1, command="/Applications/ChatGPT.app/Contents/Frameworks/X Framework.framework/Versions/1.2/Helpers/browser_crashpad_handler --x",
                                       comm="/Applications/ChatGPT.app/Contents/Frameworks/X Framework.framework/Versions/1.2/Helpers/browser_crashpad_handler")}
        self.probe = FakeHost(table=table)
        with mock.patch.object(ak, "PLATFORM", "darwin"), mock.patch.object(ak, "stale_app_helper", lambda info, probe: {"ver": "1.2"}):
            out = tk.cleanup("none", "stale-helpers", self.ctx(), "old version", "GoodQA goodqa#16441", apply=True)
        self.assertEqual(self.kills[0][1], [300])
        self.assertTrue(self.kills[0][3]["foreign"])
        self.assertTrue(out["ok"])


class CLI(TakeoverCase):
    """The ah.py surface: `takeover` and the audited stop's --dry-run, through ah.main with a temporary AH_HOME."""

    def setUp(self):
        super().setUp()
        import ah
        self.ah = ah
        ak._kill_guard().ensure_key(str(self.home))

    def run_ah(self, *argv, caller=None, remote=EMPTY_REMOTE):
        import contextlib
        import io
        out = io.StringIO()
        env = {"AH_HOME": str(self.home), "HOME": str(self.home)}
        if caller:
            env["CLAUDE_CODE_SESSION_ID"] = caller
        # `caller` only sets a session variable: no tool reads it as an identity (test_takeover_identity)
        with mock.patch.dict(os.environ, env), mock.patch.object(tk, "HostProbe", lambda: self.probe), \
                mock.patch.object(tk, "fetch_remote_evidence", lambda old, **kw: remote), \
                mock.patch.object(tk, "default_tasks", lambda home: list(self.tasks)), contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(io.StringIO()):
            code = self.ah.main(list(argv))
        text = out.getvalue()
        return code, (json.loads(text) if text.strip().startswith("{") else text)

    def test_evidence_only_is_read_only_json_that_needs_no_caller(self):
        self.codex_session()
        code, data = self.run_ah("takeover", "status", "--from", OLD, "--evidence-only", "--json")
        self.assertEqual(code, 0, data)
        self.assertEqual((data["version"], data["flavors"], data["cont_state"], data["declared_stop"]), (1, ["codex"], "handoff", True))
        self.assertIn("process_candidates", data)
        self.assertFalse(Path(tk.claim_path(str(self.home), OLD)).exists())

    def test_status_reports_the_verdict_for_a_known_caller(self):
        self.codex_session()
        (self.home / ".claude" / "wals" / CALLER).mkdir(parents=True)
        with mock.patch.object(tk.time, "time", lambda: NOW):
            code, data = self.run_ah("takeover", "status", "--from", OLD, caller=CALLER)
        self.assertEqual((code, data["state"], data["reasons"]), (0, "retired", []), data)

    def test_on_t2_dev_status_and_plan_judge_a_local_session_through_ah(self):
        """F3 through the ah.py route an agent on t2-dev takes (fetch_remote_evidence answers LOCAL_ONLY there)."""
        self.codex_session()
        (self.home / ".claude" / "wals" / CALLER).mkdir(parents=True)
        work = self.home / ".agent-harness" / "work" / OLD / "T" / "a"
        with mock.patch.object(tk.time, "time", lambda: NOW), \
                mock.patch.object(tk, "worktree_candidates", lambda old, home, run=None: [(str(work), "/repo", "a" * 40)]):
            code, data = self.run_ah("takeover", "status", "--from", OLD, caller=CALLER, remote=tk.LOCAL_ONLY)
            self.assertEqual((code, data["state"], data["reasons"]), (0, "retired", []), data)
            code, data = self.run_ah("takeover", "plan", "--from", OLD, "--action", "worktrees", caller=CALLER, remote=tk.LOCAL_ONLY)
        self.assertEqual((code, data["targets"]), (0, [{"host": "local", "path": str(work), "head": "a" * 40}]), data)
        code, data = self.run_ah("takeover", "status", "--from", OTHER, caller=CALLER, remote=tk.LOCAL_ONLY)
        self.assertEqual(data["state"], "unknown", "a session whose WAL is not on t2-dev stays unknown there")

    def test_the_verdict_needs_no_caller_and_an_unknown_session_is_unknown(self):
        self.codex_session()
        with mock.patch.object(tk.time, "time", lambda: NOW):
            code, data = self.run_ah("takeover", "status", "--from", OLD)
        self.assertEqual((data["state"], data["reasons"]), ("retired", []), data)
        (self.home / ".claude" / "wals" / CALLER).mkdir(parents=True)
        code, data = self.run_ah("takeover", "status", "--from", "00000000-none", caller=CALLER)
        self.assertEqual((data["state"], data["reasons"]), ("unknown", ["session_unknown"]))

    def test_a_bad_id_and_a_missing_ticket_are_refused(self):
        code, data = self.run_ah("takeover", "status", "--from", "Bad/Id")
        self.assertNotEqual(code, 0)
        self.assertIn("bad_id", json.dumps(data))
        (self.home / ".claude" / "wals" / CALLER).mkdir(parents=True)
        code, data = self.run_ah("takeover", "cleanup", "--from", OLD, "--action", "worktrees", "--reason", "r",
                                 "--ticket", "nope", "--apply", caller=CALLER)
        self.assertNotEqual(code, 0)

    def test_dry_run_of_the_audited_stop_never_signals_and_takeover_of_needs_expect_start(self):
        sleeper = subprocess.Popen(["sleep", "30"])
        self.addCleanup(sleeper.wait)
        self.addCleanup(sleeper.terminate)
        code, data = self.run_ah("kill", "--dry-run", "--foreign", "--pid", str(sleeper.pid), "--reason", "probe")
        self.assertEqual((code, data["dry_run"], data["results"][0]["status"]), (0, True, "would-stop"), data)
        self.assertIsNone(sleeper.poll(), "a dry run must leave the process alone")
        code, data = self.run_ah("kill", "--dry-run", "--foreign", "--pid", str(sleeper.pid), "--reason", "probe", "--takeover-of", OLD)
        self.assertNotEqual(code, 0)
        self.assertIn("--expect-start", json.dumps(data))
        self.assertIsNone(sleeper.poll())


class LinuxCaller(TakeoverCase):
    """F3 (review BLOCK at db950737): a caller on t2-dev cannot see the Mac. It judges, claims and cleans a session whose
    WAL, transcript and work dir are on t2-dev from that host's evidence; only R4 for the Mac is unknowable (disclosed). A
    session whose WAL is not on t2-dev stays unknown there."""

    def local_only(self, old, **kw):
        return tk.fetch_remote_evidence(old, local_is_remote=True)

    def ctx(self, **kw):
        ak._kill_guard().ensure_key(str(self.home))
        self.removed = []

        def remove(host, path, reason, expect_head=None):
            self.removed.append((host, path))
            return {"removed": True}
        return tk.Context(self.home, probe=self.probe, now=kw.pop("now", lambda: NOW), remote_fetch=self.local_only,
                          remove=remove, tasks_fn=lambda home: [], ticket_lookup=lambda t: True, host="t2-dev", **kw)

    def test_a_caller_on_linux_judges_this_host_alone(self):
        self.assertEqual(tk.fetch_remote_evidence(OLD, local_is_remote=True), tk.LOCAL_ONLY)
        self.codex_session()
        self.assertEqual(self.state(remote=self.local_only(OLD))["state"], "retired")
        state, _remote = tk.status(OLD, "worktrees", self.ctx())
        self.assertEqual((state["state"], state["reasons"]), ("retired", []))

    def test_a_session_whose_wal_is_not_here_stays_unknown(self):
        (self.home / ".agent-harness" / "work" / OLD).mkdir(parents=True)
        out = self.state(remote=self.local_only(OLD))
        self.assertEqual((out["state"], out["reasons"]), ("unknown", ["origin_unreachable"]))

    def test_a_claim_on_linux_is_written_here_and_satisfies_r2_after_the_quiet_window(self):
        self.claude_session(last_event="intent")  # stopped on a usage limit without writing its own handoff row
        self.assertIn("not_stopped", self.state(remote=self.local_only(OLD))["reasons"])
        out = tk.claim(OLD, self.ctx(), "usage limit", "GoodQA goodqa#16441")
        self.assertTrue(out["claimed"])
        self.assertIsNotNone(tk.read_claim(str(self.home), OLD)[0])
        self.assertEqual(self.state(remote=self.local_only(OLD))["reasons"], ["recent_activity"], "the claim starts the wait")
        self.assertEqual(self.state(remote=self.local_only(OLD), now=NOW + 2 * HOUR)["state"], "retired")

    def test_cleanup_on_linux_removes_the_local_worktrees(self):
        self.codex_session()
        work = self.home / ".agent-harness" / "work" / OLD / "T" / "a"
        work.mkdir(parents=True)
        with mock.patch.object(tk, "worktree_candidates", lambda old, home, run=None: [(str(work), "/repo", "a" * 40)]):
            out = tk.cleanup(OLD, "worktrees", self.ctx(), "r", "GoodQA goodqa#16441", apply=True)
        self.assertEqual(out["removed"], [str(work)], out)
        self.assertEqual(self.removed, [("local", str(work))])

    def test_the_mac_still_sends_a_claim_of_a_t2_dev_session_to_that_host(self):
        remote = dict(EMPTY_REMOTE, flavors=["codex"], cont_state="active", transcript=True, last_activity=NOW - 2 * HOUR)
        ctx = tk.Context(self.home, probe=self.probe, now=lambda: NOW, remote_fetch=lambda old: remote,
                         tasks_fn=lambda home: [], ticket_lookup=lambda t: True, host="mac")
        with self.assertRaises(tk.TakeoverError) as caught:
            tk.claim(OLD, ctx, "r", "GoodQA goodqa#16441")
        self.assertEqual(caught.exception.code, "origin_remote")

    def test_r2_reads_the_claim_on_the_origin_host(self):
        remote = dict(EMPTY_REMOTE, flavors=["claude"], declared_stop=False, transcript=True, last_activity=NOW - 2 * HOUR,
                      claim={"claimed_at": NOW - 2 * HOUR})
        self.assertEqual(self.state(remote=remote)["state"], "retired")
        remote["claim"] = {"claimed_at": None}  # a tombstone update without a claim time is no claim
        self.assertIn("not_stopped", self.state(remote=remote)["reasons"])


class SessionRecordLiveness(TakeoverCase):
    """R4 (review minor, and the t2-dev half of F3): a Claude CLI's environment carries no session marker (macOS hides it;
    on t2-dev the CLI's comm is its version, `2.1.330`), so an idle Claude session looked dead. Its own
    ~/.claude/sessions/<pid>.json, bound to its start time, now makes it live."""

    class Probe(FakeHost):
        tokens = {}

        def start_token(self, pid):
            return self.tokens.get(pid)

        def exe_path(self, pid):
            return self.table.get(pid, {}).get("comm", "")

    def test_a_claude_cli_with_its_session_record_is_live(self):
        self.claude_session()
        exe = "/home/eric/.local/share/claude/versions/2.1.330"
        probe = self.Probe(table={300: row(300, 1, command=exe + " --print", comm=exe)})
        probe.tokens = {300: "18807376"}
        folder = self.home / ".claude" / "sessions"
        folder.mkdir(parents=True)
        (folder / "300.json").write_text(json.dumps({"pid": 300, "sessionId": OLD, "procStart": "18807376"}))
        self.probe = probe
        out = self.state()
        self.assertEqual((out["state"], out["reasons"]), ("live", ["session_live"]))
        probe.tokens = {300: "99999999"}  # the pid was reused: the record is stale
        self.assertEqual(self.state()["state"], "retired")

    def test_stale_records_of_exited_clis_do_not_count_toward_the_cap(self):
        self.claude_session()
        exe = "/home/eric/.local/share/claude/versions/2.1.330"
        probe = self.Probe(table={300: row(300, 1, command=exe, comm=exe)})
        probe.tokens = {300: "18807376"}
        folder = self.home / ".claude" / "sessions"
        folder.mkdir(parents=True)
        for pid in range(10000, 10000 + tk.SESSION_RECORD_CAP + 20):
            (folder / ("%d.json" % pid)).write_text(json.dumps({"pid": pid, "sessionId": OTHER, "procStart": "1"}))
        (folder / "300.json").write_text(json.dumps({"pid": 300, "sessionId": OLD, "procStart": "18807376"}))
        self.probe = probe
        self.assertEqual((self.state()["state"], self.state()["reasons"]), ("live", ["session_live"]))
        probe.table.update({pid: row(pid, 1, command=exe, comm=exe) for pid in range(10000, 10000 + tk.SESSION_RECORD_CAP + 1)})
        self.assertEqual(self.state()["reasons"], ["probe_failed"], "more live-pid records than the cap is unknown, never a cut")

    def test_a_record_of_a_process_that_is_not_a_claude_cli_proves_nothing(self):
        self.claude_session()
        exe = "/Users/u/.claude/hooks/claude"  # m3: a path component that contains "claude" is not the CLI
        probe = self.Probe(table={300: row(300, 1, command=exe, comm=exe)})
        probe.tokens = {300: "18807376"}
        folder = self.home / ".claude" / "sessions"
        folder.mkdir(parents=True)
        (folder / "300.json").write_text(json.dumps({"pid": 300, "sessionId": OLD, "procStart": "18807376"}))
        self.probe = probe
        self.assertEqual(self.state()["state"], "retired")

    def test_the_start_token_of_this_process_is_readable(self):
        token = tk.start_token(os.getpid())
        self.assertTrue(token and isinstance(token, str), token)


class TombstoneAndRemotePaths(TakeoverCase):
    def test_an_update_keeps_the_claim_time_and_a_new_claim_restarts_the_wait(self):
        ak._kill_guard().ensure_key(str(self.home))
        self.codex_session()
        tk.write_claim(str(self.home), OLD, "codex", "GoodQA goodqa#1", NOW - 3 * HOUR, "mac")
        path = str(self.home / ".agent-harness" / "work" / OLD / "x")
        tk.write_claim(str(self.home), OLD, "codex", "GoodQA goodqa#2", NOW, "mac", claimed=False, removed=[path])
        claim, _bad = tk.read_claim(str(self.home), OLD)
        self.assertEqual((claim["claimed_at"], claim["removed"]), (iso(NOW - 3 * HOUR), [path]))
        tk.write_claim(str(self.home), OLD, "codex", "GoodQA goodqa#2", NOW, "mac")
        ev = tk.collect_evidence(OLD, self.home, self.probe, NOW)
        self.assertEqual(ev["claim"]["claimed_at"], NOW, "a new claim is new activity: the quiet window starts again")

    def test_remote_worktree_paths_must_lie_under_the_sessions_work_dir(self):
        remote = {"worktrees": [{"path": "/home/eric/.agent-harness/work/%s/T/a" % OLD, "head": "a" * 40},
                                {"path": "/home/eric/.agent-harness/work/%s/b" % OLD, "head": "b" * 40},
                                {"path": "/etc/passwd", "head": "c" * 40},
                                {"path": "/home/eric/.agent-harness/work/%s/../x/y" % OLD, "head": "d" * 40},
                                {"path": "/home/eric/.agent-harness/work/%s" % OTHER + "/T/a", "head": "e" * 40},
                                {"path": "/home/eric/.agent-harness/work/%s/a/b/c" % OLD, "head": "f" * 40},
                                {"path": "/home/eric/.agent-harness/work/%s/T/a" % OLD, "head": "not-a-head"}]}
        self.assertEqual([p for p, _h in tk._remote_worktrees(remote, OLD)],
                         ["/home/eric/.agent-harness/work/%s/T/a" % OLD, "/home/eric/.agent-harness/work/%s/b" % OLD])


class RealProbe(unittest.TestCase):
    """HostProbe on this machine, read only, on a child this test starts (T3: does `ps eww` show an own process's marker)."""

    def test_the_scans_see_a_child_its_marker_and_its_directory(self):
        marker = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        with tempfile.TemporaryDirectory() as tmp:
            # a Python child, not /bin/sleep: macOS hides the environment of platform binaries from `ps eww` (T3)
            child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"], cwd=tmp,
                                     env=dict(os.environ, CLAUDE_CODE_SESSION_ID=marker))
            self.addCleanup(child.wait)
            self.addCleanup(child.terminate)
            probe = tk.HostProbe()
            table = probe.proc_table()
            self.assertEqual(table[child.pid]["ppid"], os.getpid())
            self.assertIsNotNone(table[child.pid]["start"])
            self.assertIn("time.sleep", table[child.pid]["command"])
            self.assertEqual(probe.env_pairs([child.pid])[child.pid], {("claude", marker)})
            self.assertEqual(os.path.realpath(probe.cwd_scan()[child.pid]), os.path.realpath(tmp))


class SecretHygiene(TakeoverCase):
    def test_a_token_in_a_process_environment_never_reaches_any_output(self):
        token = "sk-test-" + "A1b2C3d4E5f6G7h8I9j0"
        self.codex_session()
        self.probe = FakeHost(table={100: row(100, 2, command="/usr/bin/sleep 5 --api-key=" + token)}, pairs={100: {("codex", OLD)}})
        out = self.state("processes", now=NOW + 5 * HOUR)
        tk.audit(str(self.home), {"event": "request", "reason": "stop it, token=" + token, "session": OLD})
        blob = json.dumps(out) + (self.home / ".agent-harness" / "takeover-audit.jsonl").read_text()
        self.assertNotIn(token, blob)
        for path in self.home.rglob("*"):
            if path.is_file() and path.stat().st_size < 1 << 20:
                self.assertNotIn(token, path.read_text(errors="ignore"), str(path))


if __name__ == "__main__":
    unittest.main()
