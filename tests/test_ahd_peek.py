"""ahd_peek: discovery by stat, bounded redacted tail, follow across truncation and rotation, and the fail-closed
interview exclusion read from ahd_policy.json. Scratch HOME only; planted secrets must never be printed."""
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import ahd_peek as peek  # noqa: E402

ANT = "sk-ant-api03-" + "Q" * 40
AWS = "AKIA" + "ABCDEFGHIJKLMNOP"
SESSION = "11111111-2222-4333-8444-555555555555"


def tool_use(name, inp, ts="2027-01-15T08:00:00.000Z", cwd="/Users/x/repo"):
    return {"type": "assistant", "timestamp": ts, "cwd": cwd, "isSidechain": True,
            "message": {"content": [{"type": "tool_use", "name": name, "input": inp}]}}


def text(role, body, cwd="/Users/x/repo"):
    return {"type": role, "timestamp": "2027-01-15T08:00:01.000Z", "cwd": cwd,
            "message": {"content": [{"type": "text", "text": body}]}}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)
        self.env = mock.patch.dict(os.environ, {"HOME": str(self.home)})
        self.env.start()
        self.policy = peek.load_policy()
        self.proj = self.home / ".claude" / "projects" / "-Users-x-repo"

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def agent(self, aid, records, project=None, desc="build widget", raw_tail=b""):
        d = (project or self.proj) / SESSION / "subagents"
        d.mkdir(parents=True, exist_ok=True)
        p = d / f"agent-{aid}.jsonl"
        p.write_bytes(b"".join(json.dumps(r).encode() + b"\n" for r in records) + raw_tail)
        (d / f"agent-{aid}.meta.json").write_text(json.dumps({"agentType": "task-owner", "description": desc}))
        return p


class Policy(Base):
    def test_shipped_policy_has_the_interview_rule(self):
        ex = json.loads((HOOKS / "ahd_policy.json").read_text())["exclude"]
        self.assertIn("solve", ex["token_prefixes"])
        self.assertIn("interview", ex["token_prefixes"])
        self.assertIn("vm108", ex["hosts"])

    def test_classification(self):
        p = self.policy
        for t in ("/Users/someone/Library/Application Support/Interview Pilot/x.jsonl", "-Users-someone-work-solve-installers",
                  "Solver PR review", "/w/redteam-solve/a", "app.interviewpilot.mac"):
            self.assertTrue(peek.text_excluded(t, p), t)
        for t in ("resolve merge conflict", "/Users/someone/repo/harness", "absolve"):
            self.assertFalse(peek.text_excluded(t, p), t)
        self.assertTrue(peek.host_excluded("vm108", p))
        self.assertTrue(peek.host_excluded("interview-prep.lan", p))
        self.assertFalse(peek.host_excluded("dev2", p))

    def test_fail_closed(self):
        broken = {"exclude": None}
        self.assertTrue(peek.text_excluded("anything", broken))
        self.assertTrue(peek.path_excluded("/Users/x/ok.jsonl", broken))
        self.assertTrue(peek.text_excluded(12, self.policy))  # unclassifiable value
        self.assertTrue(peek.path_excluded("relative/path.jsonl", self.policy))
        self.assertTrue(peek.path_excluded("/elsewhere/a.jsonl", self.policy, roots=peek.roots()))
        missing = peek.load_policy(self.home / "nope.json")
        self.assertIsNone(missing["exclude"])

    def test_symlink_into_interview_dir_is_excluded(self):
        target = self.home / "Interview Pilot"
        target.mkdir()
        (target / "t.jsonl").write_text("{}\n")
        self.proj.mkdir(parents=True)
        link = self.proj / "x.jsonl"
        link.symlink_to(target / "t.jsonl")
        self.assertTrue(peek.path_excluded(str(link), self.policy, roots=peek.roots()))


class ListAndTail(Base):
    def test_list_is_stat_only_and_hides_excluded_details(self):
        self.agent("a1111111111111111", [text("user", "hi")])
        self.agent("a2222222222222222", [text("user", "x")], desc="Solve capture fix")
        solve_proj = self.home / ".claude" / "projects" / "-Users-x-work-solve-floor"
        self.agent("a3333333333333333", [text("user", "y")], project=solve_proj)
        real_open = open
        opened = []

        def spy(f, *a, **k):
            opened.append(str(f))
            return real_open(f, *a, **k)

        with mock.patch("builtins.open", spy):
            rows = {r["id"]: r for r in peek.discover(self.policy, include_all=True)}
        self.assertFalse([f for f in opened if f.endswith(".jsonl")], "list must not open a transcript")
        self.assertFalse(rows["c:a1111111111111111"]["excluded"])
        for rid in ("c:a2222222222222222", "c:a3333333333333333"):
            self.assertTrue(rows[rid]["excluded"])
            self.assertNotIn("path", rows[rid])
            self.assertNotIn("description", rows[rid])
            self.assertNotIn("olve", json.dumps(rows[rid]))

    def test_tail_redacts_planted_secrets(self):
        self.agent("a1111111111111111", [
            tool_use("Bash", {"command": f"export ANTHROPIC_API_KEY={ANT}; aws s3 ls --key {AWS}",
                              "description": "list buckets"}),
            {"type": "user", "timestamp": "2027-01-15T08:00:02.000Z", "cwd": "/Users/x/repo",
             "message": {"content": [{"type": "tool_result", "content": f"token={ANT}", "is_error": False}]}},
            text("assistant", f"I found {AWS} in the env")])
        row = peek.find("c:a1111111111111111", self.policy)
        res = peek.tail(row, 10, self.policy)
        self.assertTrue(res["ok"])
        blob = json.dumps(res)
        self.assertIn("Bash", blob)
        self.assertIn("list buckets", blob)
        self.assertNotIn(ANT, blob)
        self.assertNotIn("Q" * 20, blob)
        self.assertNotIn(AWS, blob)
        self.assertIn("REDACTED", blob)

    def test_redaction_control_shows_the_test_would_catch_a_leak(self):
        self.agent("a1111111111111111", [tool_use("Bash", {"command": f"echo {ANT}"})])
        row = peek.find("c:a1111111111111111", self.policy)

        class Identity:
            @staticmethod
            def redact(t):
                return t

        with mock.patch.object(peek, "_redact", Identity):
            self.assertIn(ANT, json.dumps(peek.tail(row, 5, self.policy)))

    def test_no_redactor_means_no_free_text(self):
        self.agent("a1111111111111111", [tool_use("Bash", {"command": f"echo {ANT}"}), text("assistant", "hello")])
        row = peek.find("c:a1111111111111111", self.policy)
        with mock.patch.object(peek, "_redact", None):
            blob = json.dumps(peek.tail(row, 5, self.policy))
        self.assertNotIn(ANT, blob)
        self.assertNotIn("hello", blob)

    def test_tail_refuses_excluded_instances_and_cwd(self):
        self.agent("a2222222222222222", [text("user", "x")], desc="Interview prep")
        self.agent("a4444444444444444", [text("user", "fine"), tool_use("Bash", {"command": "ls"},
                                                                        cwd="/Users/x/work/solve-floor-gate")])
        for rid in ("c:a2222222222222222", "c:a4444444444444444"):
            res = peek.tail(peek.find(rid, self.policy), 5, self.policy)
            self.assertFalse(res["ok"], rid)
            self.assertEqual(res["code"], "excluded")
            self.assertNotIn("fine", json.dumps(res))

    def test_items_naming_interview_material_are_blanked(self):
        self.agent("a1111111111111111", [text("assistant", "now reading the Solve transcript"), text("assistant", "ok")])
        res = peek.tail(peek.find("c:a1111111111111111", self.policy), 5, self.policy)
        blob = json.dumps(res)
        self.assertNotIn("Solve", blob)
        self.assertIn('"ok"', blob)

    def test_malformed_oversized_and_half_lines(self):
        big = json.dumps(text("assistant", "x" * 5000)).encode() + b"\n"
        p = self.agent("a1111111111111111", [text("assistant", "first")],
                       raw_tail=b"\xff\xfenot json\n" + big + json.dumps(text("assistant", "last")).encode() + b"\n"
                       + b'{"type": "assistant", "half')
        pol = dict(self.policy, peek_line_max_bytes=2048)
        res = peek.tail(peek.find("c:a1111111111111111", pol), 10, pol)
        texts = [i["text"] for i in res["items"]]
        self.assertEqual(texts, ["first", "last"])
        self.assertEqual(res["stats"]["malformed"], 1)
        self.assertEqual(res["stats"]["oversized"], 1)
        self.assertTrue(p.exists())

    def test_tail_reads_at_most_the_byte_cap(self):
        recs = [text("assistant", f"line {i}") for i in range(2000)]
        self.agent("a1111111111111111", recs)
        pol = dict(self.policy, peek_tail_max_bytes=4096)
        res = peek.tail(peek.find("c:a1111111111111111", pol), 500, pol)
        self.assertTrue(res["stats"]["partial_head"])
        self.assertLess(len(res["items"]), 60)
        self.assertEqual(res["items"][-1]["text"], "line 1999")

    def test_bad_ids_are_rejected(self):
        for bad in ("../../etc/passwd", "c:../x", "dev2/c:a1", "z:abc", ""):
            self.assertIsNone(peek.find(bad, self.policy), bad)

    def test_codex_rollout(self):
        d = self.home / ".codex" / "sessions" / "2027" / "01" / "15"
        d.mkdir(parents=True)
        rid = "01a1aa40-7b53-7c63-a19f-b5c63e28b7f6"
        p = d / f"rollout-2027-01-15T08-00-00-{rid}.jsonl"
        recs = [{"type": "session_meta", "payload": {"cwd": "/Users/x/repo"}},
                {"type": "response_item", "timestamp": "2027-01-15T08:00:00Z",
                 "payload": {"type": "function_call", "name": "shell", "arguments": json.dumps({"command": ["echo", ANT]})}},
                {"type": "response_item", "timestamp": "2027-01-15T08:00:01Z",
                 "payload": {"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "done"}]}}]
        p.write_text("".join(json.dumps(r) + "\n" for r in recs))
        res = peek.tail(peek.find(f"x:{rid}", self.policy), 5, self.policy)
        self.assertTrue(res["ok"])
        self.assertEqual([i["kind"] for i in res["items"]], ["tool_use", "assistant"])
        self.assertNotIn(ANT, json.dumps(res))
        p.write_text(json.dumps({"type": "session_meta", "payload": {"cwd": "/Users/x/interview-notes"}}) + "\n")
        self.assertFalse(peek.tail(peek.find(f"x:{rid}", self.policy), 5, self.policy)["ok"])


class Follow(Base):
    def test_follow_survives_truncation_and_rotation(self):
        p = self.agent("a1111111111111111", [text("assistant", "old")])
        f = peek.Follower(str(p))
        self.assertEqual(f.poll(), [])
        with open(p, "ab") as fh:
            fh.write(json.dumps(text("assistant", "new")).encode() + b"\n" + b'{"type": "assi')
        self.assertEqual([r["message"]["content"][0]["text"] for r in f.poll()], ["new"])
        with open(p, "ab") as fh:
            fh.write(b'stant", "message": {"content": [{"type": "text", "text": "joined"}]}}\n')
        self.assertEqual([r["message"]["content"][0]["text"] for r in f.poll()], ["joined"])
        p.write_bytes(json.dumps(text("assistant", "after-truncate")).encode() + b"\n")  # shorter: truncated
        self.assertEqual([r["message"]["content"][0]["text"] for r in f.poll()], ["after-truncate"])
        rotated = p.with_name("rotated.jsonl")
        os.replace(p, rotated)
        p.write_bytes(json.dumps(text("assistant", "fresh-inode")).encode() + b"\n" * 300)
        self.assertEqual([r["message"]["content"][0]["text"] for r in f.poll()], ["fresh-inode"])
        self.assertGreaterEqual(f.stats["resets"], 2)

    def test_follow_stops_on_interview_cwd(self):
        p = self.agent("a1111111111111111", [text("assistant", "old")])
        row = peek.find("c:a1111111111111111", self.policy)
        out = io.StringIO()
        with open(p, "ab") as fh:
            fh.write(json.dumps(text("assistant", "secret plan", cwd="/w/solve-x")).encode() + b"\n")
        with mock.patch.object(peek.Follower, "__init__", lambda s, path, offset=None, line_max=1 << 20: (
                setattr(s, "path", path), setattr(s, "line_max", line_max), setattr(s, "key", (os.stat(path).st_dev, os.stat(path).st_ino)),
                setattr(s, "offset", 0), setattr(s, "buf", b""), setattr(s, "stats", {"malformed": 0, "oversized": 0, "resets": 0}))[0]):
            rc = peek.follow(row, self.policy, out=out, interval=0, max_polls=1)
        self.assertEqual(rc, 3)
        self.assertNotIn("secret plan", out.getvalue())


if __name__ == "__main__":
    unittest.main()


class ReviewRound1Peek(Base):
    def test_b2_codex_cwd_only_in_the_first_record_still_excludes(self):
        d = self.home / ".codex" / "sessions" / "2027" / "01" / "15"
        d.mkdir(parents=True)
        rid = "01a1aa40-7b53-7c63-a19f-b5c63e28b7f7"
        p = d / f"rollout-2027-01-15T08-00-00-{rid}.jsonl"
        filler = json.dumps({"type": "response_item", "payload": {"type": "function_call_output", "output": "y" * 60000}})
        with open(p, "w") as fh:
            fh.write(json.dumps({"type": "session_meta", "payload": {"cwd": "/Users/u/Solve"}}) + "\n")
            for _ in range(80):
                fh.write(filler + "\n")
            fh.write(json.dumps({"type": "response_item", "payload": {"type": "message", "role": "assistant",
                                                                      "content": [{"type": "output_text", "text": "leak"}]}}) + "\n")
        res = peek.tail(peek.find(f"x:{rid}", self.policy), 5, self.policy)
        self.assertFalse(res["ok"])
        self.assertNotIn("leak", json.dumps(res))

    def test_b2_screening_sees_text_beyond_the_cut(self):
        self.agent("a1111111111111111", [text("assistant", "a" * 900 + " then the Solve interview notes")])
        res = peek.tail(peek.find("c:a1111111111111111", self.policy), 5, self.policy)
        self.assertEqual(res["items"][0]["text"], peek.EXCLUDED_TEXT)

    def test_no_cwd_anywhere_is_refused(self):
        rec = {"type": "assistant", "timestamp": "t", "message": {"content": [{"type": "text", "text": "hi"}]}}
        self.agent("a1111111111111111", [rec])
        res = peek.tail(peek.find("c:a1111111111111111", self.policy), 5, self.policy)
        self.assertFalse(res["ok"])

    def test_tool_result_bodies_are_never_shown(self):
        self.agent("a1111111111111111", [{"type": "user", "timestamp": "t", "cwd": "/Users/x/repo",
                                          "message": {"content": [{"type": "tool_result", "content": "PLAINBODYWORD"}]}}])
        res = peek.tail(peek.find("c:a1111111111111111", self.policy), 5, self.policy)
        self.assertNotIn("PLAINBODYWORD", json.dumps(res))
        self.assertEqual(res["items"][0]["chars"], len("PLAINBODYWORD"))

    def test_fifo_meta_never_hangs_list(self):
        p = self.agent("a1111111111111111", [text("user", "x")])
        meta = p.with_name(p.stem + ".meta.json")
        meta.unlink()
        os.mkfifo(meta)
        rows = peek.discover(self.policy, include_all=True)
        self.assertEqual(len(rows), 1)
