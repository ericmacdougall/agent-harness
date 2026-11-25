"""Provenance records sources without blocking work (harness redesign, 2026-11-24).

Fails on 2ad9bbb0: free-form sources were refused (`bad-syntax`, `unknown-kind`), unresolvable sources were refused
or quarantined and the Stop hook blocked on quarantined rows, `stop-lint`, `status_truth stop` and `ask-gate` could
block in enforce mode, and ordinary offers ("tell me if you want ...") were flagged as untraceable asks.
"""

import datetime as dt
import json
import os
import subprocess
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_provenance as base  # noqa: E402
from test_provenance import HOOKS, HUMAN, QUOTE, SID  # noqa: E402

sys.path.insert(0, str(HOOKS))
import provenance  # noqa: E402
import provenance_hooks as hooks  # noqa: E402

# the old installed policy, every gate on: the cases that used to block must now pass under it
OLD_STRICT = {"spec": "enforce", "ask_user_question": "enforce", "stop_lint": "enforce", "status_lint": "enforce",
              "quarantine_lint": "enforce", "quarantine_minutes": 10,
              "wal": {"requirement": "enforce", "ask": "enforce", "blocker": "warn", "scope": "warn", "decision": "warn"}}


def iso(ts):
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).isoformat()


class Loose(base.Env):
    def setUp(self):
        super().setUp()
        session = mock.patch.dict(os.environ, {"CLAUDE_CODE_SESSION_ID": SID, "HARNESS_PROVENANCE_OFFLINE": "1"})
        session.start()
        self.addCleanup(session.stop)
        self.env = dict(os.environ, HOME=str(self.home), AH_HOME=str(self.home), AH_USER_PRESENT="1")
        self.main = self.wals / "main.jsonl"
        self.main.write_text("")

    def note(self, *args, hooks_dir=HOOKS):
        p = subprocess.run([sys.executable, str(hooks_dir / "wal_note.py"), "--wal", str(self.main), *args],
                           capture_output=True, text=True, env=self.env, timeout=60)
        return p.returncode, p.stdout + p.stderr

    def rows(self):
        return [json.loads(line) for line in self.main.read_text().splitlines() if line.strip()]

    def cli(self, *args):
        p = subprocess.run([sys.executable, str(HOOKS / "provenance.py"), *args], capture_output=True, text=True,
                           env=self.env, timeout=60)
        return p.returncode, p.stdout + p.stderr


class FreeFormSources(Loose):
    def test_plain_quotes_resolve_to_the_owner_message(self):
        for given in (f'user said "{QUOTE}"', f'user: "{QUOTE}"', f"the user, 2026-11-24: {QUOTE}", f'"{QUOTE}"',
                      f"“{QUOTE}”"):
            with self.subTest(given):
                result = provenance.resolve(given)
                self.assertTrue(result["ok"], result)
                self.assertEqual(result["label"], "USER")
                self.assertTrue(result["normalized"].startswith(f"user:{SID}/{HUMAN} "), result)

    def test_exact_forms_still_work_unchanged(self):
        result = provenance.resolve(self.user(HUMAN, QUOTE))
        self.assertTrue(result["ok"], result)
        self.assertNotIn("normalized", result)

    def test_ticket_numbers_urls_and_paths_are_kept_as_citations(self):
        for given, kind in (("goodqa#14398", "ticket"), ("GoodQA #14398", "ticket"), ("#14398", "ticket"),
                            ("https://github.com/example/repo/pull/12", "link"), ("docs/provenance.md", "path"),
                            ("/Users/someone/notes/plan.md:12", "path")):
            with self.subTest(given):
                result = provenance.resolve(given)
                self.assertTrue(result["ok"], result)
                self.assertNotEqual(result["label"], "UNSOURCED")
                self.assertEqual(result["given_as"], kind)
        self.assertEqual(provenance.resolve("goodqa#14398")["normalized"], "ticket:GoodQA goodqa#14398")

    def test_wal_note_accepts_free_form_for_every_sourced_event(self):
        for event in ("requirement", "decision", "scope", "ask"):
            with self.subTest(event):
                extra = ["--reason", "release needs the staging key"] if event == "ask" else []
                rc, out = self.note("--event", event, "--note", "ship it", "--source", f'user said "{QUOTE}"', *extra,
                                    hooks_dir=self.sandbox(**OLD_STRICT))
                self.assertEqual(rc, 0, out)
                self.assertFalse(self.rows()[-1].get("unsourced"), self.rows()[-1])


class Unsourced(Loose):
    def test_unresolvable_source_is_unsourced_not_refused(self):
        result = provenance.resolve('user said "words that nobody ever typed here"')
        self.assertFalse(result["ok"])
        self.assertTrue(result["unsourced"])
        self.assertEqual(result["label"], "UNSOURCED")
        self.assertEqual(result["problems"][0]["code"], "unsourced")
        for src in ("whatever I say", "ticket:not-a-ticket", self.user(HUMAN, "words never said by the user")):
            with self.subTest(src):
                rc, out = self.note("--event", "requirement", "--note", "keep it", "--source", src,
                                    hooks_dir=self.sandbox(**OLD_STRICT))
                self.assertEqual(rc, 0, out)
                self.assertIn("WROTE", out)
                self.assertTrue(self.rows()[-1].get("unsourced"))
        rc, out = self.note("--event", "decision", "--note", "no source at all")
        self.assertEqual(rc, 0, out)

    def test_formerly_quarantined_record_reads_as_unsourced(self):
        old = {"at": iso(time.time() - 3600), "event": "decision", "id": "wquar0000001", "note": "we go with python",
               "unsourced": True}
        self.main.write_text(json.dumps(old) + "\n")
        rc, out = self.cli("decisions", "--session", SID)
        self.assertEqual(rc, 0, out)
        self.assertIn("wquar0000001", out)
        self.assertIn("UNSOURCED", out)
        self.assertNotIn("quarantin", out.lower())
        rc, out = self.cli("decisions", "--session", SID, "--json")
        row = json.loads(out)["records"][0]
        self.assertEqual((row["status"], row["label"]), ("unsourced", "UNSOURCED"))

    def test_listings_are_newest_first_and_mark_superseded(self):
        now = time.time()
        rows = [{"at": iso(now - 600), "event": "scope", "id": "wscope000001", "note": "Mac only", "goal": "leads",
                 "source": f'user said "{QUOTE}"'},
                {"at": iso(now - 60), "event": "scope", "id": "wscope000002", "note": "every host", "goal": "leads",
                 "source": "whatever"}]
        self.main.write_text("".join(json.dumps(r) + "\n" for r in rows))
        rc, out = self.cli("decisions", "--session", SID, "--json")
        records = json.loads(out)["records"]
        self.assertEqual([r["id"] for r in records], ["wscope000002", "wscope000001"])
        self.assertEqual(records[1]["superseded_by"], "wscope000002")
        self.assertIsNone(records[0].get("superseded_by"))
        self.assertEqual((records[1]["status"], records[1]["label"]), ("sourced", "USER"))

    def test_asks_listing_never_exits_nonzero_for_an_unsourced_ask(self):
        ask = {"at": iso(time.time()), "event": "ask", "id": "wask00000001", "note": "which key?", "reason": "release",
               "source": "whatever I say", "unsourced": True}
        self.main.write_text(json.dumps(ask) + "\n")
        rc, out = self.cli("asks", "--session", SID)
        self.assertEqual(rc, 0, out)
        self.assertIn("UNSOURCED", out)


class StopNeverBlocks(Loose):
    def run_hook(self, script, args, payload, hooks_dir):
        p = subprocess.run([sys.executable, str(hooks_dir / script), *args], input=json.dumps(payload),
                           capture_output=True, text=True, env=self.env, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        return json.loads(p.stdout) if p.stdout.strip() else {}

    def test_quarantined_rows_and_uncited_asks_do_not_block_under_the_old_strict_policy(self):
        strict = self.sandbox(**OLD_STRICT)
        self.main.write_text(json.dumps({"at": iso(time.time() - 3600), "event": "decision", "id": "wquar0000002",
                                         "note": "old unsourced", "unsourced": True}) + "\n")
        for message in ("All done.", "What I need from you:\n- the OpenRouter key\n", "Decisions needed:\n- the region\n"):
            with self.subTest(message):
                out = self.run_hook("provenance_hooks.py", ["stop-lint"],
                                    {"session_id": SID, "last_assistant_message": message, "stop_hook_active": False}, strict)
                self.assertNotIn("decision", out)
                self.assertNotIn("quarantine", json.dumps(out).lower())
        gate = self.run_hook("provenance_hooks.py", ["ask-gate"],
                             {"session_id": SID, "tool_name": "AskUserQuestion",
                              "tool_input": {"questions": [{"question": "Which key?", "header": "h", "options": []}]}}, strict)
        self.assertNotIn("permissionDecision", json.dumps(gate))

    def test_status_truth_stop_never_blocks(self):
        import status_truth
        payload = {"session_id": SID, "last_assistant_message": "prod move is not done; leads not started"}
        turn = {"answer": payload["last_assistant_message"], "prompt": "whats left", "prompt_id": "p1", "consulted": False}
        doc = {"state": "ok", "goals": [{"id": "prod-move", "state": "DONE_LIVE"}, {"id": "leads", "state": "IN_PROGRESS"}]}
        with mock.patch.object(status_truth, "_policy_mode", return_value="enforce"), \
                mock.patch.object(status_truth, "current_turn", return_value=turn), \
                mock.patch.object(status_truth, "goals_doc", return_value=doc), \
                mock.patch.object(status_truth, "in_scope", return_value=True):
            out = status_truth.cmd_stop(payload)
        self.assertNotIn("decision", out)
        self.assertEqual(out, {})


class AskLint(Loose):
    def lint(self, text):
        return hooks.lint_message(text, SID)

    def test_optional_suggestions_offers_and_questions_raise_nothing(self):
        for text in ("You could also run the slow suite later.", "If you want I can open the PR now.",
                     "Tell me if you want it moved into Applications.", "Let me know which one you prefer.",
                     "Should I also check the logs?", "Your call: pick A or B.", "Please confirm when you are back.",
                     "Status: merged, deploy pending.", "Open questions:\n- does the cache need a TTL?\n",
                     "Nothing is needed from you.", "I don't need anything from you."):
            with self.subTest(text):
                self.assertEqual(self.lint(text), [])

    def test_explicit_needed_from_you_without_an_ask_gives_one_line_once(self):
        payload = {"session_id": SID, "last_assistant_message": "Needed from you: the staging key.", "stop_hook_active": False}
        with mock.patch.object(provenance, "POLICY_FILE", self.home / "missing-policy.json"), \
                mock.patch.object(hooks, "central_enabled", return_value=False):
            first = hooks.cmd_stop_lint(dict(payload))
            second = hooks.cmd_stop_lint(dict(payload))
        self.assertEqual(len(first.get("systemMessage", "").splitlines()), 1, first)
        self.assertIn("ask", first["systemMessage"])
        self.assertNotIn("decision", first)
        self.assertEqual(second, {})

    def test_registered_ask_clears_it(self):
        self.main.write_text(json.dumps({"at": iso(time.time()), "event": "ask", "id": "wask00000002", "note": "key",
                                         "reason": "release needs it", "source": "whatever"}) + "\n")
        self.assertEqual(self.lint("Needed from you: the staging key [ask:wask00000002]."), [])
        self.assertEqual(len(self.lint("What I need from you:\n- the staging key\n")), 1)


if __name__ == "__main__":
    unittest.main()
