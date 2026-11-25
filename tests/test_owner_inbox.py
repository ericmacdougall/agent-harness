"""owner_inbox.py: inject unread OWNER-DECISION-*.md and inbox/ notes, then mark them read."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
HOOKS = ROOT / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
sys.path.insert(0, str(ROOT))
import owner_inbox  # noqa: E402
import wal  # noqa: E402

SID = "48e6450e-a254-472a-a551-c65dad043a2c"
OTHER = "2cb7bec1-f2a8-411a-b896-4813c4017244"


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)
        self.env_patch = patch.dict(os.environ, {"HARNESS_OWNER_INBOX_HOME": str(self.home),
                                                 "AH_HOME": str(self.home)})
        self.env_patch.start()
        self.work = self.home / ".agent-harness" / "work" / wal.safe_id(SID)
        self.work.mkdir(parents=True, mode=0o700)

    def tearDown(self):
        self.env_patch.stop()
        self.tmp.cleanup()

    def write_decision(self, name="OWNER-DECISION-test.md", body="Close the 55 asks.\n", session=SID):
        directory = self.home / ".agent-harness" / "work" / wal.safe_id(session)
        directory.mkdir(parents=True, mode=0o700, exist_ok=True)
        path = directory / name
        path.write_text(body, encoding="utf-8")
        os.chmod(path, 0o600)
        return path

    def write_inbox(self, name="note.md", body="Use existing staging accounts.\n", session=SID):
        directory = self.home / ".agent-harness" / "work" / wal.safe_id(session) / "inbox"
        directory.mkdir(parents=True, mode=0o700, exist_ok=True)
        path = directory / name
        path.write_text(body, encoding="utf-8")
        os.chmod(path, 0o600)
        return path

    def event(self, name="UserPromptSubmit", session=SID, **extra):
        payload = {"hook_event_name": name, "session_id": session}
        payload.update(extra)
        return payload

    def hook(self, event):
        return owner_inbox.hook_output(event)

    def context(self, event):
        out = self.hook(event)
        self.assertIsNotNone(out)
        return out["hookSpecificOutput"]["additionalContext"]

class Inject(Base):
    def test_prompt_injects_decision_and_marks_read(self):
        self.write_decision(body="Yes, close the 55 answered asks.\n")
        text = self.context(self.event())
        self.assertIn("OWNER DECISION (answer inbox)", text)
        self.assertIn("OWNER-DECISION-test.md", text)
        self.assertIn("Yes, close the 55 answered asks.", text)
        self.assertIsNone(self.hook(self.event()), "a second turn must not re-inject an unchanged file")

    def test_changed_file_is_unread_again(self):
        path = self.write_decision(body="first\n")
        self.context(self.event())
        path.write_text("updated decision\n", encoding="utf-8")
        text = self.context(self.event())
        self.assertIn("updated decision", text)
        self.assertNotIn("\nfirst\n", text)

    def test_inbox_markdown_is_injected(self):
        self.write_inbox(body="Yes, use the existing staging test accounts.\n")
        text = self.context(self.event())
        self.assertIn("inbox/note.md", text)
        self.assertIn("existing staging test accounts", text)

    def test_inbox_ignores_hidden_and_non_text(self):
        self.write_inbox(name=".secret.md", body="hidden\n")
        (self.work / "inbox").mkdir(exist_ok=True)
        (self.work / "inbox" / "notes.bin").write_bytes(b"\x00\x01")
        self.write_decision(body="visible\n")
        text = self.context(self.event())
        self.assertIn("visible", text)
        self.assertNotIn("hidden", text)
        self.assertNotIn("notes.bin", text)

    def test_symlink_decision_is_skipped(self):
        target = self.home / "outside.md"
        target.write_text("should never be injected\n", encoding="utf-8")
        os.symlink(target, self.work / "OWNER-DECISION-link.md")
        self.assertIsNone(self.hook(self.event()))

    def test_other_session_notes_are_invisible(self):
        self.write_decision(body="deeptap only\n", session=OTHER)
        self.assertIsNone(self.hook(self.event(session=SID)))
        text = self.context(self.event(session=OTHER))
        self.assertIn("deeptap only", text)

    def test_missing_work_dir_or_session_is_silent(self):
        self.assertIsNone(self.hook(self.event(session="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")))
        self.assertIsNone(self.hook(self.event(session="")))
        self.assertIsNone(self.hook({"hook_event_name": "UserPromptSubmit"}))
        self.assertIsNone(self.hook(self.event(name="PreToolUse")))

    def test_session_start_and_post_tool_use_inject_context(self):
        self.write_decision(body="keep going\n")
        for name in ("SessionStart", "PostToolUse"):
            # rewrite as unread for each event
            self.write_decision(body=f"body for {name}\n")
            out = self.hook(self.event(name=name))
            self.assertEqual(out["hookSpecificOutput"]["hookEventName"], name)
            self.assertIn(f"body for {name}", out["hookSpecificOutput"]["additionalContext"])

    def test_stop_says_one_line_and_leaves_the_note_for_the_next_prompt(self):  # never a block since 2026-11-24
        self.write_decision(body="do non-live work only\n")
        out = self.hook(self.event(name="Stop"))
        self.assertNotIn("decision", out)
        self.assertIn("OWNER-DECISION-test.md", out["systemMessage"])
        self.assertNotIn("do non-live work only", out["systemMessage"])
        self.assertIsNone(self.hook(self.event(name="Stop")), "the same unread set is named once")
        self.assertIn("do non-live work only", self.context(self.event()))  # delivered, not lost

    def test_overflow_files_wait_for_the_next_turn(self):
        for i in range(owner_inbox.MAX_FILES + 2):
            self.write_decision(name=f"OWNER-DECISION-{i:02d}.md", body=f"note {i}\n")
        text = self.context(self.event())
        self.assertIn("OWNER-DECISION-00.md", text)  # too long to inline: one line per note naming its file
        self.assertIn("+2 more unread", text)
        self.assertLessEqual(len(text), 2000)
        text2 = self.context(self.event())
        self.assertIn("note 8", text2)  # the last two fit inline
        self.assertNotIn("OWNER-DECISION-00.md", text2)

    def test_cli_fails_open_on_bad_input(self):
        result = subprocess.run([sys.executable, str(HOOKS / "owner_inbox.py"), "hook"],
                                input="{not json", capture_output=True, text=True,
                                env=dict(os.environ, HARNESS_OWNER_INBOX_HOME=str(self.home)))
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "")

    def test_cli_prints_context_json(self):
        self.write_decision(body="merge after Fable PASS\n")
        result = subprocess.run([sys.executable, str(HOOKS / "owner_inbox.py"), "hook"],
                                input=json.dumps(self.event()), capture_output=True, text=True,
                                env=dict(os.environ, HARNESS_OWNER_INBOX_HOME=str(self.home)))
        self.assertEqual(result.returncode, 0)
        payload = json.loads(result.stdout)
        self.assertIn("merge after Fable PASS", payload["hookSpecificOutput"]["additionalContext"])

    def test_pending_lists_paths_without_bodies(self):
        self.write_decision(body="secret-looking body should not be listed\n")
        result = subprocess.run([sys.executable, str(HOOKS / "owner_inbox.py"), "pending", "--session", SID],
                                capture_output=True, text=True,
                                env=dict(os.environ, HARNESS_OWNER_INBOX_HOME=str(self.home)))
        self.assertEqual(result.returncode, 0)
        data = json.loads(result.stdout)
        self.assertEqual(data["unread"][0]["relpath"], "OWNER-DECISION-test.md")
        self.assertNotIn("secret-looking", result.stdout)


    def test_subagent_event_does_not_consume_the_note(self):
        self.write_decision(body="for the main session only\n")
        self.assertIsNone(self.hook(self.event(name="PostToolUse", agent_id="a1b2c3")))
        # A main session started with --agent has agent_type but no agent_id; it must still receive the note.
        text = self.context(self.event(agent_type="task-owner"))
        self.assertIn("for the main session only", text)
        self.assertIsNone(self.hook(self.event()))

    def test_stop_hook_active_stays_silent(self):
        self.write_decision(body="do not loop\n")
        self.assertIsNone(self.hook(self.event(name="Stop", stop_hook_active=True)))
        out = self.hook(self.event(name="Stop"))
        self.assertNotIn("decision", out)
        self.assertIn("1 unread", out["systemMessage"])

    def test_failed_mark_does_not_stop_loop_or_eat_posttool(self):
        self.write_decision(body="still unread if mark fails\n")
        os.chmod(self.work, 0o500)
        try:
            self.assertIsNone(self.hook(self.event(name="Stop")))
            self.assertIsNone(self.hook(self.event(name="PostToolUse")))
            text = self.context(self.event())  # UserPromptSubmit still surfaces it
            self.assertIn("still unread if mark fails", text)
        finally:
            os.chmod(self.work, 0o700)
        text = self.context(self.event())
        self.assertIn("still unread if mark fails", text)
        self.assertIsNone(self.hook(self.event()))

    def test_unreadable_file_is_skipped_not_fatal(self):
        bad = self.write_decision(name="OWNER-DECISION-bad.md", body="cannot read me\n")
        self.write_decision(name="OWNER-DECISION-good.md", body="visible note\n")
        os.chmod(bad, 0o000)
        try:
            text = self.context(self.event())
            self.assertIn("visible note", text)
            self.assertNotIn("cannot read me", text)
        finally:
            os.chmod(bad, 0o600)



class Install(unittest.TestCase):

    def test_installer_ships_and_wires_the_inbox(self):
        import install  # noqa: E402
        import install_codex  # noqa: E402
        self.assertIn("owner_inbox.py", install.HOOKS)
        self.assertIn("owner_inbox.py", install_codex.DELIVERY_HELPERS)
        self.assertIn(str(Path("/h/.claude") / "hooks" / "owner_inbox.py"),
                      install.managed_scripts(Path("/h/.claude")))
        hooks = install.managed_hooks(Path("/h/.claude"), True)
        for event, arg in (("UserPromptSubmit", "hook"), ("SessionStart", "hook"),
                           ("Stop", "hook"), ("PostToolUse", "hook")):
            found = [h for g in hooks.get(event, []) for h in g["hooks"]
                     if (h.get("args") or [""])[0].endswith("owner_inbox.py")]
            self.assertEqual(len(found), 1, event)
            self.assertEqual(found[0]["args"][1:], [arg])
            self.assertNotIn("onFailure", found[0], "the inbox hook fails open")
        merged = install_codex.merge_hooks({}, Path("/h/.codex"))["hooks"]
        for event in ("UserPromptSubmit", "SessionStart"):
            commands = [h["command"] for g in merged[event] for h in g["hooks"]]
            self.assertTrue(any("owner_inbox.py" in c and c.endswith(" hook") for c in commands), event)
        for event in ("Stop", "PreToolUse"):
            commands = [h["command"] for g in merged.get(event, []) for h in g["hooks"]]
            self.assertFalse(any("owner_inbox.py" in c for c in commands), event)
        # Reinstall is idempotent (does not duplicate the Codex hook).
        again = install_codex.merge_hooks(install_codex.merge_hooks({}, Path("/h/.codex")),
                                          Path("/h/.codex"))["hooks"]
        for event in ("UserPromptSubmit", "SessionStart"):
            commands = [h["command"] for g in again[event] for h in g["hooks"]]
            self.assertEqual(sum("owner_inbox.py" in c for c in commands), 1, event)
        manifest = json.loads((HOOKS / "hooks_manifest.json").read_text())
        ids = {h["id"]: h for h in manifest["hooks"]}
        for rid in ("owner_inbox:prompt", "owner_inbox:session-start",
                    "owner_inbox:stop", "owner_inbox:posttool"):
            self.assertEqual(ids[rid]["status"], "installed", rid)
        self.assertIn("codex", ids["owner_inbox:prompt"]["flavors"])
        self.assertNotIn("codex", ids["owner_inbox:stop"]["flavors"])

class Crossing(Base):
    """2026-11-24: relayed answers crossed questions. Notes now arrive oldest first, carry an id and what they answer,
    and a long note arrives as a path within the context cap."""

    def test_oldest_note_first_whatever_its_name(self):
        newer = self.write_decision(name="OWNER-DECISION-a.md", body="answer B\n")
        older = self.write_decision(name="OWNER-DECISION-z.md", body="answer A\n")
        os.utime(older, (1_700_000_000, 1_700_000_000))
        os.utime(newer, (1_700_000_100, 1_700_000_100))
        text = self.context(self.event())
        self.assertLess(text.index("answer A"), text.index("answer B"))

    def test_note_names_the_asks_it_answers_and_how_to_close_them(self):
        self.write_decision(body="In-Reply-To: [ask:w0123456789a]\nYes.\n")
        text = self.context(self.event())
        self.assertIn("in-reply-to: w0123456789a", text)
        self.assertIn("--event ask_resolved --ref w0123456789a", text)
        self.assertIn("OWNER-DECISION-test.md@", text)

    def test_an_edited_note_is_marked_updated(self):
        path = self.write_decision(body="first\n")
        self.context(self.event())
        path.write_text("second\n", encoding="utf-8")
        self.assertIn("UPDATED", self.context(self.event()))

    def test_a_long_note_arrives_as_its_path_within_the_cap(self):
        path = self.write_decision(body="decision text " * 400)
        text = self.context(self.event())
        self.assertIn(str(path), text)
        self.assertNotIn("decision text decision text", text)
        self.assertLessEqual(len(text), 700)


if __name__ == "__main__":
    unittest.main()

