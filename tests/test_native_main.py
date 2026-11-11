"""Desktop review-role controls. No installed hook, private database or stamp."""
import importlib.util
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "harness" / "hooks"))

import caller_identity as ci
from native_context import CodeIdentity, OPENAI_TEAM, ProcessIdentity

# The unchanged baseline has no review-role adapter. Run its actual denying
# predicate for the positive red control instead of failing on an import error.
ADAPTER_PRESENT = importlib.util.find_spec("native_main") is not None
if ADAPTER_PRESENT:
    import native_main as nm

ROOT_ID = "11111111-2222-3333-4444-555555555555"
CHILD_ID = "11111111-2222-3333-4444-555555555556"
CALL_ID = "exec-11111111-2222-3333-4444-555555555555"
CHILD_CALL_ID = "exec-11111111-2222-3333-4444-555555555556"
GUI = "/Applications/Fixture.app/Contents/MacOS/ChatGPT"
CLI = "/Applications/Fixture.app/Contents/Resources/codex-cli/CodexCLI.app/Contents/MacOS/codex"
ROOT_ROW = (ROOT_ID, "vscode", "user", "Codex Desktop", None, None, None, 0)


def payload(**overrides):
    return dict({"hook_event_name": "PreToolUse", "session_id": ROOT_ID,
                 "tool_use_id": CALL_ID, "tool_name": "Bash"}, **overrides)


class FakeDesktop:
    def __init__(self):
        self.processes = {
            10: ProcessIdentity(10, 20, 501, 4, "/usr/bin/python3"),
            20: ProcessIdentity(20, 30, 501, 3, CLI),
            30: ProcessIdentity(30, 1, 501, 2, GUI),
        }
        self.codes = {20: CodeIdentity("codex", OPENAI_TEAM, "a" * 40, CLI)}
        self.gui_code = CodeIdentity("com.openai.codex", OPENAI_TEAM, "b" * 40, GUI)
        self.gui_calls = 0
        self.on_gui = lambda: None

    def process(self, pid):
        return self.processes[pid]

    def signature(self, pid):
        return self.codes.get(pid)

    def desktop_signature(self, pid):
        self.gui_calls += 1
        self.on_gui()
        return self.gui_code if pid == 30 else None


class DesktopReviewRole(unittest.TestCase):
    def setUp(self):
        self.backend = FakeDesktop()
        self.reads = []

    def row(self, ident):
        self.reads.append(ident)
        return ROOT_ROW, ("fixture binding",)

    def admit(self, envelope, reader=None):
        if not ADAPTER_PRESENT:
            with patch.object(ci, "native_deny_reason", return_value="native_origin_has_no_main_admission"):
                return ci.is_main(envelope)
        return nm._is_desktop_root(envelope, 10, self.backend, reader or self.row)

    def test_genuine_current_desktop_root_can_qualify_for_review(self):
        self.assertTrue(self.admit(payload()))
        self.assertEqual(self.reads, [ROOT_ID, ROOT_ID])

    def test_default_shared_main_predicate_still_denies_native(self):
        with patch.object(ci, "native_deny_reason", return_value="native_origin_has_no_main_admission"):
            self.assertFalse(ci.is_main(payload()))

    def test_copied_both_root_markers_cannot_erase_current_child(self):
        with patch.dict(os.environ, {"CODEX_THREAD_ID": ROOT_ID, "CODEX_TOOL_CALL_ID": CALL_ID}):
            self.assertFalse(self.admit(payload(agent_id=CHILD_ID, tool_use_id=CHILD_CALL_ID)))
        self.assertEqual(self.reads, [])
        self.assertEqual(self.backend.gui_calls, 0)

    def test_missing_or_conflicting_current_identity_denies(self):
        for extra in ({"hook_event_name": "PostToolUse"}, {"tool_name": "Write"},
                      {"tool_use_id": None}, {"tool_use_id": "bogus"}, {"session_id": False},
                      {"agent_id": 0}, {"agent_type": []}, {"agentId": CHILD_ID},
                      {"thread_id": CHILD_ID}, {"toolUseId": "call_other"},
                      {"parent_thread_id": CHILD_ID}):
            with self.subTest(extra=extra):
                self.assertFalse(self.admit(payload(**extra)))

    def test_historical_desktop_row_does_not_admit_cli_resume(self):
        self.backend.processes[20] = ProcessIdentity(20, 40, 501, 3, CLI)
        self.backend.processes[40] = ProcessIdentity(40, 1, 501, 1, "/bin/zsh")
        self.assertFalse(self.admit(payload()))

    def test_more_distant_gui_cannot_admit_nested_cli(self):
        self.backend.processes[20] = ProcessIdentity(20, 40, 501, 3, CLI)
        self.backend.processes[40] = ProcessIdentity(40, 30, 501, 3, "/bin/zsh")
        self.assertFalse(self.admit(payload()))

    def test_wrong_gui_identity_or_package_denies(self):
        self.backend.gui_code = CodeIdentity("com.example.other", OPENAI_TEAM, "b" * 40, GUI)
        self.assertFalse(self.admit(payload()))
        other = "/Applications/Other.app/Contents/MacOS/ChatGPT"
        self.backend.processes[30] = ProcessIdentity(30, 1, 501, 2, other)
        self.backend.gui_code = CodeIdentity("com.openai.codex", OPENAI_TEAM, "b" * 40, other)
        self.assertFalse(self.admit(payload()))

    def test_nearer_unapproved_native_runtime_does_not_fall_back(self):
        self.backend.processes[10] = ProcessIdentity(10, 11, 501, 5, "/usr/bin/python3")
        self.backend.processes[11] = ProcessIdentity(11, 20, 501, 4, "/other/codex")
        self.assertFalse(self.admit(payload()))

    def test_reused_gui_pid_denies(self):
        def reuse():
            if self.backend.gui_calls == 2:
                self.backend.processes[30] = ProcessIdentity(30, 1, 501, 5, GUI)
        self.backend.on_gui = reuse
        self.assertFalse(self.admit(payload()))

    def test_same_pid_gui_code_change_denies(self):
        def change():
            if self.backend.gui_calls == 2:
                self.backend.gui_code = CodeIdentity("com.openai.codex", OPENAI_TEAM, "c" * 40, GUI)
        self.backend.on_gui = change
        self.assertFalse(self.admit(payload()))

    def test_same_pid_runtime_code_change_denies(self):
        def change():
            if self.backend.gui_calls == 2:
                self.backend.codes[20] = CodeIdentity("codex", OPENAI_TEAM, "c" * 40, CLI)
        self.backend.on_gui = change
        self.assertFalse(self.admit(payload()))

    def test_identity_row_changed_before_positive_denies(self):
        rows = iter([(ROOT_ROW, ("fixture binding",)), ((*ROOT_ROW[:-1], 1), ("fixture binding",))])
        self.assertFalse(self.admit(payload(), lambda _ident: next(rows)))

    @unittest.skipUnless(ADAPTER_PRESENT, "new adapter absent on unchanged baseline")
    def test_public_entry_uses_current_account_home_and_fixed_reader(self):
        account = type("Account", (), {"pw_dir": "/fixture/home"})()
        with patch.object(nm.sys, "platform", "darwin"), \
                patch.object(nm.os, "getpid", return_value=10), \
                patch.object(nm.os, "getuid", return_value=501), \
                patch.object(nm.pwd, "getpwuid", return_value=account), \
                patch.object(nm, "_DesktopBackend", return_value=self.backend), \
                patch.object(nm, "_read_thread", return_value=(ROOT_ROW, ("fixture binding",))) as read, \
                patch.dict(os.environ, {"HOME": "/untrusted", "CODEX_THREAD_ID": CHILD_ID,
                                        "CODEX_METADATA_DB": "/untrusted/database"}):
            self.assertTrue(nm.is_desktop_review_root(payload()))
        self.assertEqual(read.call_args_list, [unittest.mock.call(Path("/fixture/home"), 501, ROOT_ID)] * 2)

    @unittest.skipUnless(ADAPTER_PRESENT, "new adapter absent on unchanged baseline")
    def test_malformed_current_hook_never_queries_runtime(self):
        with patch.object(nm.sys, "platform", "darwin"), patch.object(nm, "_DesktopBackend") as backend:
            self.assertFalse(nm.is_desktop_review_root(payload(agent_id=CHILD_ID)))
        backend.assert_not_called()


@unittest.skipUnless(ADAPTER_PRESENT, "new reader is absent on the unchanged baseline")
class FixedMetadataReader(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.home = Path(tmp.name).resolve()
        self.db = self.home / ".codex" / "state_5.sqlite"
        self.db.parent.mkdir(mode=0o700)
        with sqlite3.connect(self.db) as db:
            db.execute("CREATE TABLE threads (id TEXT PRIMARY KEY, source TEXT, thread_source TEXT, "
                       "originator TEXT, agent_path TEXT, agent_role TEXT, attached_thread_parent_id TEXT, "
                       "archived INTEGER, first_user_message TEXT)")
            db.execute("INSERT INTO threads VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                       (*ROOT_ROW, "fixture private content"))

    def read(self, ident=ROOT_ID):
        return nm._read_thread(self.home, os.getuid(), ident)

    def test_only_exact_identity_projection_returns(self):
        self.assertEqual(self.read()[0], ROOT_ROW)
        self.assertIsNone(self.read(CHILD_ID))

    def test_nonroot_and_archived_rows_are_not_root(self):
        for sql in ("UPDATE threads SET source='cli'", "UPDATE threads SET archived=1",
                    "UPDATE threads SET agent_path='/root/child'", "UPDATE threads SET originator=7"):
            with self.subTest(sql=sql), sqlite3.connect(self.db) as db:
                db.execute("DELETE FROM threads")
                db.execute("INSERT INTO threads VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                           (*ROOT_ROW, "fixture private content"))
                db.execute(sql)
                db.commit()
                self.assertFalse(nm._is_desktop_root(payload(), 10, FakeDesktop(), self.read))

    def test_nonregular_or_aliased_database_denies(self):
        target = self.db.with_suffix(".saved")
        self.db.rename(target)
        self.db.symlink_to(target)
        self.assertIsNone(self.read())

    def test_unknown_schema_and_bad_database_deny(self):
        with sqlite3.connect(self.db) as db:
            db.execute("ALTER TABLE threads RENAME COLUMN originator TO unknown_origin")
        self.assertIsNone(self.read())
        self.db.write_bytes(b"not a sqlite database")
        self.assertIsNone(self.read())

    def test_two_matching_rows_in_unqualified_schema_deny(self):
        with sqlite3.connect(self.db) as db:
            db.execute("CREATE TABLE copied AS SELECT * FROM threads")
            db.execute("DROP TABLE threads")
            db.execute("ALTER TABLE copied RENAME TO threads")
            db.execute("INSERT INTO threads SELECT * FROM threads")
        self.assertIsNone(self.read())

    def test_concurrent_exclusive_lock_is_bounded_and_denies(self):
        db = sqlite3.connect(self.db)
        try:
            db.execute("BEGIN EXCLUSIVE")
            self.assertIsNone(self.read())
        finally:
            db.close()

    def test_database_binding_change_denies(self):
        before = nm._database_binding(self.home, self.db, os.getuid())
        with patch.object(nm, "_database_binding", side_effect=[before, None]):
            self.assertIsNone(self.read())

    def test_readonly_reads_current_committed_wal(self):
        db = sqlite3.connect(self.db)
        try:
            self.assertEqual(db.execute("PRAGMA journal_mode=WAL").fetchone(), ("wal",))
            db.execute("UPDATE threads SET archived=1")
            db.commit()
            self.assertEqual(self.read()[0], (*ROOT_ROW[:-1], 1))
            db.execute("UPDATE threads SET archived=0")
            self.assertEqual(self.read()[0], (*ROOT_ROW[:-1], 1))
            db.rollback()
        finally:
            db.close()

    def test_oversized_identity_column_is_refused(self):
        with sqlite3.connect(self.db) as db:
            db.execute("UPDATE threads SET agent_path=?", ("x" * 16384,))
        self.assertIsNone(self.read())

    def test_generated_identity_field_is_refused_before_evaluation(self):
        with sqlite3.connect(self.db) as db:
            db.execute("DROP TABLE threads")
            db.execute("CREATE TABLE threads (id TEXT PRIMARY KEY, source TEXT, thread_source TEXT, "
                       "originator TEXT GENERATED ALWAYS AS ('Codex Desktop') VIRTUAL, "
                       "agent_path TEXT, agent_role TEXT, attached_thread_parent_id TEXT, archived INTEGER)")
            db.execute("INSERT INTO threads(id,source,thread_source,archived) VALUES(?,?,?,?)",
                       (ROOT_ID, "vscode", "user", 0))
        self.assertIsNone(self.read())

    def test_expired_statement_budget_denies(self):
        with patch.object(nm.time, "monotonic", side_effect=[1.0] + [2.0] * 100):
            self.assertIsNone(self.read())

    def test_projection_cannot_select_private_content_or_another_row(self):
        statements = []
        real_connect = sqlite3.connect

        def connect(*args, **kwargs):
            db = real_connect(*args, **kwargs)
            db.set_trace_callback(statements.append)
            return db

        with patch.object(nm.sqlite3, "connect", side_effect=connect):
            self.assertEqual(self.read()[0], ROOT_ROW)
        query = next(sql for sql in statements if "FROM main.threads" in sql)
        self.assertNotIn("first_user_message", query)
        self.assertIn("WHERE id = '" + ROOT_ID + "' LIMIT 2", query)


class Packaging(unittest.TestCase):
    def test_both_manifests_copy_native_review_adapter(self):
        import ast
        for name, variable in (("install.py", "HOOKS"), ("install_codex.py", "DELIVERY_HELPERS")):
            with self.subTest(name=name):
                module = ast.parse((ROOT / name).read_text())
                value = next(node.value for node in module.body if isinstance(node, ast.Assign)
                             and any(isinstance(t, ast.Name) and t.id == variable for t in node.targets))
                self.assertEqual(ast.literal_eval(value).count("native_main.py"), 1)


if __name__ == "__main__":
    unittest.main()
