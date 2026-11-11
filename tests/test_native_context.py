"""Origin evidence cannot grant a native caller privileged main status."""
import os
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from dataclasses import dataclass, replace
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "harness" / "hooks"))
import native_context as nc


class FakeBackend:
    def __init__(self):
        self.processes = {
            10: nc.ProcessIdentity(10, 20, 1000, 1, "/usr/bin/python3"),
            20: nc.ProcessIdentity(20, 1, 1000, 2, "/Applications/Example/CodexCLI/codex"),
        }
        self.signed = nc.CodeIdentity("codex", nc.OPENAI_TEAM, "a" * 40,
                                      "/Applications/Example/CodexCLI/codex")
        self.calls = 0
        self.swap = None

    def process(self, pid):
        if pid not in self.processes:
            raise OSError("process gone")
        return self.processes[pid]

    def signature(self, pid):
        if pid != 20:
            return None
        self.calls += 1
        result = self.signed
        if self.swap and self.calls == 1:
            self.swap(self)
        return result


class RuntimeOrigin(unittest.TestCase):
    def test_desktop_or_cli_origin_never_grants_role(self):
        value = nc.probe_runtime_origin(10, backend=FakeBackend())
        self.assertEqual(value.origin, "openai")
        self.assertTrue(value.native_lineage)
        self.assertEqual(value.role, "unknown")
        self.assertFalse(value.main_authority)
        self.assertFalse(value.strong_user_source)

    def test_bad_signature_or_mismatched_executable_is_unknown(self):
        cases = {"other team": {"team": "OTHER"}, "other identifier": {"identifier": "python"},
                 "invalid hash": {"cdhash": "x"}, "other executable": {"executable": "/tmp/codex"}}
        for name, changes in cases.items():
            with self.subTest(name):
                backend = FakeBackend()
                backend.signed = replace(backend.signed, **changes)
                value = nc.probe_runtime_origin(10, backend=backend)
                self.assertEqual(value.origin, "unknown")
                self.assertTrue(value.native_lineage)
                self.assertFalse(value.main_authority)

    def test_pid_reuse_reparent_and_same_start_exec_swap_fail(self):
        def reused(b): b.processes[20] = replace(b.processes[20], started=3)
        def reparented(b): b.processes[10] = replace(b.processes[10], parent=21)
        def exec_path(b): b.processes[20] = replace(b.processes[20], executable="/tmp/unsigned")
        def exec_code(b): b.signed = replace(b.signed, cdhash="b" * 40)
        for swap in (reused, reparented, exec_path, exec_code):
            with self.subTest(swap=swap.__name__):
                backend = FakeBackend(); backend.swap = swap
                self.assertEqual(nc.probe_runtime_origin(10, backend=backend).origin, "unknown")

    def test_unknown_ancestry_cycle_and_live_guest_failure_do_not_guess(self):
        backend = FakeBackend(); backend.processes[10] = replace(backend.processes[10], parent=10)
        self.assertEqual(nc.probe_runtime_origin(10, backend=backend).origin, "unknown")
        backend = FakeBackend()
        def inaccessible(pid):
            if pid == 20: raise OSError("guest unavailable")
            return None
        with mock.patch.object(backend, "signature", side_effect=inaccessible):
            value = nc.probe_runtime_origin(10, backend=backend)
        self.assertEqual(value.origin, "unknown")
        self.assertTrue(value.native_lineage)

    def test_nearer_other_runtime_is_not_attributed_to_outer_codex(self):
        backend = FakeBackend()
        backend.processes[10] = replace(backend.processes[10], executable="/usr/local/bin/claude")
        value = nc.probe_runtime_origin(10, backend=backend)
        self.assertEqual(value.origin, "unknown")
        self.assertTrue(value.native_lineage)

    def test_unrecognized_ordinary_process_has_no_native_origin(self):
        backend = FakeBackend(); backend.processes[10] = replace(backend.processes[10], parent=1)
        value = nc.probe_runtime_origin(10, backend=backend)
        self.assertEqual(value.origin, "unknown")
        self.assertFalse(value.native_lineage)

    def test_every_use_revalidates_running_code(self):
        backend = FakeBackend()
        self.assertEqual(nc.probe_runtime_origin(10, backend=backend).origin, "openai")
        backend.signed = replace(backend.signed, team="OTHER")
        self.assertEqual(nc.probe_runtime_origin(10, backend=backend).origin, "unknown")


class DenyOnly(unittest.TestCase):
    def test_native_hint_can_only_deny_and_never_authenticate(self):
        with mock.patch.dict(os.environ, {"CODEX_THREAD_ID": "untrusted-hint"}):
            self.assertIsNotNone(nc.native_deny_reason({}))

    def test_unknown_native_probe_never_falls_through(self):
        value = nc.OriginObservation("unknown", True, "signature_unavailable")
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(nc, "probe_runtime_origin", return_value=value):
            self.assertIsNotNone(nc.native_deny_reason({"transcript_path": "/safe/.claude/projects/p/s.jsonl"}))

    def test_missing_native_metadata_is_not_main_proof(self):
        value = nc.OriginObservation("unknown", False, "probe_failed")
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(nc, "probe_runtime_origin", return_value=value):
            self.assertIsNotNone(nc.native_deny_reason({}))

    def test_existing_non_native_path_can_continue_legacy_checks(self):
        value = nc.OriginObservation("unknown", False, "no_native_runtime")
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(nc, "probe_runtime_origin", return_value=value):
            self.assertIsNone(nc.native_deny_reason({}))


class ReviewRuntimeRegressions(unittest.TestCase):
    def test_renamed_signed_runtime_is_verified_independent_of_basename(self):
        class Renamed(FakeBackend):
            def signature(self, pid):
                if pid == 10: return None
                return super().signature(pid)
        backend = Renamed()
        path = "/Applications/Example/CodexCLI/renamed-runtime"
        backend.processes[20] = replace(backend.processes[20], executable=path)
        backend.signed = replace(backend.signed, executable=path)
        result = nc.probe_runtime_origin(10, backend=backend)
        self.assertEqual(result.origin, "openai")
        self.assertTrue(result.native_lineage)
        self.assertGreaterEqual(backend.calls, 2)
        self.assertFalse(result.main_authority)

    def test_renamed_outer_codex_does_not_cross_nearer_runtime_barrier(self):
        backend = FakeBackend()
        backend.processes[10] = replace(backend.processes[10], executable="/usr/local/bin/claude")
        path = "/Applications/Example/CodexCLI/renamed-runtime"
        backend.processes[20] = replace(backend.processes[20], executable=path)
        backend.signed = replace(backend.signed, executable=path)
        result = nc.probe_runtime_origin(10, backend=backend)
        self.assertEqual(result.origin, "unknown")
        self.assertTrue(result.native_lineage)
        self.assertEqual(result.reason, "nearer_other_runtime")

    def test_renamed_runtime_still_checks_same_pid_same_start_exec_races(self):
        backend = FakeBackend()
        path = "/Applications/Example/CodexCLI/renamed-runtime"
        backend.processes[20] = replace(backend.processes[20], executable=path)
        backend.signed = replace(backend.signed, executable=path)
        backend.swap = lambda b: setattr(b, "signed", replace(b.signed, cdhash="b" * 40))
        result = nc.probe_runtime_origin(10, backend=backend)
        self.assertEqual(result.origin, "unknown")
        self.assertTrue(result.native_lineage)


class TerminalLoginEndsTheWalk(unittest.TestCase):
    """Terminal compatibility requires a stable kernel boundary, not a path-only guess."""

    class Chain(FakeBackend):
        login_is_terminal = True

        def __init__(self):
            super().__init__()
            self.processes = {
                10: nc.ProcessIdentity(10, 20, 1000, 1, "/usr/bin/python3"),
                20: nc.ProcessIdentity(20, 30, 1000, 2, "/bin/zsh"),
                40: nc.ProcessIdentity(40, 1, 1000, 4,
                    '/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal'),
            }

        def process_generation(self, pid):
            if pid == 30:
                value = getattr(self, 'boundary', nc.TerminalBoundary(
                    30, 40, 0, '/usr/bin/login', 300, 400, 3, 4, b'u' * 16))
                return nc.KernelGeneration(value.pid, value.unique_id, value.parent_unique_id,
                    value.id_version, value.original_parent_version, value.executable_uuid)
            if pid == 40:
                return nc.KernelGeneration(40, 400, 1, 4, 1, b't' * 16)
            if pid == 1:
                return nc.KernelGeneration(1, 1, 0, 1, 0, b'l' * 16)
            raise OSError('inert missing generation')

        def process(self, pid):
            if pid == 30:
                raise OSError("kernel process identity unavailable")
            return super().process(pid)

        def terminal_login_identity(self, pid):
            if pid != 30 or not self.login_is_terminal:
                raise OSError("boundary unavailable")
            return nc.TerminalBoundary(30, 40, 0, "/usr/bin/login", 300, 400, 3, 4, b"u" * 16)

    def test_unreadable_terminal_login_is_the_end_of_a_non_native_chain(self):
        result = nc.probe_runtime_origin(10, backend=self.Chain())
        self.assertEqual(result.reason, "no_native_runtime")
        self.assertFalse(result.native_lineage)
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(nc, "probe_runtime_origin", return_value=result):
            self.assertIsNone(nc.native_deny_reason({}))

    def test_any_other_unreadable_ancestor_still_fails_closed(self):
        backend = self.Chain()
        backend.login_is_terminal = False
        result = nc.probe_runtime_origin(10, backend=backend)
        self.assertEqual((result.reason, result.failed_pid), ("ancestor_unreadable", 30))  # named now, still uncertain
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(nc, "probe_runtime_origin", return_value=result):
            self.assertIsNotNone(nc.native_deny_reason({}))

    def test_a_native_runtime_below_login_is_still_found(self):
        backend = self.Chain()
        backend.processes[20] = nc.ProcessIdentity(20, 30, 1000, 2, "/Applications/Example/CodexCLI/codex")
        result = nc.probe_runtime_origin(10, backend=backend)
        self.assertEqual(result.origin, "openai")
        self.assertTrue(result.native_lineage)

    def test_the_caller_itself_unreadable_is_never_excused(self):
        backend = self.Chain()
        result = nc.probe_runtime_origin(30, backend=backend)
        self.assertEqual(result.reason, "probe_failed")

    @unittest.skipUnless(sys.platform == "darwin", "exercises the macOS libproc backend")
    def test_real_backend_accepts_only_the_exact_system_login_path(self):
        import ctypes as ct

        def backend(path):
            class FakeLibproc:
                @staticmethod
                def proc_pidinfo(pid, flavor, arg, buffer, size):
                    if flavor == 17:
                        value = nc.DarwinBackend.UniqueInfo.from_buffer_copy(
                            b"u" * 16 + (300).to_bytes(8, sys.byteorder) + (400).to_bytes(8, sys.byteorder)
                            + (3).to_bytes(4, sys.byteorder) + (4).to_bytes(4, sys.byteorder) + b"\0" * 16)
                    else:
                        value = nc.DarwinBackend.ShortBSDInfo()
                        value.pid, value.ppid, value.uid = pid, 40, 0
                    ct.memmove(buffer, ct.byref(value), size)
                    return size

                @staticmethod
                def proc_pidpath(pid, buffer, size):
                    data = path.encode()
                    ct.memmove(buffer, data, len(data))
                    return len(data)

            value = nc.DarwinBackend.__new__(nc.DarwinBackend)
            value.proc = FakeLibproc()
            return value

        self.assertEqual(backend("/usr/bin/login").terminal_login_identity(756).pid, 756)
        for path in ("/usr/bin/login/", "/tmp/usr/bin/login", "/usr/bin/sudo", "/usr/local/bin/login", "login", ""):
            with self.subTest(path=path):
                with self.assertRaises(OSError):
                    backend(path).terminal_login_identity(756)


class StableBoundaryRegressions(unittest.TestCase):
    @dataclass(frozen=True)
    class Record:
        pid: int = 30
        parent: int = 40
        uid: int = 0
        executable: str = "/usr/bin/login"
        unique_id: int = 300
        parent_unique_id: int = 400
        id_version: int = 3
        original_parent_version: int = 4
        executable_uuid: bytes = b"u" * 16

    class Chain(TerminalLoginEndsTheWalk.Chain):
        def __init__(self):
            super().__init__()
            cls = getattr(nc, "TerminalBoundary", StableBoundaryRegressions.Record)
            self.boundary = cls(30, 40, 0, "/usr/bin/login", 300, 400, 3, 4, b"u" * 16)
            self.boundary_calls = 0
            self.mutate = None
            self.codes = {}

        def signature(self, pid):
            return self.codes.get(pid)

        def event(self):
            self.boundary_calls += 1
            if self.mutate:
                self.mutate(self)

        def is_terminal_login(self, pid):
            self.event()
            return pid == 30

        def terminal_login_identity(self, pid):
            self.event()
            return self.boundary

    def denied(self, backend):
        value = nc.probe_runtime_origin(10, backend=backend)
        self.assertNotIn(value.reason, {"no_native_runtime", "nearer_other_runtime"})
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(nc, "probe_runtime_origin", return_value=value):
            self.assertIsNotNone(nc.native_deny_reason({}))

    def test_collected_changes_during_boundary_never_permit_legacy_fallback(self):
        for field, value in (("parent", 41), ("started", 99), ("executable", "/tmp/changed"), ("uid", 0)):
            with self.subTest(field=field):
                b = self.Chain()
                b.mutate = lambda obj, field=field, value=value: obj.processes.__setitem__(20, replace(obj.processes[20], **{field: value}))
                self.denied(b)
        b = self.Chain()
        b.mutate = lambda obj: obj.codes.__setitem__(20, nc.CodeIdentity("codex", nc.OPENAI_TEAM, "b" * 40, "/bin/zsh"))
        self.denied(b)

    def test_boundary_changes_never_permit_legacy_fallback(self):
        for field, value in (("unique_id", 301), ("parent_unique_id", 401), ("parent", 41),
                             ("uid", 501), ("id_version", 4), ("original_parent_version", 5), ("executable_uuid", b"v" * 16),
                             ("executable", "/tmp/login")):
            with self.subTest(field=field):
                b = self.Chain()
                def mutate(obj, field=field, value=value):
                    if obj.boundary_calls >= 2:
                        obj.boundary = replace(obj.boundary, **{field: value})
                b.mutate = mutate
                self.denied(b)

    def test_invalid_boundary_records_never_permit_legacy_fallback(self):
        for changes in ({"uid": 501}, {"pid": 31}, {"parent": 30}, {"unique_id": 0},
                        {"parent_unique_id": 0}, {"id_version": 0}, {"executable_uuid": b""},
                        {"executable": "/usr/bin/login/"}):
            with self.subTest(changes=changes):
                b = self.Chain(); b.boundary = replace(b.boundary, **changes)
                self.denied(b)

    def test_ordinary_pid_one_chain_rechecks_before_no_native_result(self):
        b = self.Chain(); b.processes[20] = replace(b.processes[20], parent=1)
        def changed(pid):
            if pid == 20:
                b.processes[10] = replace(b.processes[10], started=99)
            return None
        b.signature = changed
        self.denied(b)

    def test_stable_boundary_reaches_all_rechecks_without_legacy_boolean(self):
        b = self.Chain()
        def forbidden(_pid):
            self.fail("path-only method must not be called")
        b.is_terminal_login = forbidden
        result = nc.probe_runtime_origin(10, backend=b)
        self.assertEqual(result.reason, "no_native_runtime")
        self.assertGreaterEqual(b.boundary_calls, 3)

    def test_collected_mutation_during_boundary_rechecks_is_seen(self):
        for target in (2, 3):
            with self.subTest(boundary_read=target):
                b = self.Chain()
                def changed(obj, target=target):
                    if obj.boundary_calls == target:
                        obj.processes[20] = replace(obj.processes[20], started=99)
                b.mutate = changed
                self.denied(b)
                self.assertGreaterEqual(b.boundary_calls, target)

    def test_same_path_running_code_change_during_late_boundary_is_seen(self):
        for target in (2, 3):
            with self.subTest(boundary_read=target):
                b = self.Chain()
                original = dict(b.processes)
                def changed(obj, target=target):
                    if obj.boundary_calls == target:
                        obj.codes[20] = nc.CodeIdentity("codex", nc.OPENAI_TEAM, "b" * 40, "/bin/zsh")
                b.mutate = changed
                self.denied(b)
                self.assertEqual(b.processes, original)
                self.assertGreaterEqual(b.boundary_calls, target)

    def test_missing_boolean_or_failed_boundary_is_uncertain(self):
        for value in (True, False, None):
            with self.subTest(value=value):
                b = self.Chain(); b.terminal_login_identity = lambda _pid: value
                self.denied(b)
        b = TerminalLoginEndsTheWalk.Chain()
        with mock.patch.object(type(b), "terminal_login_identity", None):
            self.denied(b)
        b = self.Chain()
        def unavailable(_pid):
            raise OSError("inert failure")
        b.terminal_login_identity = unavailable
        self.denied(b)

    def test_code_recheck_errors_and_changes_at_pid_one_fail_closed(self):
        for failure in (True, False):
            b = self.Chain(); b.processes[20] = replace(b.processes[20], parent=1)
            calls = []
            def signature(pid):
                calls.append(pid)
                if pid == 20 and len(calls) > 2:
                    if failure:
                        raise OSError("inert failed recheck")
                    return nc.CodeIdentity("codex", nc.OPENAI_TEAM, "b" * 40, "/bin/zsh")
                return None
            b.signature = signature
            self.denied(b)


class LoginAncestorRegressions(unittest.TestCase):
    @dataclass(frozen=True)
    class Generation:
        pid: int
        unique_id: int
        parent_unique_id: int
        id_version: int
        original_parent_version: int
        executable_uuid: bytes

    class Chain(StableBoundaryRegressions.Chain):
        def __init__(self):
            super().__init__()
            cls = getattr(nc, 'KernelGeneration', LoginAncestorRegressions.Generation)
            self.processes[20] = replace(self.processes[20], executable='/usr/local/bin/claude')
            self.processes[40] = nc.ProcessIdentity(40, 1, 1000, 4,
                '/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal')
            self.generations = {40: cls(40, 400, 1, 4, 1, b't' * 16),
                                1: cls(1, 1, 0, 1, 0, b'l' * 16)}
            self.generation_reads = []

        def process_generation(self, pid):
            self.generation_reads.append(pid)
            if pid == 30:
                return super().process_generation(pid)
            if pid not in self.generations:
                raise OSError('inert missing generation')
            return self.generations[pid]

    def legacy_main(self, observation):
        import caller_identity as ci
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve() / '.claude'
            sid = '11111111-2222-3333-4444-555555555555'
            transcript = home / 'projects' / 'fixture' / (sid + '.jsonl')
            transcript.parent.mkdir(parents=True)
            transcript.write_text('{}\n')
            payload = {'session_id': sid, 'transcript_path': str(transcript), 'tool_name': 'Bash'}
            with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(nc, 'probe_runtime_origin', return_value=observation):
                return ci.is_main(payload, home)

    def test_direct_native_parent_above_login_never_allows_legacy(self):
        b = self.Chain(); path = '/Applications/Fixture/renamed-runtime'
        b.processes[40] = replace(b.processes[40], executable=path)
        b.codes[40] = nc.CodeIdentity('codex', nc.OPENAI_TEAM, 'c' * 40, path)
        self.assertFalse(self.legacy_main(nc.probe_runtime_origin(10, backend=b)))

    def test_further_native_ancestor_above_login_never_allows_legacy(self):
        b = self.Chain(); path = '/Applications/Fixture/renamed-runtime'
        b.processes[40] = replace(b.processes[40], parent=50, executable='/usr/bin/plain')
        b.generations[40] = replace(b.generations[40], parent_unique_id=500)
        b.processes[50] = nc.ProcessIdentity(50, 1, 1000, 5, path)
        b.generations[50] = replace(b.generations[40], pid=50, unique_id=500, parent_unique_id=1)
        b.codes[50] = nc.CodeIdentity('codex', nc.OPENAI_TEAM, 'd' * 40, path)
        self.assertFalse(self.legacy_main(nc.probe_runtime_origin(10, backend=b)))

    def test_login_parent_unique_mismatch_never_allows_legacy(self):
        b = self.Chain(); b.generations[40] = replace(b.generations[40], unique_id=401)
        self.assertFalse(self.legacy_main(nc.probe_runtime_origin(10, backend=b)))

    def test_normal_terminal_full_chain_remains_a_useful_positive(self):
        b = self.Chain(); result = nc.probe_runtime_origin(10, backend=b)
        self.assertEqual(result.reason, 'no_native_runtime')
        self.assertTrue(self.legacy_main(result))
        self.assertIn(40, b.generation_reads)
        self.assertIn(1, b.generation_reads)

    def assert_denied(self, backend):
        result = nc.probe_runtime_origin(10, backend=backend)
        self.assertFalse(self.legacy_main(result))
        self.assertNotEqual(result.reason, 'no_native_runtime')

    def test_upper_generation_fields_and_pid_one_are_rechecked(self):
        for pid, field, value in ((40, 'unique_id', 401), (40, 'parent_unique_id', 2),
                (40, 'id_version', 9), (40, 'original_parent_version', 9),
                (40, 'executable_uuid', b'v' * 16), (1, 'unique_id', 2),
                (1, 'parent_unique_id', 2), (1, 'id_version', 9)):
            with self.subTest(pid=pid, field=field):
                b = self.Chain()
                def mutate(obj, pid=pid, field=field, value=value):
                    if obj.boundary_calls == 2:
                        obj.generations[pid] = replace(obj.generations[pid], **{field: value})
                b.mutate = mutate
                self.assert_denied(b)
                self.assertGreaterEqual(b.boundary_calls, 2)

    def test_upper_process_and_code_changes_during_boundary_recheck_deny(self):
        for target in (2, 3):
            for field, value in (('uid', 0), ('started', 99), ('parent', 50),
                                 ('executable', '/tmp/changed'), ('code', True)):
                with self.subTest(target=target, field=field):
                    b = self.Chain()
                    def mutate(obj, target=target, field=field, value=value):
                        if obj.boundary_calls == target:
                            if field == 'code':
                                obj.codes[40] = nc.CodeIdentity('codex', nc.OPENAI_TEAM,
                                    'e' * 40, obj.processes[40].executable)
                            else:
                                obj.processes[40] = replace(obj.processes[40], **{field: value})
                    b.mutate = mutate
                    self.assert_denied(b)

    def test_missing_generation_wrong_upper_link_and_unknown_code_deny(self):
        for kind in ('missing', 'malformed', 'init-link', 'zero-root', 'code-error', 'basename'):
            with self.subTest(kind=kind):
                b = self.Chain()
                if kind == 'missing':
                    b.process_generation = None
                elif kind == 'malformed':
                    b.generations[40] = replace(b.generations[40], unique_id=True)
                elif kind == 'init-link':
                    b.generations[40] = replace(b.generations[40], parent_unique_id=2)
                elif kind == 'zero-root':
                    b.processes[40] = replace(b.processes[40], parent=0)
                elif kind == 'code-error':
                    b.signature = lambda _pid: object()
                else:
                    b.processes[40] = replace(b.processes[40], executable='/tmp/codex')
                self.assert_denied(b)

    def test_generation_change_during_upper_process_acquisition_denies(self):
        b = self.Chain()
        original = b.process
        def process(pid):
            value = original(pid)
            if pid == 40:
                b.generations[40] = replace(b.generations[40], id_version=99)
            return value
        b.process = process
        self.assert_denied(b)

    class NestedChain(Chain):
        def __init__(self):
            super().__init__()
            self.processes[40] = replace(self.processes[40], parent=50)
            self.generations[40] = replace(self.generations[40], parent_unique_id=500)
            self.second = nc.TerminalBoundary(50, 60, 0, '/usr/bin/login',
                                            500, 600, 5, 6, b'v' * 16)
            self.processes[60] = nc.ProcessIdentity(60, 1, 1000, 6, '/usr/bin/plain')
            self.generations[50] = nc.KernelGeneration(50, 500, 600, 5, 6, b'v' * 16)
            self.generations[60] = nc.KernelGeneration(60, 600, 1, 6, 1, b'w' * 16)
            self.second_calls = 0
            self.nested_mutate = None

        def process(self, pid):
            if pid == 50:
                raise OSError('inert nested login full BSD restriction')
            return super().process(pid)

        def terminal_login_identity(self, pid):
            if pid == 50:
                self.second_calls += 1
                if self.nested_mutate:
                    self.nested_mutate(self)
                return self.second
            return super().terminal_login_identity(pid)

    def test_nested_logins_continue_and_retain_earlier_boundary(self):
        b = self.NestedChain()
        result = nc.probe_runtime_origin(10, backend=b)
        self.assertEqual(result.reason, 'no_native_runtime')
        self.assertTrue(self.legacy_main(result))
        self.assertGreaterEqual(b.second_calls, 3)
        b = self.NestedChain()
        def mutate(obj):
            if obj.second_calls == 2:
                obj.boundary = replace(obj.boundary, id_version=99)
        b.nested_mutate = mutate
        self.assert_denied(b)
        b = self.NestedChain()
        b.codes[60] = nc.CodeIdentity('codex', nc.OPENAI_TEAM, 'f' * 40,
                                    b.processes[60].executable)
        self.assert_denied(b)

    def test_upper_ancestry_shares_cycle_and_hop_budget(self):
        b = self.Chain()
        b.processes[40] = replace(b.processes[40], parent=30)
        b.generations[40] = replace(b.generations[40], parent_unique_id=300)
        self.assert_denied(b)
        b = self.Chain()
        for pid in range(40, 75):
            b.processes[pid] = nc.ProcessIdentity(pid, pid + 1, 1000, pid, '/usr/bin/plain')
            b.generations[pid] = nc.KernelGeneration(pid, pid * 10, (pid + 1) * 10,
                                                    pid, pid + 1, b'z' * 16)
        self.assert_denied(b)


class KernelBoundaryABI(unittest.TestCase):
    def backend(self, *, results=None, mutate=None, path="/usr/bin/login", path_result=None):
        import ctypes as ct
        calls = []
        class InertLibproc:
            @staticmethod
            def proc_pidinfo(pid, flavor, arg, buffer, size):
                calls.append((flavor, arg, size))
                if flavor == 17:
                    value = nc.DarwinBackend.UniqueInfo()
                    value.uuid[:] = b"u" * 16
                    value.uniqueid, value.parent_uniqueid = 300, 400
                    value.idversion, value.original_parent_version = 3, 4
                    if mutate and len(calls) == 3:
                        mutate(value)
                else:
                    value = nc.DarwinBackend.ShortBSDInfo()
                    value.pid, value.ppid, value.uid = pid, 40, 0
                self.assertEqual(arg, 0)
                self.assertEqual(size, 56 if flavor == 17 else 64)
                ct.memmove(buffer, ct.byref(value), size)
                return (results or {}).get(flavor, size)

            @staticmethod
            def proc_pidpath(pid, buffer, size):
                data = path.encode()
                ct.memmove(buffer, data, len(data))
                return len(data) if path_result is None else path_result
        backend = nc.DarwinBackend.__new__(nc.DarwinBackend)
        backend.proc = InertLibproc()
        return backend, calls

    def test_exact_abi_success_and_live_argument(self):
        import ctypes as ct
        self.assertEqual(ct.sizeof(nc.DarwinBackend.ShortBSDInfo), 64)
        self.assertEqual(ct.sizeof(nc.DarwinBackend.UniqueInfo), 56)
        backend, calls = self.backend()
        self.assertEqual(backend.terminal_login_identity(30),
                         nc.TerminalBoundary(30, 40, 0, "/usr/bin/login", 300, 400, 3, 4, b"u" * 16))
        self.assertEqual(calls, [(17, 0, 56), (13, 0, 64), (17, 0, 56)])

    def test_upper_generation_reader_uses_exact_live_abi_and_bounds(self):
        backend, calls = self.backend()
        self.assertEqual(backend.process_generation(30),
            nc.KernelGeneration(30, 300, 400, 3, 4, b'u' * 16))
        self.assertEqual(calls, [(17, 0, 56)])
        for result in (-1, 0, 55, 57):
            with self.subTest(result=result), self.assertRaises(OSError):
                self.backend(results={17: result})[0].process_generation(30)
        for pid in (True, 0, -1, 2 ** 31, '30'):
            with self.subTest(pid=pid), self.assertRaises(OSError):
                backend.process_generation(pid)
        with self.assertRaises(OSError):
            backend.process_generation(1)  # Fake has nonzero parent ID; real init must have zero.

    def test_bad_sizes_and_missing_paths_fail_closed(self):
        for flavor, values in ((13, (-1, 0, 63, 65)), (17, (-1, 0, 55, 57))):
            for result in values:
                with self.subTest(flavor=flavor, result=result), self.assertRaises(OSError):
                    self.backend(results={flavor: result})[0].terminal_login_identity(30)
        for result in (-1, 0, 4, 4096, 8192):
            with self.subTest(path_result=result), self.assertRaises(OSError):
                self.backend(path_result=result)[0].terminal_login_identity(30)

    def test_each_meaningful_unique_field_is_bracketed(self):
        for name, value in (("uniqueid", 301), ("parent_uniqueid", 401), ("idversion", 4),
                            ("original_parent_version", 5)):
            with self.subTest(name=name), self.assertRaises(OSError):
                self.backend(mutate=lambda obj, name=name, value=value: setattr(obj, name, value))[0].terminal_login_identity(30)
        with self.assertRaises(OSError):
            self.backend(mutate=lambda obj: obj.uuid.__setitem__(0, 0))[0].terminal_login_identity(30)


class ProbeFailureReasons(unittest.TestCase):
    """goodqa#15646 plan A: a failed probe names WHICH ancestor failed and why. Behaviour stays fail-closed."""

    class Failing(FakeBackend):
        def __init__(self, reason, pid=20, name="claude"):
            super().__init__()
            self.processes[10] = nc.ProcessIdentity(10, 20, 1000, 1, "/usr/bin/python3")
            self.reason, self.fail_pid, self.fail_name = reason, pid, name

        def process(self, pid):
            if pid == self.fail_pid:
                raise nc.ProbeFailure(self.reason, pid, self.fail_name)
            return super().process(pid)

    def test_each_reason_code_is_reported_with_the_failing_pid_and_name(self):
        for reason in ("ancestor_binary_replaced", "ancestor_unreadable", "signature_refused"):
            with self.subTest(reason=reason):
                value = nc.probe_runtime_origin(10, backend=self.Failing(reason))
                self.assertEqual((value.origin, value.reason, value.failed_pid, value.failed_name),
                                 ("unknown", reason, 20, "claude"))
                self.assertFalse(value.main_authority)

    def test_a_named_failure_still_denies_main_and_never_falls_through(self):
        for reason in ("ancestor_binary_replaced", "ancestor_unreadable", "signature_refused"):
            with self.subTest(reason=reason):
                value = nc.probe_runtime_origin(10, backend=self.Failing(reason))
                with mock.patch.dict(os.environ, {}, clear=True), \
                        mock.patch.object(nc, "probe_runtime_origin", return_value=value):
                    self.assertEqual(nc.native_deny_reason({}), "runtime_origin_uncertain")

    def test_a_replaced_binary_is_never_offered_to_the_login_boundary_path(self):
        class Guarded(self.Failing):
            def terminal_login_identity(self, pid):
                raise AssertionError("a replaced binary must not be examined as a login boundary")
        for reason in ("ancestor_binary_replaced", "signature_refused"):
            with self.subTest(reason=reason):
                value = nc.probe_runtime_origin(10, backend=Guarded(reason))
                self.assertEqual((value.reason, value.failed_pid), (reason, 20))

    def test_an_unreadable_ancestor_that_is_not_a_login_is_named_not_generic(self):
        class NotLogin(self.Failing):
            def terminal_login_identity(self, pid):
                raise OSError("not a login boundary")
        value = nc.probe_runtime_origin(10, backend=NotLogin("ancestor_unreadable"))
        self.assertEqual((value.reason, value.failed_pid), ("ancestor_unreadable", 20))

    def test_a_generic_error_is_still_probe_failed_without_a_pid(self):
        class Generic(FakeBackend):
            def process(self, pid):
                if pid == 20:
                    raise OSError("something else")
                return super().process(pid)
        value = nc.probe_runtime_origin(10, backend=Generic())
        self.assertEqual((value.reason, value.failed_pid, value.failed_name), ("probe_failed", None, ""))

    def test_the_failing_name_is_clean_text_never_a_path(self):
        value = nc.probe_runtime_origin(10, backend=self.Failing("ancestor_unreadable", name="/tmp/x y\n;rm"))
        self.assertRegex(value.failed_name, r"^[A-Za-z0-9._-]{0,32}$")
        self.assertNotIn("/", value.failed_name)

    def test_the_caller_itself_failing_is_reported_too(self):
        value = nc.probe_runtime_origin(10, backend=self.Failing("ancestor_unreadable", pid=10, name="python3"))
        self.assertEqual((value.reason, value.failed_pid), ("ancestor_unreadable", 10))

    @staticmethod
    def libproc(pidinfo_ok, path_len, comm=b"claude"):
        class Fake:
            @staticmethod
            def proc_pidinfo(pid, flavor, arg, ref, size):
                if not pidinfo_ok:
                    return 0
                info = ref._obj
                info.pid, info.ppid, info.uid, info.start_sec, info.start_usec = pid, 761, 501, 1794126395, 763881
                info.comm = comm
                return size

            @staticmethod
            def proc_pidpath(pid, buffer, size):
                return path_len
        backend = nc.DarwinBackend.__new__(nc.DarwinBackend)
        backend.proc = Fake()
        return backend

    @unittest.skipUnless(sys.platform == "darwin", "exercises the macOS libproc backend")
    def test_real_backend_tells_a_replaced_binary_from_an_unreadable_process(self):
        with self.assertRaises(nc.ProbeFailure) as replaced:
            self.libproc(True, 0).process(2990)
        self.assertEqual((replaced.exception.reason, replaced.exception.pid, replaced.exception.name),
                         ("ancestor_binary_replaced", 2990, "claude"))
        with self.assertRaises(nc.ProbeFailure) as unreadable:
            self.libproc(False, 0).process(756)
        self.assertEqual((unreadable.exception.reason, unreadable.exception.pid), ("ancestor_unreadable", 756))

    @unittest.skipUnless(sys.platform == "darwin", "exercises the macOS libproc backend")
    def test_a_readable_process_is_still_returned(self):
        value = self.libproc(True, len(b"/usr/bin/true"), b"true").process(321)
        self.assertEqual((value.pid, value.parent), (321, 761))

    @unittest.skipUnless(sys.platform == "darwin", "exercises the macOS Security backend")
    def test_a_refused_guest_lookup_is_signature_refused(self):
        class Cf:
            def __getattr__(self, name):
                return lambda *args: 1

        class Sec:
            @staticmethod
            def SecCodeCopyGuestWithAttributes(*args):
                return 100002

        backend = nc.DarwinBackend.__new__(nc.DarwinBackend)
        backend.cf, backend.sec = Cf(), Sec()
        backend._constant = lambda name: 1
        with self.assertRaises(nc.ProbeFailure) as refused:
            backend.signature(2990)
        self.assertEqual((refused.exception.reason, refused.exception.pid), ("signature_refused", 2990))


class StaleRuntimeDetector(unittest.TestCase):
    """Runtime processes whose binary was deleted by a self-update, so restarts are scheduled, not discovered."""

    @staticmethod
    def backend(rows):
        """rows: pid -> (pidinfo_ok, path_len, comm, ppid)."""
        class Fake:
            @staticmethod
            def proc_listallpids(buffer, size):
                import ctypes as ct
                pids = sorted(rows)
                if buffer is None:
                    return len(pids)  # the real call returns a pid count
                array = ct.cast(buffer, ct.POINTER(ct.c_int))
                for i, pid in enumerate(pids):
                    array[i] = pid
                return len(pids)

            @staticmethod
            def proc_pidinfo(pid, flavor, arg, ref, size):
                ok, _, comm, ppid = rows[pid]
                if not ok:
                    return 0
                info = ref._obj
                info.pid, info.ppid, info.uid, info.start_sec, info.start_usec = pid, ppid, 501, 1794126395, 5
                info.comm = comm
                return size

            @staticmethod
            def proc_pidpath(pid, buffer, size):
                return rows[pid][1]
        backend = nc.DarwinBackend.__new__(nc.DarwinBackend)
        backend.proc = Fake()
        return backend

    @unittest.skipUnless(sys.platform == "darwin", "exercises the macOS libproc backend")
    def test_lists_only_runtime_processes_that_lost_their_binary(self):
        rows = {
            100: (True, 0, b"claude", 7),        # stale Claude session
            101: (True, 0, b"2.1.319", 7),       # stale versioned Claude binary name
            102: (True, 0, b"codex", 7),         # stale Codex
            103: (True, 15, b"claude", 7),       # live runtime: has a kernel path
            104: (True, 0, b"sleep", 7),         # not a runtime: ignored
            105: (False, 0, b"claude", 7),       # other uid or gone: cannot tell, not listed
        }
        found = nc.stale_runtime_processes(backend=self.backend(rows))
        self.assertEqual([(row["pid"], row["name"]) for row in found],
                         [(100, "claude"), (101, "2.1.319"), (102, "codex")])
        self.assertTrue(all(set(row) == {"pid", "ppid", "name", "started"} for row in found))

    @unittest.skipUnless(sys.platform == "darwin", "exercises the macOS libproc backend")
    def test_no_stale_runtime_is_an_empty_list(self):
        self.assertEqual(nc.stale_runtime_processes(backend=self.backend({100: (True, 15, b"claude", 7)})), [])

    def test_unsupported_platform_is_an_empty_list_never_an_error(self):
        with mock.patch.object(nc.sys, "platform", "linux"):
            self.assertEqual(nc.stale_runtime_processes(), [])


class Packaging(unittest.TestCase):
    @staticmethod
    def manifest(filename, field):
        import ast
        root = Path(__file__).resolve().parents[1]
        tree = ast.parse((root / filename).read_text())
        assignment = next(node for node in tree.body if isinstance(node, ast.Assign)
                          and any(isinstance(target, ast.Name) and target.id == field for target in node.targets))
        return ast.literal_eval(assignment.value)

    def test_both_manifests_ship_native_dependencies_without_running_installers(self):
        expected = {"native_context.py", "native_user_source.py", "native_admission.py"}
        for filename, field in (("install.py", "HOOKS"), ("install_codex.py", "DELIVERY_HELPERS")):
            # Read the literal manifest via AST; importing/running installers is
            # unnecessary and could change local configuration.
            names = self.manifest(filename, field)
            self.assertTrue(expected <= set(names), (filename, expected - set(names)))
            self.assertTrue(all(names.count(name) == 1 for name in expected))

    def test_fresh_codex_helper_set_imports_wal_note_and_passes_ah_doctor(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as folder:
            home = Path(folder) / "home"; home.mkdir()
            helpers = home / ".codex" / "agent-harness"; helpers.mkdir(parents=True)
            # Exercise the actual declarative copy set in a fresh isolated home,
            # plus the installer's two explicit helper copies. No installer or
            # hook configuration is executed, and no real service is contacted.
            for name in self.manifest("install_codex.py", "DELIVERY_HELPERS"):
                shutil.copyfile(root / "harness" / "hooks" / name, helpers / name)
            shutil.copyfile(root / "codex" / "hooks" / "wal.py", helpers / "wal.py")
            shutil.copyfile(root / "harness" / "hooks" / "ops_watch.py", helpers / "ops_watch.py")
            code = ("import json,sys; sys.path.insert(0,sys.argv[1]); import wal_note,ah; "
                    "print(json.dumps(ah.doctor(),sort_keys=True))")
            env = {key: value for key, value in os.environ.items() if key in {"PATH", "SYSTEMROOT"}}
            env.update(HOME=str(home), AH_HOME=str(home), AH_EXPECT_AHD="0")
            run = subprocess.run([sys.executable, "-I", "-B", "-c", code, str(helpers)],
                                 env=env, cwd=home, text=True, capture_output=True, timeout=5)
            self.assertEqual(run.returncode, 0, run.stderr)
            result = json.loads(run.stdout)
            self.assertTrue(result["ok"], result)
            self.assertTrue(any(row["check"] == "import wal_note" and row["ok"] for row in result["checks"]))
            self.assertFalse((home / ".codex" / "hooks.json").exists())
            self.assertFalse((home / ".codex" / "config.toml").exists())


if __name__ == "__main__":
    unittest.main()
