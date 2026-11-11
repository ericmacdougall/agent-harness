"""Exact GoodQA delivery profiles and nonvacuous result contracts."""

import json
import io
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from contextlib import redirect_stdout
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "harness" / "hooks"))
import integrate_local as delivery
import deliver as remote_delivery


DESKTOP = ["npm", "run", "test:release", "--", "--only=desktop"]
PYTEST = ["python3", "-m", "pytest", "-q", "bin/test_goodqa_bugs_release.py"]
PREPARATION = ["npm", "ci", "--prefer-offline"]
LEGACY = ["python3", "-m", "unittest", "discover", "-s", "tests"]
PREPARATION_HOLD = "Scoped delivery checks do not support preparation commands"
BASELINE_HOLD = "Scoped delivery profiles cannot certify an unrelated recovery baseline"
UNITTESTS = [
    ["python3", "-m", "unittest", "discover", "-s", directory, "-p", filename]
    for directory, filename in (
        ("bin", "test_release_bootstrap.py"),
        ("lanes/qac-pool-runner", "test_release_authority_boundaries.py"),
        ("lanes/qac-pool-runner", "test_release_bindings.py"),
    )
]
GO = ["go", "-C", "framework", "test", "-mod=readonly", "-count=1", "-json", "-run",
      "^(TestProductionTransportSelectorStopsBeforePython|TestTriageDryRunRequiresExactAggregateOutcome|"
      "TestHeldQualificationListenerIsBoundLoopbackAndNoLease)$", "./cmd/harness-release", "./internal/testguard"]
GO_CURRENT = [*GO[:8], GO[8][:-2] + "|TestOwnedTriageUnitTextUsesClosedClassifier)$", *GO[9:]]
PACKAGE = "harness/framework/cmd/harness-release"
OTHER = "harness/framework/internal/testguard"
PARENT = "TestProductionTransportSelectorStopsBeforePython"
CHILDREN = (PARENT + "/approved", PARENT + "/changed-target")
TRIAGE = "TestTriageDryRunRequiresExactAggregateOutcome"
LISTENER = "TestHeldQualificationListenerIsBoundLoopbackAndNoLease"
CLASSIFIER = "TestOwnedTriageUnitTextUsesClosedClassifier"
CLASSIFIER_CHILDREN = tuple(CLASSIFIER + "/" + suffix for suffix in (
    "qac-held-release-15648-triage-owned-unit-classifier.service",
    "qac-held-release-15648-triage-owned-unit-classifier.timer",
    "99-held-release-15648.conf",
))


class ScopeGrammar(unittest.TestCase):
    def test_preparation_plan_admission_preserves_held_and_legacy_vectors(self):
        with mock.patch.multiple(delivery, _scoped_original=mock.DEFAULT, _scoped_result_root=mock.DEFAULT,
                                 _scoped_tool=mock.DEFAULT, resolve_check_interpreter=mock.DEFAULT) as probes:
            for command in (*UNITTESTS, GO, GO_CURRENT):
                with self.subTest(vector=command[0], selector=command[-1]):
                    with self.assertRaisesRegex(delivery.CheckInterpreterError, PREPARATION_HOLD):
                        delivery.require_check_interpreters([LEGACY, command], preparations=[PREPARATION])
                    with self.assertRaisesRegex(delivery.CheckInterpreterError, PREPARATION_HOLD):
                        delivery.scoped_check_context([command], None, None, preparations=[PREPARATION])
            for held in (DESKTOP, PYTEST):
                with self.subTest(held=held[0]):
                    with self.assertRaises(delivery.CheckInterpreterError) as error:
                        delivery.require_check_interpreters([GO, held], preparations=[PREPARATION])
                    self.assertEqual(str(error.exception), delivery.SCOPED_HOLDS[tuple(held)])
            for probe in probes.values():
                probe.assert_not_called()
            self.assertIsNone(delivery.scoped_check_context([LEGACY], None, None, preparations=[PREPARATION]))
            delivery.require_check_interpreters([LEGACY], preparations=[PREPARATION])
            probes["resolve_check_interpreter"].assert_called_once_with("python3")

    def test_finish_combination_is_refused_before_workflow_or_interpreter(self):
        args = SimpleNamespace(prepare=[shlex.join(PREPARATION)], check=[shlex.join(UNITTESTS[0])],
                               original=Path.cwd(), resolve_baseline=None)
        with mock.patch.object(remote_delivery, "Workflow") as workflow, \
                mock.patch.object(delivery, "_scoped_original") as probe:
            with self.assertRaisesRegex(remote_delivery.DeliveryError, PREPARATION_HOLD) as error:
                remote_delivery.finish(args)
        self.assertEqual((error.exception.status, error.exception.code), ("BLOCKED_POLICY", 2))
        workflow.assert_not_called()
        probe.assert_not_called()

    def test_direct_delivery_scope_refuses_before_environment_or_flow_lookup(self):
        flow = mock.Mock(original=Path.cwd(), state={"source_head": "1" * 40})
        with mock.patch.object(remote_delivery, "require_scoped_environment",
                               side_effect=delivery.CheckInterpreterError("fixture environment reached")) as environment:
            with self.subTest(boundary="policy"):
                with self.assertRaisesRegex(remote_delivery.DeliveryError, PREPARATION_HOLD):
                    remote_delivery.delivery_check_scope(flow, [UNITTESTS[0]], preparations=[PREPARATION])
            with self.subTest(boundary="no-environment"):
                environment.assert_not_called()

    def test_exact_vectors_are_recognized(self):
        for command in [DESKTOP, PYTEST, GO, GO_CURRENT, *UNITTESTS]:
            with self.subTest(command=command):
                self.assertTrue(delivery.approved_check(command))
                self.assertEqual(remote_delivery.approved_commands([shlex.join(command)]), [command])

    def test_extra_or_altered_arguments_do_not_widen_selection(self):
        for command in [DESKTOP, PYTEST, GO, GO_CURRENT, *UNITTESTS]:
            with self.subTest(command=command):
                self.assertFalse(delivery.approved_check([*command, "--extra"]))
        for command in (
            ["npm", "run", "test:release", "--", "--only=api"],
            ["python3", "-m", "pytest", "-q", "bin/../bin/test_goodqa_bugs_release.py"],
            [*UNITTESTS[0][:-1], "test_other.py"],
            [*GO[:-1], "./..."],
            ["node", "--test", "apps/desktop/src/agent-browser/main.test.ts"],
        ):
            self.assertFalse(delivery.approved_check(command), command)

    def test_desktop_recognized_but_preflight_holds_before_execution(self):
        with mock.patch.object(delivery, "run_process") as child:
            with self.assertRaisesRegex(delivery.CheckInterpreterError, "per-file"):
                delivery.require_check_interpreters([DESKTOP], Path.cwd())
            child.assert_not_called()

    def test_pytest_holds_before_checkout_or_interpreter_access(self):
        with mock.patch.object(delivery, "_scoped_original", return_value=(Path.cwd(), None, None, None)) as original, \
                mock.patch.object(delivery, "_scoped_tool") as tool, \
                mock.patch.object(delivery, "run_process") as child:
            with self.assertRaisesRegex(delivery.CheckInterpreterError, "pytest.*closure"):
                delivery.require_check_interpreters([PYTEST], Path.cwd())
            with self.assertRaisesRegex(delivery.CheckInterpreterError, "pytest.*closure"):
                delivery.require_check_interpreters([GO, PYTEST], Path.cwd())
            with self.assertRaisesRegex(delivery.CheckInterpreterError, "pytest.*closure"):
                delivery.run(Path.cwd(), PYTEST)
            original.assert_not_called()
            tool.assert_not_called()
            child.assert_not_called()

    def test_ambient_temporary_roots_refuse_even_when_empty(self):
        for key in ("TMPDIR", "TEMP", "TMP", "TEMPDIR"):
            with self.subTest(key=key):
                with self.assertRaisesRegex(delivery.CheckInterpreterError, "environment"):
                    delivery.scoped_environment(UNITTESTS[0], {"HOME": delivery.SCOPED_HOME, key: ""})

    def test_typed_run_without_scope_holds_before_execution(self):
        with mock.patch.object(delivery, "run_process") as child:
            for command in [GO, GO_CURRENT, *UNITTESTS]:
                with self.assertRaisesRegex(delivery.CheckInterpreterError, "bound delivery context"):
                    delivery.run(Path.cwd(), command)
            with self.assertRaisesRegex(delivery.CheckInterpreterError, "per-file"):
                delivery.run(Path.cwd(), DESKTOP)
            child.assert_not_called()

    def test_go_vector_cannot_be_reused_on_other_revision(self):
        for command, source in (
            (GO, delivery.SCOPED_HARNESS_CURRENT),
            (GO_CURRENT, delivery.SCOPED_HARNESS_SOURCE),
        ):
            with mock.patch.object(delivery, "_scoped_original") as original:
                with self.assertRaisesRegex(delivery.CheckInterpreterError, "source revision"):
                    delivery.scoped_check_context([command], Path.cwd(), source)
                original.assert_not_called()


def event(action, package, test=None):
    record = {"Action": action, "Package": package}
    if test is not None:
        record["Test"] = test
    return record


def go_events():
    events = [event("start", PACKAGE), event("start", OTHER), event("run", PACKAGE, PARENT)]
    for child in CHILDREN:
        events.extend((event("run", PACKAGE, child), event("pass", PACKAGE, child)))
    events.append(event("pass", PACKAGE, PARENT))
    for package, name in ((PACKAGE, TRIAGE), (OTHER, LISTENER)):
        events.extend((event("run", package, name), event("pass", package, name), event("pass", package)))
    return events


class GoResult(unittest.TestCase):
    def check_events(self, events, command=GO):
        evidence = delivery.ScopedGoEvidence(tuple(command))
        raw = b"".join((json.dumps(value) + "\n").encode() for value in events)
        for offset in range(0, len(raw), 19):
            evidence(raw[offset:offset + 19])
        return evidence.passed()

    def test_parent_and_both_children_required(self):
        self.assertTrue(self.check_events(go_events()))
        for child in CHILDREN:
            with self.subTest(child=child):
                self.assertFalse(self.check_events([row for row in go_events() if row.get("Test") != child]))

    def test_skipped_duplicate_wrong_package_or_parent_lifetime_refuse(self):
        good = go_events()
        for update in (
            [dict(row, Action="skip") if row.get("Test") == CHILDREN[0] and row["Action"] == "pass" else row
             for row in good],
            good[:4] + [good[3]] + good[4:],
            [dict(row, Package=OTHER) if row.get("Test") == CHILDREN[0] else row for row in good],
            [*good[:2], *good[3:5], good[2], *good[5:]],
            [*good[:-1], event("run", OTHER, "TestOther"), good[-1]],
            good[:-1],
        ):
            self.assertFalse(self.check_events(update))

    def test_ambient_fixture_control_refuses_even_when_empty(self):
        for name in ("QAC_BINDING_CONTROL_CHILD", "QAC_BINDING_FIXTURE_ROOT", "QAC_API", "LANE_ROOT"):
            with self.subTest(name=name):
                with self.assertRaisesRegex(delivery.CheckInterpreterError, "environment"):
                    delivery.scoped_environment(GO, {name: ""})

    def test_current_classifier_needs_each_child_in_any_order(self):
        old = go_events()
        self.assertFalse(self.check_events(old, GO_CURRENT))
        for children in (CLASSIFIER_CHILDREN, CLASSIFIER_CHILDREN[::-1]):
            classifier = [event("run", PACKAGE, CLASSIFIER)]
            for child in children:
                classifier.extend((event("run", PACKAGE, child), event("pass", PACKAGE, child)))
            classifier.append(event("pass", PACKAGE, CLASSIFIER))
            index = old.index(event("pass", PACKAGE))
            current = [*old[:index], *classifier, *old[index:]]
            self.assertTrue(self.check_events(current, GO_CURRENT))
            self.assertFalse(self.check_events(current))
            for child in children:
                self.assertFalse(self.check_events([row for row in current if row.get("Test") != child],
                                                   GO_CURRENT))
                self.assertFalse(self.check_events(
                    [dict(row, Action="skip") if row.get("Test") == child and row["Action"] == "pass" else row
                     for row in current], GO_CURRENT))


class OwnedScopedExecution(unittest.TestCase):
    def git(self, *args):
        environment = {**delivery.git_environment(isolated=True), "GIT_AUTHOR_NAME": "Fixture",
                       "GIT_AUTHOR_EMAIL": "fixture@example.invalid", "GIT_COMMITTER_NAME": "Fixture",
                       "GIT_COMMITTER_EMAIL": "fixture@example.invalid"}
        return subprocess.check_output(["git", "-C", str(self.repo), *args], env=environment,
                                       stderr=subprocess.STDOUT, text=True, timeout=5).strip()

    def setUp(self):
        if sys.version_info < (3, 10) or os.geteuid() == 0:
            self.skipTest("scoped execution requires a supported non-root Python")
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.repo = Path(temporary.name).resolve()
        result_parent = tempfile.TemporaryDirectory()
        self.addCleanup(result_parent.cleanup)
        self.results = Path(result_parent.name).resolve()
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.name", "Fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        self.git("remote", "add", "origin", "https://github.com/ericmacdougall/bugtracker-harness.git")
        self.selected = self.repo / "bin/test_release_bootstrap.py"
        self.selected.parent.mkdir()
        self.python = Path(sys.executable).resolve()
        self.home = str(Path.home())
        self.environment = {"HOME": self.home}
        patches = mock.patch.multiple(delivery, SCOPED_HARNESS_ROOT=self.repo, SCOPED_HOME=self.home,
                                      SCOPED_RESULT_ROOT=self.results,
                                      SCOPED_TOOLS={"python3": (self.python, self.python)},
                                      SCOPED_TOOL_UID=self.python.stat().st_uid)
        patches.start()
        self.addCleanup(patches.stop)

    def select(self, code):
        self.selected.write_text(code)
        self.git("add", "--", "bin/test_release_bootstrap.py")
        self.git("commit", "-qm", "owned test fixture")
        head, tree = self.git("rev-parse", "HEAD"), self.git("rev-parse", "HEAD^{tree}")
        patch = mock.patch.dict(delivery.SCOPED_HARNESS_TREES, {head: tree})
        patch.start()
        self.addCleanup(patch.stop)
        return delivery.scoped_check_context([UNITTESTS[0]], self.repo, head, target=head)

    def run_selected(self, scope, receipts):
        return delivery.run(self.repo, UNITTESTS[0], timeout=10, discard_output=True,
                            scoped_context=scope, env=self.environment, sink=receipts.append)

    def test_actual_disposable_runner_and_context_bound_receipt(self):
        scope = self.select("import unittest\nclass Fixture(unittest.TestCase):\n    def test_real(self):\n"
                            "        self.assertEqual(2+3, 5)\n")
        receipts = []
        self.assertEqual(self.run_selected(scope, receipts).returncode, 0)
        [receipt] = [json.loads(line) for line in receipts]
        self.assertEqual(receipt["source"], scope.source)
        self.assertEqual(receipt["head"], scope.target)
        self.assertEqual(receipt["checkout"], list(scope.checkout_identity))
        self.assertEqual(set(receipt["inputs"]), {"bin/test_release_bootstrap.py"})

    def test_remote_check_dispatch_records_only_validated_scoped_result(self):
        scope = self.select("import unittest\nclass Fixture(unittest.TestCase):\n    def test_real(self):\n"
                            "        self.assertEqual(2+3, 5)\n")
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(
                os.environ, {**self.environment, "PATH": os.defpath}, clear=True):
            logs = Path(directory) / "checks"
            remote_delivery.run_checks(self.repo, [], [UNITTESTS[0]], 10, logs, scoped_context=scope)
            [path] = logs.iterdir()
            record = json.loads(path.read_text().splitlines()[-1])
        self.assertEqual(record["head"], scope.target)
        self.assertEqual(record["kind"], "scoped-check-pass")

    def test_direct_check_dispatch_preserves_one_shot_inputs(self):
        scope = self.select("import unittest\nclass Fixture(unittest.TestCase):\n"
                            "    def test_real(self):\n        self.assertEqual(2+3, 5)\n")
        with mock.patch.object(remote_delivery, "run_check", return_value=subprocess.CompletedProcess(LEGACY, 0)) as run:
            remote_delivery.run_checks(self.repo, iter([PREPARATION]), iter([LEGACY]), 5, self.results / "legacy")
            with self.subTest(boundary="legacy-ordered-dispatch"):
                self.assertEqual([call.args[1] for call in run.call_args_list], [PREPARATION, LEGACY])
        logs = self.results / "scoped"
        with mock.patch.dict(os.environ, {**self.environment, "PATH": os.defpath}, clear=True):
            try:
                remote_delivery.run_checks(self.repo, iter(()), iter([UNITTESTS[0]]), 5, logs, scoped_context=scope)
            except remote_delivery.DeliveryError as error:
                self.fail(f"empty preparation iterator must allow a scoped run: {error.status}")
        [path] = logs.iterdir()
        record = json.loads(path.read_text().splitlines()[-1])
        self.assertEqual((record["kind"], record["head"]), ("scoped-check-pass", scope.target))

    def test_local_delivery_checks_owned_scratch_and_final_tree(self):
        base, scope, argv = self.local_candidate()
        status, output = self.local_run(argv)
        self.assertEqual(status, 0, output)
        self.assertEqual(json.loads(output)["status"], "INTEGRATED")
        self.assertEqual(self.git("rev-parse", "HEAD^{tree}"), delivery.SCOPED_HARNESS_TREES[scope.source])

    def local_candidate(self):
        self.git("commit", "--allow-empty", "-qm", "owned baseline")
        base = self.git("rev-parse", "HEAD")
        self.git("checkout", "-qb", "feature")
        scope = self.select("import unittest\nclass Fixture(unittest.TestCase):\n    def test_real(self):\n"
                            "        self.assertEqual(2+3, 5)\n")
        self.git("checkout", "-q", "main")
        argv = ["integrate_local.py", "--repo", str(self.repo), "--original-branch", "main",
                "--source", "feature", "--expected-head", base, "--expected-source-head", scope.source,
                "--timeout", "8", "--check-timeout", "10", "--check", shlex.join(UNITTESTS[0])]
        return base, scope, argv

    def local_run(self, argv):
        output = io.StringIO()
        with mock.patch.dict(os.environ, {**self.environment, "PATH": os.defpath}, clear=True), \
                mock.patch.object(sys, "argv", argv), redirect_stdout(output):
            status = delivery.main()
        return status, output.getvalue()

    def test_ignored_or_untracked_original_never_advances_locally(self):
        base, _, argv = self.local_candidate()
        (self.repo / ".git/info/exclude").write_text("ignored-artifact\n")
        for name in ("ignored-artifact", "untracked-artifact"):
            with self.subTest(name=name):
                artifact = self.repo / name
                artifact.write_text("owned fixture")
                try:
                    with mock.patch.object(delivery, "scratch_journal_root",
                                           wraps=delivery.scratch_journal_root) as reserve:
                        status, output = self.local_run(argv)
                    self.assertNotEqual(status, 0, output)
                    self.assertEqual(self.git("rev-parse", "HEAD"), base)
                    reserve.assert_not_called()
                finally:
                    artifact.unlink()

    def test_unsafe_target_git_mode_holds_before_reservation(self):
        base, candidate, argv = self.local_candidate()
        self.git("checkout", "-q", "feature")
        self.selected.unlink()
        self.selected.symlink_to("other.py")
        self.git("add", "--", "bin/test_release_bootstrap.py")
        self.git("commit", "-qm", "owned aliased target")
        target, tree = self.git("rev-parse", "HEAD"), self.git("rev-parse", "HEAD^{tree}")
        self.git("checkout", "-q", "main")
        argv[argv.index(candidate.source)] = target
        with mock.patch.dict(delivery.SCOPED_HARNESS_TREES, {target: tree}), \
                mock.patch.object(delivery, "scratch_journal_root", wraps=delivery.scratch_journal_root) as reserve:
            status, output = self.local_run(argv)
        self.assertEqual(status, 2, output)
        self.assertIn("unsafe Git mode", output)
        self.assertEqual(self.git("rev-parse", "HEAD"), base)
        reserve.assert_not_called()

    def test_original_preexisting_ignored_file_never_advances_remotely(self):
        base, candidate, _ = self.local_candidate()
        (self.repo / ".git/info/exclude").write_text("ignored-artifact\n")
        (self.repo / "ignored-artifact").write_text("owned fixture")
        flow, original_scope = self.remote_run_fixture(base, candidate)
        flow.save.assert_not_called()
        original_scope.__enter__.return_value.reserve_external.assert_not_called()

    def test_late_ignored_file_is_rechecked_before_remote_fast_forward(self):
        base, candidate, _ = self.local_candidate()
        (self.repo / ".git/info/exclude").write_text("ignored-artifact\n")
        def introduce_hazard(**unused):
            (self.repo / "ignored-artifact").write_text("late owned fixture")
            return SimpleNamespace(key="fixture")
        flow, original_scope = self.remote_run_fixture(base, candidate, reserve=introduce_hazard)
        self.assertTrue(flow.save.called)
        original_scope.__enter__.return_value.reserve_external.assert_called_once()

    def test_scoped_preparation_refuses_before_actual_remote_fast_forward(self):
        base, candidate, _ = self.local_candidate()
        marker = self.repo / "owned-preparation-marker"
        original_run = remote_delivery.run_check

        def fake_prepare(repo, argv, **options):
            if argv == PREPARATION:
                marker.write_text("owned fixture only")
                return subprocess.CompletedProcess(argv, 0)
            return original_run(repo, argv, **options)

        with mock.patch.object(remote_delivery, "run_check", side_effect=fake_prepare) as runner, \
                mock.patch.object(remote_delivery, "fetch_target") as fetch:
            flow, scope, error = self.remote_run_fixture(base, candidate, preparations=[PREPARATION], fetch=fetch)
        for label, observed, expected in (
            ("head-is-base", self.git("rev-parse", "HEAD") == base, True),
            ("marker-absent", marker.exists(), False),
            ("workflow-save-absent", flow.save.called, False),
            ("reservation-absent", scope.__enter__.return_value.reserve_external.called, False),
            ("fetch-absent", fetch.called, False),
            ("runner-absent", runner.called, False),
            ("log-absent", (self.results / "checks").exists(), False),
            ("checkout-clean", self.git("status", "--porcelain") == "", True),
            ("policy", (error.status, error.code, str(error)), ("BLOCKED_POLICY", 2, PREPARATION_HOLD)),
        ):
            with self.subTest(boundary=label):
                self.assertEqual(observed, expected)

    def remote_run_fixture(self, base, candidate, *, reserve=None, preparations=(), fetch=None):
        flow = mock.Mock(original=self.repo, branch="main", directory=self.results,
                         args=SimpleNamespace(timeout=5, check_timeout=5))
        flow.state = {"phase": "PR_READY", "source_head": candidate.source, "baseline": base,
                      "repository": "ericmacdougall/bugtracker-harness"}
        flow.facts.return_value = {}
        target = candidate.source
        original_scope = mock.MagicMock()
        reservation = original_scope.__enter__.return_value.reserve_external
        reservation.return_value = SimpleNamespace(key="fixture", journal=None)
        reservation.side_effect = reserve
        if preparations:
            flow.save.side_effect = lambda **fields: flow.state.update(fields)
        def execute(repo, *args, timeout=5):
            result = subprocess.run(["git", "-C", str(repo), *args], env=delivery.git_environment(isolated=True),
                                    capture_output=True, text=True, timeout=timeout)
            return result.returncode, result.stdout
        with mock.patch.multiple(
                remote_delivery, verify_remote_pr=mock.Mock(return_value={"state": "MERGED", "mergeCommit": {"oid": target}}),
                github_target=mock.Mock(return_value=target), fetch_target=fetch if fetch is not None else mock.Mock(),
                verify_remote_descendant=mock.Mock(), OriginalScope=mock.Mock(return_value=original_scope),
                task_generation_digest=mock.Mock(return_value="fixture"), git=execute,
                snapshot=lambda *args: self.git("rev-parse", "HEAD")), \
                mock.patch.dict(os.environ, {**self.environment, "PATH": os.defpath}, clear=True):
            with self.assertRaises(remote_delivery.DeliveryError) as caught:
                remote_delivery.remote_finish(flow, preparations, [UNITTESTS[0]])
        if preparations:
            return flow, original_scope, caught.exception
        self.assertEqual(self.git("rev-parse", "HEAD"), base)
        return flow, original_scope

    def test_local_prepare_and_direct_resolution_stop_before_scratch(self):
        base, scope, argv = self.local_candidate()
        direct = SimpleNamespace(repo=self.repo, original_branch="main", expected_head=base,
                                 source="feature", expected_source_head=scope.source, timeout=5,
                                 check_timeout=5, resolve_journal="0" * 64)
        with mock.patch.object(delivery, "run", return_value=subprocess.CompletedProcess(PREPARATION, 1)) as runner, \
                mock.patch.object(delivery, "scratch_journal_root", wraps=delivery.scratch_journal_root) as reserve:
            status, output = self.local_run([*argv, "--prepare", shlex.join(PREPARATION)])
            for label, observed, expected in (
                ("local-status", status, 2), ("local-message", PREPARATION_HOLD in output, True),
                ("local-reserve", reserve.called, False), ("local-runner", runner.called, False),
            ):
                with self.subTest(boundary=label):
                    self.assertEqual(observed, expected)
            reserve.reset_mock()
            runner.reset_mock()
            out = io.StringIO()
            with mock.patch.dict(os.environ, {**self.environment, "PATH": os.defpath}, clear=True), redirect_stdout(out):
                status = delivery.integrate_scratch(direct, [], [UNITTESTS[0]])
            for label, observed, expected in (
                ("direct-status", status, 2), ("direct-message", BASELINE_HOLD in out.getvalue(), True),
                ("direct-reserve", reserve.called, False), ("direct-runner", runner.called, False),
            ):
                with self.subTest(boundary=label):
                    self.assertEqual(observed, expected)
        self.assertEqual(self.git("rev-parse", "HEAD"), base)

    def test_bound_preparation_is_refused_before_log_or_child(self):
        scope = self.select("import unittest\n")
        log_dir = self.results / "checks"
        with mock.patch.object(remote_delivery, "run_check", return_value=subprocess.CompletedProcess(PREPARATION, 0)) as runner:
            with self.subTest(boundary="dispatcher"):
                with self.assertRaisesRegex(remote_delivery.DeliveryError, PREPARATION_HOLD):
                    remote_delivery.run_checks(self.repo, [PREPARATION], [LEGACY], 5, log_dir, scoped_context=scope)
            with self.subTest(boundary="no-log"):
                self.assertFalse(log_dir.exists())
            with self.subTest(boundary="no-dispatched-child"):
                runner.assert_not_called()
        with mock.patch.object(delivery, "run_process", return_value=subprocess.CompletedProcess(PREPARATION, 0)) as runner:
            for argv in (PREPARATION, tuple(PREPARATION)):
                with self.subTest(representation=type(argv).__name__):
                    with self.assertRaisesRegex(delivery.CheckInterpreterError, PREPARATION_HOLD):
                        delivery.run(self.repo, argv, scoped_context=scope)
            with self.subTest(boundary="no-single-child"):
                runner.assert_not_called()

    def test_direct_pending_paths_refuse_before_original_scope(self):
        scope = self.select("import unittest\n")
        pending = {"phase": "REMOTE_APPLYING", "guard_key": "1" * 64, "local_key": None,
                   "source_head": scope.source, "target": scope.target, "merge_head": scope.target,
                   "apply_base": scope.target, "baseline": scope.target, "pr_number": 1,
                   "checks_digest": remote_delivery.checks_digest([PREPARATION], [UNITTESTS[0]])}
        flow = mock.Mock(original=self.repo, branch="main", directory=self.results,
                         args=SimpleNamespace(timeout=5, resolve_baseline=scope.target), state=pending)
        before = pending.copy()
        for entry, preparations, checks, message in (
            (remote_delivery.resume_remote_finish, [PREPARATION], [UNITTESTS[0]], PREPARATION_HOLD),
            (remote_delivery.local_completion, [PREPARATION], [UNITTESTS[0]], PREPARATION_HOLD),
            (remote_delivery.resolve_baseline, [], [UNITTESTS[0]], BASELINE_HOLD),
            (remote_delivery.resolve_baseline, [], [LEGACY, UNITTESTS[0]], BASELINE_HOLD),
        ):
            with self.subTest(entry=entry.__name__, checks=len(checks)):
                boundary = remote_delivery.DeliveryError("FIXTURE_BOUNDARY", "OriginalScope reached")
                with mock.patch.object(remote_delivery, "OriginalScope", side_effect=boundary) as original:
                    with self.subTest(boundary="policy"):
                        with self.assertRaisesRegex(remote_delivery.DeliveryError, message):
                            entry(flow, preparations, checks)
                    with self.subTest(boundary="no-lock"):
                        original.assert_not_called()
        self.assertEqual(pending, before)
        flow.save.assert_not_called()
        self.assertEqual(self.git("rev-parse", "HEAD"), scope.target)

    def test_local_child_uses_admitted_vectors_instead_of_divergent_raw_arguments(self):
        base, scope, _ = self.local_candidate()
        common = delivery.git_common_directory(self.repo, 5)[0]
        raw = SimpleNamespace(timeout=5, check_timeout=5, prepare=[shlex.join(PREPARATION)], check=["npm test"])
        state = {"phase": "LOCAL_READY", "source": str(self.repo), "source_branch": "feature",
                 "source_head": scope.source, "baseline": base}
        flow = mock.Mock(original=self.repo, branch="main", identity=delivery.checkout_identity(self.repo),
                         common=common, args=raw, state=state, ticket_exit=0)
        bounded = mock.Mock(return_value=(0, '{"status":"INTEGRATED"}'))
        with mock.patch.multiple(remote_delivery, verify_source=mock.Mock(), local_completion=mock.Mock(return_value=True),
                                 bounded=bounded, snapshot=lambda *args: self.git("rev-parse", "HEAD"),
                                 ancestry=mock.Mock(return_value=False)), \
                mock.patch.dict(os.environ, {**self.environment, "PATH": os.defpath}, clear=True):
            result = remote_delivery.local_finish(flow, [], [UNITTESTS[0]])
            command = bounded.call_args.args[0]
        self.assertEqual(result, 0)
        self.assertEqual(flow.save.call_args.kwargs["checks_digest"], remote_delivery.checks_digest([], [UNITTESTS[0]]))
        with self.subTest(boundary="no-raw-preparation"):
            self.assertNotIn("--prepare", command)
        with self.subTest(boundary="same-admitted-vector"):
            self.assertEqual(shlex.split(command[command.index("--check") + 1]), UNITTESTS[0])
        self.assertEqual(self.git("rev-parse", "HEAD"), base)

    def test_scoped_python_suppresses_startup_and_ambient_environment(self):
        runtime = self.results / "runtime"
        subprocess.run([str(self.python), "-S", "-B", "-m", "venv", "--without-pip", "--copies", str(runtime)],
                       check=True, capture_output=True, timeout=15)
        tool = runtime / "bin/python3"
        packages = next(runtime.glob("lib/python*/site-packages"))
        marker = self.results / "startup-ran"
        (packages / "sitecustomize.py").write_text(f"from pathlib import Path\nPath({str(marker)!r}).touch()\n")
        code = ("import os, sys, unittest\nfrom pathlib import Path\n"
                "class Fixture(unittest.TestCase):\n"
                "    def test_isolation(self):\n"
                "        self.assertEqual(sys.flags.no_site, 1)\n"
                "        self.assertTrue(sys.dont_write_bytecode)\n"
                "        self.assertNotIn('QAC_UNSCOPED_SENTINEL', os.environ)\n"
                f"        self.assertEqual(Path(os.environ['TMPDIR']).parent, Path({str(self.results)!r}))\n")
        scope = self.select(code)
        with mock.patch.object(delivery, "SCOPED_TOOLS", {"python3": (tool, tool.resolve())}), \
                mock.patch.dict(os.environ, {"QAC_UNSCOPED_SENTINEL": "fixture"}):
            self.assertEqual(self.run_selected(scope, []).returncode, 0)
        self.assertFalse(marker.exists())

    def test_probe_and_test_receive_only_sanitized_environment(self):
        scope = self.select("import unittest\nclass Fixture(unittest.TestCase):\n    def test_real(self):\n"
                            "        self.assertEqual(2+3, 5)\n")
        actual = delivery.run_process
        observed = []
        def record(argv, **kwargs):
            if argv[0] == str(self.python):
                observed.append((argv, kwargs.get("env")))
            return actual(argv, **kwargs)
        with mock.patch.object(delivery, "run_process", side_effect=record), \
                mock.patch.dict(os.environ, {"QAC_UNSCOPED_SENTINEL": "fixture"}):
            self.assertEqual(self.run_selected(scope, []).returncode, 0)
        self.assertEqual(len(observed), 2)
        self.assertEqual(observed[0][0][1:4], ["-I", "-S", "-B"])
        self.assertEqual(observed[1][0][1:3], ["-S", "-B"])
        for _, env in observed:
            self.assertIsNotNone(env)
            self.assertNotIn("QAC_UNSCOPED_SENTINEL", env)

    def test_ambient_artifact_path_is_never_used(self):
        scope = self.select("import unittest\n")
        ambient = self.results / "ambient"
        ambient.mkdir()
        with mock.patch.object(delivery.tempfile, "mkdtemp") as create:
            with self.assertRaisesRegex(delivery.CheckInterpreterError, "environment"):
                delivery.run(self.repo, UNITTESTS[0], timeout=10, scoped_context=scope,
                             env={**self.environment, "TMPDIR": str(ambient)})
            create.assert_not_called()
        self.assertEqual(list(ambient.iterdir()), [])

    def test_artifact_root_must_be_private_and_unaliased(self):
        scope = self.select("import unittest\n")
        alias = self.results / "alias"
        alias.symlink_to(self.results, target_is_directory=True)
        with mock.patch.object(delivery, "SCOPED_RESULT_ROOT", alias), \
                mock.patch.object(delivery.tempfile, "mkdtemp") as create:
            with self.assertRaisesRegex(delivery.CheckInterpreterError, "owner-only"):
                self.run_selected(scope, [])
            create.assert_not_called()
        self.results.chmod(0o755)
        try:
            with mock.patch.object(delivery.tempfile, "mkdtemp") as create:
                with self.assertRaisesRegex(delivery.CheckInterpreterError, "owner-only"):
                    self.run_selected(scope, [])
                create.assert_not_called()
        finally:
            self.results.chmod(0o700)

    def test_actual_empty_skip_and_failure_never_yield_receipt(self):
        for code in (
            "import unittest\n",
            "import unittest\nclass Fixture(unittest.TestCase):\n    @unittest.skip('fixture')\n"
            "    def test_skipped(self):\n        pass\n",
            "import unittest\nclass Fixture(unittest.TestCase):\n    def test_failure(self):\n"
            "        self.assertEqual(2, 3)\n",
        ):
            scope = self.select(code)
            receipts = []
            self.assertEqual(self.run_selected(scope, receipts).returncode, 1)
            self.assertEqual(receipts, [])

    def test_alias_duplicate_and_repository_drift_refuse(self):
        code = "import unittest\n"
        scope = self.select(code)
        package = self.selected.parent / "nested"
        package.mkdir()
        (package / "__init__.py").touch()
        (package / self.selected.name).write_text(code)
        with self.assertRaisesRegex(delivery.CheckInterpreterError, "ambiguous"):
            self.run_selected(scope, [])
        (package / self.selected.name).unlink()
        self.selected.unlink()
        self.selected.symlink_to(package / "__init__.py")
        with self.assertRaises(delivery.CheckInterpreterError):
            self.run_selected(scope, [])
        self.git("remote", "set-url", "origin", "https://github.com/ericmacdougall/other.git")
        with self.assertRaisesRegex(delivery.CheckInterpreterError, "approved harness original"):
            delivery.scoped_check_context([UNITTESTS[0]], self.repo, scope.source, target=scope.target)
