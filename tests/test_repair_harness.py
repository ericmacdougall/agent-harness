"""Failure and retry controls for the two-host repair sequencer."""
import argparse
import fcntl
from contextlib import redirect_stdout
import io
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
import repair_harness as repair


class RepairSequence(unittest.TestCase):
    def setUp(self):
        self.stage = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(redirect_stdout(io.StringIO()))
        (self.stage / "release.tar").write_bytes(b"identical archive fixture")
        self.local = Mock(side_effect=self.reply)
        self.remote = Mock(side_effect=self.reply)
        self.options = argparse.Namespace(apply=True, ref="a" * 40, host="t2-dev")

    def reply(self, phase, payload=None):
        if phase == "check":
            return {"stage": "repair-teststage", "status": "ok", "backups": [],
                    "git_backstop": "inactive", "log_dir": "/private/repair-teststage"}
        return {"stage": "repair-teststage", "status": "ok", "backups": ["/private/backup"],
                "git_backstop": "inactive", "log_dir": "/private/repair-teststage"}

    def test_second_host_preflight_failure_starts_no_apply(self):
        self.remote.side_effect = repair.RepairError("remote preview failed")
        with self.assertRaisesRegex(repair.RepairError, "preflight"):
            repair.sequence(self.options, self.stage, self.local, self.remote)
        self.assertEqual([call.args[0] for call in self.local.call_args_list], ["check"])
        self.assertEqual([call.args[0] for call in self.remote.call_args_list], ["check"])

    def test_uncertain_remote_apply_never_applies_locally(self):
        self.remote.side_effect = [self.reply("check"), repair.RepairError("lost SSH acknowledgement")]
        with self.assertRaisesRegex(repair.RepairError, "Remote apply outcome is uncertain"):
            repair.sequence(self.options, self.stage, self.local, self.remote)
        self.assertEqual([call.args[0] for call in self.local.call_args_list], ["check"])
        self.assertEqual([call.args[0] for call in self.remote.call_args_list], ["check", "apply"])

    def test_local_failure_discloses_worker_already_applied(self):
        self.local.side_effect = [self.reply("check"), repair.RepairError("local installer failed")]
        with self.assertRaisesRegex(repair.RepairError, "remote already applied"):
            repair.sequence(self.options, self.stage, self.local, self.remote)
        self.assertEqual([call.args[0] for call in self.local.call_args_list], ["check", "apply"])

    def test_check_preview_provides_same_archive_to_both_hosts(self):
        self.options.apply = False
        repair.sequence(self.options, self.stage, self.local, self.remote)
        self.assertEqual(self.local.call_args.args, ("check", self.stage / "release.tar"))
        self.assertEqual(self.remote.call_args.args, self.local.call_args.args)

    def test_reported_remote_partial_failure_does_not_fall_back_locally(self):
        failed = dict(self.reply("apply"), status="failed")
        self.remote.side_effect = [self.reply("check"), failed]
        with self.assertRaisesRegex(repair.RepairError, "may be partial"):
            repair.sequence(self.options, self.stage, self.local, self.remote)
        self.assertEqual([call.args[0] for call in self.local.call_args_list], ["check"])

    def test_ssh_option_injection_refused_before_creating_stage(self):
        mask = os.umask(0o022)
        os.umask(mask)
        self.addCleanup(os.umask, mask)  # main() sets the process umask to 077; later tests in this process need theirs
        with patch.object(sys, "argv", ["repair", "--ref", "a" * 40, "--host=-oProxyCommand=false"]):
            with patch.object(repair, "work_dir") as stage, self.assertRaisesRegex(repair.RepairError, "trusted SSH host"):
                repair.main()
            stage.assert_not_called()


class ReleaseAncestry(unittest.TestCase):
    def test_older_exact_main_ancestor_allowed_unmerged_disallowed(self):
        def git(*args):
            return subprocess.run(
                ["/usr/bin/git", "-c", "user.name=Repair Fixture", "-c", "user.email=fixture@example.invalid", *args],
                cwd=repo, check=True, capture_output=True, text=True,
            ).stdout.strip()

        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        repo = root / "origin"
        repo.mkdir()
        git("init", "-b", "main")
        (repo / "install.py").write_text("reviewed\n")
        git("add", "install.py")
        git("commit", "-m", "reviewed")
        reviewed = git("rev-parse", "HEAD")
        git("commit", "--allow-empty", "-m", "main advanced")
        tip = git("rev-parse", "HEAD")
        git("branch", "unmerged")
        git("checkout", "unmerged")
        git("commit", "--allow-empty", "-m", "not in main")
        unmerged = git("rev-parse", "HEAD")
        positive, negative = root / "positive", root / "negative"
        positive.mkdir()
        negative.mkdir()
        with patch.object(repair, "ORIGIN", str(repo)):
            self.assertEqual(repair.canonical_archive(reviewed, positive), tip)
            self.assertTrue((positive / "release.tar").is_file())
            cache = root / "repair-source.git"
            cache_inode = cache.stat().st_ino
            with self.assertRaisesRegex(repair.RepairError, "outside canonical main"):
                repair.canonical_archive(unmerged, negative)
            self.assertFalse((negative / "release.tar").exists())
            self.assertEqual(cache.stat().st_ino, cache_inode)
            self.assertFalse((positive / "verified").exists())
            bounded = root / "bounded"
            bounded.mkdir()
            with patch.object(repair, "MAX_ARCHIVE", 1024), self.assertRaises(subprocess.CalledProcessError):
                repair.canonical_archive(reviewed, bounded)
            self.assertLessEqual((bounded / "release.tar").stat().st_size, 1024)


class HostSafety(unittest.TestCase):
    def test_lock_refuses_symlink_and_hardlink(self):
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        target = root / 'target'
        target.write_text('preserve')
        for kind in ('symlink', 'hardlink'):
            path = root / (kind + '.lock')
            path.symlink_to(target) if kind == 'symlink' else os.link(target, path)
            with self.subTest(kind=kind), self.assertRaises((OSError, repair.RepairError)):
                with repair.host_lock(root, path.name):
                    self.fail('unsafe lock acquired')
        self.assertEqual(target.read_text(), 'preserve')

    def test_low_disk_stops_before_canonical_fetch(self):
        stage = Path(self.enterContext(tempfile.TemporaryDirectory()))
        with patch.object(repair.shutil, 'disk_usage', return_value=argparse.Namespace(free=1)), patch.object(repair, 'git') as git:
            with self.assertRaisesRegex(repair.RepairError, 'space'):
                repair.canonical_archive('a' * 40, stage)
        git.assert_not_called()

    def test_contended_source_cache_never_fetches(self):
        work = Path(self.enterContext(tempfile.TemporaryDirectory()))
        stage = work / 'stage'
        stage.mkdir()
        with repair.host_lock(work, 'repair-source.lock'), patch.object(repair, 'git') as git:
            with self.assertRaisesRegex(repair.RepairError, 'host lock'):
                repair.canonical_archive('a' * 40, stage)
        git.assert_not_called()


class ArchiveExtraction(unittest.TestCase):
    def test_matching_digest_does_not_authorize_escape_link_or_duplicate_members(self):
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        for kind in ("traversal", "absolute", "symlink", "hardlink", "duplicate"):
            with self.subTest(member=kind):
                archive = root / f"{kind}.tar"
                with tarfile.open(archive, "w") as bundle:
                    fixture = tarfile.TarInfo("regular.txt")
                    fixture.size = 1
                    bundle.addfile(fixture, io.BytesIO(b"x"))
                    path = {
                        "traversal": "../escaped.txt", "absolute": str(root / "escaped.txt"),
                        "symlink": "unsafe", "hardlink": "unsafe", "duplicate": "regular.txt",
                    }[kind]
                    invalid = tarfile.TarInfo(path)
                    if kind in ("symlink", "hardlink"):
                        invalid.type = tarfile.SYMTYPE if kind == "symlink" else tarfile.LNKTYPE
                        invalid.linkname = "../escaped.txt"
                    bundle.addfile(invalid)
                with self.assertRaisesRegex(repair.RepairError, "Unexpected member|Duplicate"):
                    repair.extraction(archive, root / f"extract-{kind}", repair.digest(archive))
                self.assertFalse((root / "escaped.txt").exists())


@unittest.skipIf(os.geteuid() == 0, "Repair deliberately requires a non-root account")
class StockInstallers(unittest.TestCase):
    def setUp(self):
        self.temp = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.home = self.temp / "account"
        (self.home / ".agent-harness").mkdir(mode=0o700, parents=True)
        (self.home / ".agent-harness/work").mkdir(mode=0o700)
        for name in repair.HOOK_PATHS:
            marker = self.home / name
            marker.parent.mkdir(parents=True)
            marker.write_text("older installed fixture\n")
        for name in repair.SETTINGS:
            (self.home / name).write_text("# user's settings fixture\n")
        old_policy = self.home / ".claude/hooks/commit_policy.json"
        old_policy.write_text('{"backstop_repos": ["existing/repo"]}')
        self.profile = self.home / ".codex/agent-harness/spec_policy.local.json"
        self.profile.write_text('{"personal":"unchanged"}')
        self.archive = subprocess.run(["/usr/bin/git", "archive", "HEAD"], cwd=ROOT, capture_output=True, check=True).stdout
        self.expected = repair.hashlib.sha256(self.archive).hexdigest()

    def preview(self, archive=None):
        archive = self.archive if archive is None else archive
        return repair.host_worker("check", self.expected, "-", len(archive), io.BytesIO(archive), self.home)

    def apply(self, stage):
        return repair.host_worker("apply", self.expected, stage, 0, io.BytesIO(), self.home)

    def test_real_install_preserves_config_preexisting_profile_and_reports_backups(self):
        protected = repair.snapshot([self.home / name for name in repair.SETTINGS] + [self.profile])
        prior = repair.snapshot(self.home / path for path in repair.HOOK_PATHS)
        preview = self.preview()
        self.assertEqual(preview["status"], "ok")
        self.assertEqual(repair.snapshot(self.home / path for path in repair.HOOK_PATHS), prior)
        applied = self.apply(preview["stage"])
        self.assertEqual(applied["status"], "ok")
        self.assertEqual(len(applied["backups"]), 2)
        self.assertNotEqual(repair.snapshot(self.home / path for path in repair.HOOK_PATHS), prior)
        self.assertEqual(repair.snapshot([self.home / name for name in repair.SETTINGS] + [self.profile]), protected)
        # Release 1001 has no commit policy, so nothing migrates its personal values into a local profile any more.
        self.assertFalse((self.home / ".claude/hooks/commit_policy.local.json").exists())

    def test_tampered_archive_never_invokes_installer(self):
        with patch.object(repair, "bounded_install") as installer:
            preview = self.preview(self.archive[:-1] + b"x")
        self.assertEqual(preview["status"], "failed")
        installer.assert_not_called()

    def test_installation_change_after_preview_refuses_apply(self):
        preview = self.preview()
        self.assertEqual(preview["status"], "ok")
        (self.home / ".codex/config.toml").write_text("edited during preview\n")
        with patch.object(repair, "bounded_install") as installer:
            applied = self.apply(preview["stage"])
        self.assertEqual(applied["status"], "failed")
        installer.assert_not_called()

    def test_low_disk_preview_and_apply_invoke_no_installer(self):
        with patch.object(repair.shutil, 'disk_usage', return_value=argparse.Namespace(free=1)), patch.object(repair, 'bounded_install') as installer:
            reply = self.preview()
        self.assertEqual(reply['status'], 'failed')
        installer.assert_not_called()
        preview = self.preview()
        self.assertEqual(preview['status'], 'ok')
        with patch.object(repair.shutil, 'disk_usage', return_value=argparse.Namespace(free=1)), patch.object(repair, 'bounded_install') as installer:
            reply = self.apply(preview['stage'])
        self.assertEqual(reply['status'], 'failed')
        installer.assert_not_called()

    def test_host_lock_prevents_overlapping_apply_before_installer(self):
        preview = self.preview()
        self.assertEqual(preview['status'], 'ok')
        with repair.host_lock(repair.work_dir(self.home), 'repair-apply.lock'):
            with patch.object(repair, 'bounded_install') as installer:
                reply = self.apply(preview['stage'])
        self.assertEqual(reply['status'], 'failed')
        installer.assert_not_called()

    def test_stage_extra_import_does_not_enter_fresh_apply_source(self):
        preview = self.preview()
        self.assertEqual(preview['status'], 'ok')
        stage = self.home / '.agent-harness/work' / preview['stage']
        (stage / 'source-check' / 'json.py').write_text("raise RuntimeError('injected import')\n")
        (stage / 'json.py').write_text("raise RuntimeError('injected import')\n")
        reply = self.apply(preview['stage'])
        self.assertEqual(reply['status'], 'ok')
        self.assertFalse((stage / 'source-apply/json.py').exists())

    def test_host_lock_spans_both_real_installers(self):
        preview = self.preview()
        self.assertEqual(preview['status'], 'ok')
        installer = repair.bounded_install
        observed = []
        def check_lock(*args, **kwargs):
            with self.assertRaisesRegex(repair.RepairError, 'host lock'):
                with repair.host_lock(repair.work_dir(self.home), 'repair-apply.lock'):
                    self.fail('lifetime lock was released')
            observed.append(args[1])
            return installer(*args, **kwargs)
        with patch.object(repair, 'bounded_install', side_effect=check_lock):
            applied = self.apply(preview['stage'])
        self.assertEqual(applied['status'], 'ok')
        self.assertEqual(observed, list(repair.INSTALLERS))

    def test_corrupted_non_ah_file_after_install_is_reported(self):
        preview = self.preview()
        self.assertEqual(preview["status"], "ok")
        installer = repair.bounded_install

        def corrupt(*args, **kwargs):
            output = installer(*args, **kwargs)
            if args[1] == "install_codex.py":
                (self.home / ".codex/agent-harness/wal.py").write_text("corrupted\n")
            return output

        with patch.object(repair, "bounded_install", side_effect=corrupt):
            applied = self.apply(preview["stage"])
        self.assertEqual(applied["status"], "failed")
        self.assertEqual(len(applied["backups"]), 2)
