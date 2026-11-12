"""goodqa#15738: the worktree verifier accepts exactly `extensions.worktreeConfig=true` and vets every per-worktree config.

Real temporary repositories and real linked worktrees; fake network. A marker program named by a dangerous key must never
run, which a test that only reads the refusal reason could not show."""
import os
import stat
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_ah_worktree_remove import Repo, git  # noqa: E402

import command_guard as cg  # noqa: E402


class Extension(Repo):
    def setUp(self):
        super().setUp()
        self.common = self.primary / ".git"
        self.target_file = self.common / "worktrees" / "linked" / "config.worktree"
        self.primary_file = self.common / "config.worktree"
        self.marker = self.home / "MARKER-RAN"
        script = self.home / "marker.sh"
        script.write_text("#!/bin/sh\necho ran >> %s\ncat >/dev/null\nexit 0\n" % self.marker)
        script.chmod(0o755)
        self.script = str(script)

    def extension(self, text="\ttrue\n", *, header="[extensions]\n\tworktreeConfig =", more=""):
        """Append raw lines to the shared config (the key form is written by hand, bare keys and repeats included)."""
        with open(self.common / "config", "a") as handle:
            handle.write(header + text.replace("\ttrue\n", " true\n") if header.endswith("=") else header + text)
            handle.write(more)

    def raw(self, *lines):
        with open(self.common / "config", "a") as handle:
            handle.write("\n".join(lines) + "\n")

    def verify(self, path=None):
        return cg.verify_worktree(str(path or self.linked), policy=None)

    def assertRefused(self, fragment, report=None):
        report = report or self.verify()
        self.assertFalse(report["removable"], report)
        fragments = (fragment,) if isinstance(fragment, str) else tuple(fragment)
        self.assertTrue(any(f in report["reason"] for f in fragments), report["reason"])
        self.assertFalse(self.marker.exists(), "a program named by the config ran")
        return report

    # git itself may stop on some of these keys before the verifier's own check (it then reports it could not verify):
    # still a refusal. The specific reason is pinned for the keys where git carries on.
    GIT_STOPS = ("could not verify", "exact top")

    # ---- AC-1
    def test_the_extension_alone_is_accepted_in_every_true_spelling(self):
        original = (self.common / "config").read_text()
        for label, lines in (("true", ["[extensions]", "\tworktreeConfig = true"]), ("TRUE", ["[extensions]", "\tworktreeConfig = TRUE"]),
                             ("yes", ["[extensions]", "\tworktreeConfig = yes"]), ("on", ["[extensions]", "\tworktreeConfig = on"]),
                             ("1", ["[extensions]", "\tworktreeConfig = 1"]), ("bare key", ["[extensions]", "\tworktreeConfig"]),
                             ("mixed case key", ["[EXTENSIONS]", "\tWorkTreeConfig = true"])):
            with self.subTest(label):
                (self.common / "config").write_text(original)
                self.raw(*lines)
                report = self.verify()
                self.assertTrue(report["removable"], report)

    def test_a_clean_published_worktree_with_the_extension_is_really_removed(self):
        self.raw("[extensions]", "\tworktreeConfig = true")
        report = cg.remove_worktree(str(self.linked), policy=None)
        self.assertTrue(report["removed"], report)
        self.assertFalse(self.linked.exists())

    # ---- AC-2
    def test_other_extension_keys_still_refuse_alone_and_beside_the_accepted_one(self):
        original = (self.common / "config").read_text()
        for key in ("objectFormat = sha256", "partialClone = origin", "preciousObjects = true", "refStorage = reftable",
                    "compatObjectFormat = sha1", "relativeWorktrees = true", "x = y"):
            for beside in (False, True):
                with self.subTest(key=key, beside=beside):
                    (self.common / "config").write_text(original)
                    self.raw("[extensions]", *(["\tworktreeConfig = true"] if beside else []), "\t" + key)
                    self.assertRefused(("[extensions] section",) + self.GIT_STOPS)

    def test_a_subsection_spelling_is_a_different_key_and_refuses(self):
        self.raw('[extensions "x"]', "\tworktreeConfig = true")
        self.assertRefused("[extensions] section")

    def test_values_outside_the_true_set_and_duplicates_refuse(self):
        original = (self.common / "config").read_text()
        for value in ("false", "no", "off", "0", "maybe", "2", "1k", "0x1", ""):
            with self.subTest(value=value):
                (self.common / "config").write_text(original)
                self.raw("[extensions]", "\tworktreeConfig = " + value)
                self.assertRefused(("worktreeConfig",) + self.GIT_STOPS)
        for first, second in (("false", "true"), ("true", "false"), ("true", "true")):
            with self.subTest(first=first, second=second):
                (self.common / "config").write_text(original)
                self.raw("[extensions]", "\tworktreeConfig = " + first, "\tworktreeConfig = " + second)
                self.assertRefused(("more than once", "not plainly true"))

    # ---- AC-3 and AC-4
    DANGEROUS = (
        ("core", "fsmonitor", None), ("core", "hooksPath", "/tmp"), ("core", "sshCommand", "x"), ("core", "gitProxy", "x"),
        ("core", "pager", "x"), ("core", "editor", "x"), ("core", "askPass", "x"), ("core", "attributesFile", "/tmp/a"),
        ("core", "excludesFile", "/tmp/e"), ("core", "worktree", "/tmp"), ("core", "alternateRefsCommand", "x"),
        ("core", "ignoreCase", "true"), ("core", "bare", "true"), ("core", "logAllRefUpdates", "true"),
        ("include", "path", "/tmp/x"), ("includeIf.gitdir:/x/", "path", "/tmp/x"), ("credential", "helper", "x"),
        ("filter.x", "clean", "x"), ("url.x", "insteadOf", "y"), ("alias", "x", "!id"), ("http", "proxy", "x"),
        ("protocol", "allow", "always"), ("diff", "external", "x"), ("merge", "tool", "x"), ("submodule", "recurse", "true"),
        ("remote.origin", "url", "https://github.com/a/b"), ("branch", "autosetupmerge", "true"), ("user", "name", "x"),
        ("index", "threads", "2"), ("extensions", "worktreeConfig", "true"), ("gc", "auto", "0"), ("pack", "threads", "1"),
    )

    def write(self, file, section, key, value):
        file.parent.mkdir(parents=True, exist_ok=True)
        value = self.script if value is None else value
        file.write_text('[%s]\n\t%s = %s\n' % (section if "." not in section else section.replace(".", ' "', 1) + '"', key, value))

    def test_every_dangerous_key_in_the_targets_file_refuses_and_nothing_runs(self):
        self.raw("[extensions]", "\tworktreeConfig = true")
        for section, key, value in self.DANGEROUS:
            with self.subTest(section=section, key=key):
                self.write(self.target_file, section, key, value)
                self.assertRefused(("per-worktree config",) + self.GIT_STOPS)
        self.target_file.unlink()

    def test_the_allowlisted_keys_pass(self):
        self.raw("[extensions]", "\tworktreeConfig = true")
        for body in ("[core]\n\tsparseCheckout = true\n\tsparseCheckoutCone = false\n[index]\n\tsparse = false\n",
                     "[index]\n\tsparse = true\n", "[core]\n\tsparseCheckout\n",
                     "[core]\n\tbare = false\n", "[core]\n\tbare = no\n", ""):
            with self.subTest(body=body[:30]):
                self.target_file.parent.mkdir(parents=True, exist_ok=True)
                self.target_file.write_text(body)
                self.assertTrue(self.verify()["removable"])
        for body in ("[core]\n\tsparseCheckout = maybe\n", "[core]\n\tbare\n", "[core]\n\tbare = 2\n"):
            with self.subTest(body=body[:30]):
                self.target_file.write_text(body)
                self.assertRefused(("per-worktree config",) + self.GIT_STOPS)  # git may reject the value itself

    def test_the_files_that_decide_are_the_primarys_the_targets_and_the_callers(self):
        other = self.base / "other"
        git(self.primary, "worktree", "add", "-q", "-b", "other", str(other))
        git(self.primary, "update-ref", "refs/remotes/origin/other", git(other, "rev-parse", "HEAD"))
        self.live["refs/heads/other"] = git(other, "rev-parse", "HEAD")
        self.raw("[extensions]", "\tworktreeConfig = true")
        compiled = cg.Compiled(self.policy, home=str(self.home), cwd=str(self.primary))
        other_file = self.common / "worktrees" / "other" / "config.worktree"
        command = "git worktree remove %s" % self.linked
        # the primary's file: the delegated removal runs from the primary, so it refuses in both forms
        self.write(self.primary_file, "core", "fsmonitor", None)
        self.assertRefused("per-worktree config")
        verdict, text = cg.decide(command, compiled, cwd=str(self.primary))
        self.assertEqual(verdict, "block")
        self.assertFalse(self.marker.exists())
        self.primary_file.unlink()
        # an UNRELATED linked worktree's file is never read by this removal: it must not block it (one odd file must
        # not freeze every sibling, as it did in the first draft on the real t2-dev proof)
        self.write(other_file, "core", "fsmonitor", None)
        self.assertTrue(self.verify()["removable"], self.verify())
        verdict, text = cg.decide(command, compiled, cwd=str(self.primary))
        self.assertEqual(verdict, "allow", text)
        # but when the CALLER stands in that worktree (the hook form runs git there), its file decides
        verdict, text = cg.decide(command, cg.Compiled(self.policy, home=str(self.home), cwd=str(other)), cwd=str(other))
        self.assertEqual(verdict, "block")
        self.assertIn("per-worktree config", text)
        self.assertFalse(self.marker.exists())
        other_file.unlink()
        self.write(self.target_file, "core", "fsmonitor", None)  # and the target's own file
        self.assertRefused("per-worktree config")
        self.target_file.unlink()
        self.assertTrue(self.verify()["removable"])
        verdict, text = cg.decide(command, compiled, cwd=str(self.primary))
        self.assertEqual(verdict, "allow", text)

    def test_unsafe_file_shapes_refuse_and_an_absent_file_does_not(self):
        self.raw("[extensions]", "\tworktreeConfig = true")
        self.assertTrue(self.verify()["removable"])  # no per-worktree file at all
        self.target_file.parent.mkdir(parents=True, exist_ok=True)
        harmless = self.home / "harmless.cfg"
        harmless.write_text("[core]\n\tsparseCheckout = true\n")
        shapes = {
            "symlink": lambda: self.target_file.symlink_to(harmless),
            "dangling symlink": lambda: self.target_file.symlink_to(self.home / "nowhere"),
            "directory": lambda: self.target_file.mkdir(),
            "too large": lambda: self.target_file.write_text("# padding\n" * 8000),
            "not config": lambda: self.target_file.write_text("[core\n\t=== broken\n"),
        }
        for label, make in shapes.items():
            with self.subTest(label):
                if self.target_file.is_symlink() or self.target_file.is_file():
                    self.target_file.unlink()
                elif self.target_file.is_dir():
                    self.target_file.rmdir()
                make()
                self.assertFalse(self.verify()["removable"])
                self.assertFalse(self.marker.exists())

    # ---- NEG-6: the file is only read when the extension is on
    def test_a_per_worktree_file_is_ignored_without_the_extension_and_the_extension_inside_it_enables_nothing(self):
        self.write(self.target_file, "core", "fsmonitor", None)
        self.write(self.primary_file, "core", "hooksPath", "/tmp")
        self.assertTrue(self.verify()["removable"])  # git does not read them, and neither does the verifier
        self.target_file.write_text("[extensions]\n\tworktreeConfig = true\n")
        self.primary_file.unlink()
        self.assertTrue(self.verify()["removable"])
        self.assertFalse(cg._worktree_config_enabled((self.common / "config").read_text().replace("\n", "\x00")))

    # ---- NEG-7 and NEG-8: the other checks still decide
    def test_sparse_checkout_files_dirty_and_primary_worktrees_still_refuse_for_their_own_reasons(self):
        self.raw("[extensions]", "\tworktreeConfig = true")
        # a REAL sparse checkout, the shape on the t2-dev worktrees: git writes core.sparseCheckout into config.worktree itself
        git(self.linked, "sparse-checkout", "set", "--no-cone", "/nothing-matches-here")
        self.assertIn("sparsecheckout", self.target_file.read_text().lower())
        self.assertRefused("hidden from git status")
        git(self.linked, "sparse-checkout", "disable")
        # git 2.54 leaves `index.sparse = false` in the file after a disable (the real t2-dev files have it too): allowlisted
        self.assertTrue(self.verify()["removable"], self.verify())
        (self.linked / "a.txt").write_text("changed\n")
        self.assertRefused("not clean")
        git(self.linked, "checkout", "-q", "--", "a.txt")
        self.assertRefused("not a plain file", self.verify(self.primary))

    def test_the_per_worktree_allowlist_itself_checks_value_shapes_even_where_git_would_not_stop(self):
        refuse = cg._per_worktree_items_refusal
        self.assertIsNone(refuse(""))
        self.assertIsNone(refuse("core.sparsecheckout\ntrue\x00core.sparsecheckoutcone\nfalse\x00core.bare\nfalse\x00"))
        self.assertIsNone(refuse("core.sparsecheckout\x00"))  # a bare key is true, which git accepts here
        self.assertIsNone(refuse("CORE.SparseCheckout\nYES\x00core.bare\nNo\x00index.sparse\nfalse\x00index.sparse\x00"))
        for listing in ("core.sparsecheckout\nmaybe\x00", "core.sparsecheckoutcone\n2\x00", "core.sparsecheckout\n\x00",
                        "core.bare\x00", "core.bare\ntrue\x00", "core.bare\n2\x00", "core.bare\n\x00",
                        "core.fsmonitor\nx\x00", "index.sparse\nmaybe\x00", "index.version\n4\x00", "extensions.worktreeconfig\ntrue\x00",
                        "core.sparsecheckout\ntrue\x00core.hookspath\n/tmp\x00"):
            with self.subTest(listing=listing[:40]):
                self.assertIsNotNone(refuse(listing))
        self.assertNotIn("\x00", refuse("weird\x01key\ntrue\x00"))
        self.assertNotIn("true", refuse("core.hookspath\nsecret-value\x00"))  # names only, never a value

    # ---- AC-3 order, NEG-12 timeout, AC-5
    def test_the_per_worktree_vetting_runs_before_status_and_a_timeout_refuses(self):
        self.raw("[extensions]", "\tworktreeConfig = true")
        self.target_file.parent.mkdir(parents=True, exist_ok=True)
        self.target_file.write_text("[core]\n\tsparseCheckout = true\n")
        calls = []
        real = cg._git_out

        def spy(repo, args, timeout, stdin=None):
            calls.append(list(args))
            return real(repo, args, timeout, stdin)
        with mock.patch.object(cg, "_git_out", spy):
            self.assertTrue(self.verify()["removable"])
        names = [c[0] for c in calls]
        first_file = next(i for i, c in enumerate(calls) if c[:2] == ["config", "--file"])
        for later in ("ls-files", "status"):
            self.assertLess(first_file, names.index(later))

        def slow(repo, args, timeout, stdin=None):
            if args[:2] == ["config", "--file"]:
                raise TimeoutError("time budget")
            return real(repo, args, timeout, stdin)
        with mock.patch.object(cg, "_git_out", slow):
            report = self.verify()
        self.assertFalse(report["removable"])
        self.assertIn("TimeoutError", report["reason"])

    def test_reflogs_off_is_allow_list_based_in_the_shared_config(self):
        original = (self.common / "config").read_text()
        for value in ("false", "0", "no", "off", "never", "00", "0k", "", "garbage"):
            with self.subTest(value=value):
                (self.common / "config").write_text(original)
                self.raw("[core]", "\tlogAllRefUpdates = " + value)
                self.assertRefused(("reflogs are switched off",) + self.GIT_STOPS)  # git itself rejects never and garbage
        for lines in (["[core]", "\tlogAllRefUpdates = true"],
                      ["[core]", "\tlogAllRefUpdates = yes"], ["[core]", "\tlogAllRefUpdates = on"],
                      ["[core]", "\tlogAllRefUpdates = 1"], ["[core]", "\tlogAllRefUpdates = always"]):
            with self.subTest(lines=lines[1:]):
                (self.common / "config").write_text(original)
                self.raw(*lines)
                self.assertTrue(self.verify()["removable"], self.verify())

    def test_the_removal_command_also_switches_fsmonitor_off(self):
        real, seen = subprocess.run, []

        def spy(argv, *args, **kwargs):
            if "worktree" in argv and "remove" in argv:
                seen.append(list(argv))
            return real(argv, *args, **kwargs)
        with mock.patch.object(cg.subprocess, "run", spy):
            self.assertTrue(cg.remove_worktree(str(self.linked), policy=None)["removed"])
        self.assertIn("core.fsmonitor=false", seen[0])
        self.assertIn("core.hooksPath=/dev/null", seen[0])

    # ---- AC-6: the clone verifier stays strict
    def test_the_strict_config_check_the_clone_verifier_uses_still_refuses_the_extension(self):
        listing = "extensions.worktreeconfig\ntrue\x00"
        self.assertIn("[extensions] section", cg._config_refusal(listing))
        self.assertIsNone(cg._config_refusal(listing, allow_worktree_config=True))
        self.assertIn("[extensions] section", cg._config_refusal("extensions.objectformat\nsha256\x00", allow_worktree_config=True))
        clone = self.home / "clone"
        clone.mkdir()
        git(clone, "init", "-q", "-b", "main")
        (clone / "a.txt").write_text("x\n")
        git(clone, "add", "a.txt")
        git(clone, "commit", "-q", "-m", "x")
        git(clone, "remote", "add", "origin", "https://github.com/acme/widgets.git")
        git(clone, "config", "extensions.worktreeConfig", "true")
        self.assertIn("[extensions] section", cg.reproducible_clone_refusal(str(clone), self.policy) or "")


if __name__ == "__main__":
    unittest.main()
