"""Failing-first evidence: each mutant re-creates a bug, the named test must fail; the clean run must pass."""
import os
import re
import stat
import sys
import unittest

ROOT = "/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/software-factory/s1/receipt-clone"
sys.path.insert(0, ROOT + "/harness/hooks")
sys.path.insert(0, ROOT)
from lane import commands as cmd, manifest as mf, store as st, identity as ident  # noqa: E402
from tests import test_lane_commands, test_lane_store, test_lane_identity, test_lane_r1  # noqa: E402,F401


def run(module, test_id):
    suite = unittest.defaultTestLoader.loadTestsFromName("tests.%s.%s" % (module, test_id))
    result = unittest.TextTestRunner(stream=open(os.devnull, "w"), verbosity=0).run(suite)
    return "ran %d, failed %d" % (result.testsRun, len(result.failures) + len(result.errors))


M1 = ("test_lane_commands", "CheckpointTests.test_identity_comes_only_from_the_stamp_and_must_match_the_holder")
RACE = ("test_lane_store", "RootRaceTests.test_a_creation_race_is_tolerated_deterministically")
SRC = ("test_lane_commands", "LiveTargetTests.test_set_and_show_with_source")
STAMP = ("test_lane_commands", "RealCliPathTests.test_main_checkpoint_through_the_real_entry_succeeds_on_one_stamp")
EXEC = ("test_lane_identity", "NoExecTests.test_identity_and_held_check_start_no_process_and_agree_with_git")

print("clean    M1: %s | race: %s | source: %s | no-exec: %s" % (run(*M1), run(*RACE), run(*SRC), run(*EXEC)))

orig_checkpoint = cmd.checkpoint


def trusting(ports, store, **kw):  # mutant: the caller's claim is believed instead of the hook stamp
    ports.is_main = lambda c, k: True
    return orig_checkpoint(ports, store, **kw)


cmd.checkpoint = trusting
print("mutant   M1 (caller claim trusted):", run(*M1))
cmd.checkpoint = orig_checkpoint

orig_root = st.Store.ensure_root


def old_ensure_root(self):  # mutant: the original unguarded mkdir
    if os.path.islink(str(self.root)):
        raise st.RefusedInput("lane store root is a symlink")
    if not self.root.exists():
        self.root.mkdir(mode=0o700, parents=True)
        os.chmod(str(self.root), 0o700)
    info = os.lstat(str(self.root))
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise st.RefusedInput("loose")


st.Store.ensure_root = old_ensure_root
print("mutant   root race (unguarded mkdir):", run(*RACE))
st.Store.ensure_root = orig_root

orig_src = mf.SOURCE
mf.SOURCE = re.compile(r"^(user|answer|ticket|file|wal|queue):[A-Za-z0-9:/#._@-]{1,200}$")
print("mutant   manifest source class (old regex):", run(*SRC))
mf.SOURCE = orig_src

import subprocess  # noqa: E402
orig_git_dir = ident._git_dir
orig_remotes = ident._remotes


def exec_remotes(path):  # mutant: the old `git remote` exec
    out = subprocess.run(["git", "-C", str(path), "remote", "-v"], capture_output=True, text=True)
    return orig_remotes(path)


ident._remotes = exec_remotes
print("mutant   identity via git exec:", run(*EXEC))
ident._remotes = orig_remotes
orig_cp = cmd.checkpoint


def double_consuming(ports, store, **kw):  # mutant: checkpoint asks for the one-shot stamp again instead of using `main`
    kw["main"] = None
    return orig_cp(ports, store, **kw)


cmd.checkpoint = double_consuming
print("mutant   checkpoint consumes the stamp twice:", run(*STAMP))
cmd.checkpoint = orig_cp
# F1 mutant: the old comparison (None == None passes), compiled from the head's own source
import types  # noqa: E402
src = open(ROOT + "/harness/hooks/lane/commands.py").read()
new_cond = 'if not isinstance(who, str) or not who or not isinstance(holder, str) or not holder or who != holder \\\n                or caller.get("generation", gen) != gen:'
assert new_cond in src, "head source changed"
old_src = src.replace(new_cond, 'if who != holder or caller.get("generation", gen) != gen:')
mut = types.ModuleType("lane.commands_f1")
mut.__package__ = "lane"
mut.__file__ = "commands_f1.py"
exec(compile(old_src, "commands_f1.py", "exec"), mut.__dict__)
F1A = ("test_lane_r1", "UnstampedCallerTests.test_unstamped_caller_on_an_unbound_lane_is_refused_with_zero_effects")
F1B = ("test_lane_r1", "UnstampedCallerTests.test_empty_or_none_caller_is_refused_even_if_the_holder_is_also_empty")
print("clean    F1: %s | %s" % (run(*F1A), run(*F1B)))
import ah_lane  # noqa: E402
good, good_ah = test_lane_r1.cmd, ah_lane.commands
test_lane_r1.cmd = mut
ah_lane.commands = mut
print("mutant   F1 (None == None passes): %s | %s" % (run(*F1A), run(*F1B)))
test_lane_r1.cmd, ah_lane.commands = good, good_ah
# F2 mutant: an existing path is accepted unchecked (the old os.path.exists behaviour)
from lane import worktrees  # noqa: E402
orig_vw = worktrees.verify_worktree
F2 = [("test_lane_r1", "WorktreeTests." + n) for n in ("test_unrelated_directory_is_refused", "test_another_repos_worktree_is_refused",
      "test_wrong_branch_or_detached_head_is_refused", "test_symlink_to_a_valid_worktree_is_refused",
      "test_the_main_checkout_itself_is_refused", "test_start_refuses_before_reserving_and_a_good_path_is_accepted")]
print("clean    F2:", [run(*t) for t in F2])
worktrees.verify_worktree = lambda *a, **k: None
print("mutant   F2 (existing path accepted):", [run(*t) for t in F2])
worktrees.verify_worktree = orig_vw
print("restored M1: %s | race: %s | source: %s | no-exec: %s" % (run(*M1), run(*RACE), run(*SRC), run(*EXEC)))
