"""merge_gate.py: ref and bulk-data writes through the GitHub API must target history that is in main (goodqa#14909).

Real-tool control: every case runs against real throwaway git repositories (no network; the "GitHub remote" is a local bare
repository reached through url.<path>.insteadOf, so the hook's fresh `git fetch origin main` is a real fetch). The fake gh
runner raises if the gate ever calls gh. Deterministic: no randomness. MERGE_GATE_HOOKS_DIR runs the same cases on old code."""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
HOOKS = Path(os.environ.get("MERGE_GATE_HOOKS_DIR") or ROOT / "harness" / "hooks")
sys.path.insert(0, str(HOOKS))
import merge_gate as mg  # noqa: E402

ENV = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@e", GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@e",
           GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_SYSTEM="/dev/null")


def git(cwd, *args):
    return subprocess.run(["git", *args], cwd=cwd, env=ENV, capture_output=True, text=True, check=True).stdout.strip()


def no_gh(args, timeout, cwd=None):
    raise AssertionError("the ref-write path must not call gh: " + " ".join(args))


def commit(repo, name, text=None):
    Path(repo, name).write_text(text or name)
    git(repo, "add", name)
    git(repo, "commit", "-q", "-m", name)
    return git(repo, "rev-parse", "HEAD")


class RefWrite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        base = cls.tmp.name
        cls.remote = os.path.join(base, "remote.git")
        cls.repo = os.path.join(base, "r")
        git(base, "init", "-q", "--bare", "-b", "main", cls.remote)
        os.mkdir(cls.repo)
        git(cls.repo, "init", "-q", "-b", "main")
        git(cls.repo, "remote", "add", "origin", "https://github.com/o/r.git")
        git(cls.repo, "config", "url.%s.insteadOf" % cls.remote, "https://github.com/o/r.git")
        commit(cls.repo, "a")
        cls.on_main = commit(cls.repo, "b")
        git(cls.repo, "push", "-q", "--no-verify", "origin", "main")
        git(cls.repo, "checkout", "-q", "-b", "feature")
        cls.feature = commit(cls.repo, "f")  # shares history with main, not on main
        git(cls.repo, "checkout", "-q", "-b", "listed", cls.on_main)
        cls.listed = commit(cls.repo, "l")  # shares history with main but is on the pre-rewrite list
        git(cls.repo, "checkout", "-q", "--orphan", "old")
        Path(cls.repo, "o").write_text("old")
        git(cls.repo, "add", "o")
        git(cls.repo, "commit", "-q", "-m", "old")
        cls.off_main = git(cls.repo, "rev-parse", "HEAD")
        git(cls.repo, "checkout", "-q", "main")
        cls.oldlist = os.path.join(base, "old.gz")
        import gzip
        with gzip.open(cls.oldlist, "wt") as handle:
            handle.write(cls.listed[:12] + "\n" + cls.off_main[:12] + "\n")
        cls.plain = os.path.join(base, "plain")
        os.mkdir(cls.plain)
        cls.lookalike = os.path.join(base, "lookalike")
        os.mkdir(cls.lookalike)
        git(cls.lookalike, "init", "-q", "-b", "main")
        git(cls.lookalike, "remote", "add", "origin", "https://github.com/o/r-old.git")
        cls.bigfile = os.path.join(base, "big.bin")
        with open(cls.bigfile, "wb") as handle:
            handle.truncate(8 * 1024 * 1024)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        os.environ["MERGE_GATE_OLD_SHAS"] = self.oldlist
        mg.ALLOW_INSTEADOF = True  # the fixtures reach their "GitHub" through insteadOf; test_n1 turns the refusal back on

    def tearDown(self):
        os.environ.pop("MERGE_GATE_OLD_SHAS", None)
        mg.ALLOW_INSTEADOF = False

    def run_cmd(self, command, cwd=None):
        payload = {"tool_name": "Bash", "tool_input": {"command": command}, "cwd": cwd or self.repo}
        with tempfile.TemporaryDirectory() as state:
            return mg.decide(payload, no_gh, state)

    def ok(self, command, cwd=None):
        code, text = self.run_cmd(command, cwd)
        self.assertEqual(code, 0, text)

    def blocked(self, command, cwd=None, needle=None):
        code, text = self.run_cmd(command, cwd)
        self.assertEqual(code, 2, "expected a block for: " + command)
        if needle:
            self.assertIn(needle, text)

    def api(self, method, endpoint, *fields):
        return "gh api -X %s %s %s" % (method, endpoint, " ".join("-f %s" % f for f in fields))

    # --- core -----------------------------------------------------------------------------------------------------
    def test_tag_on_main_allowed(self):
        self.ok(self.api("POST", "repos/o/r/git/refs", "ref=refs/tags/v1", "sha=" + self.on_main))

    def test_incident_tag_at_old_history_blocked(self):
        self.blocked(self.api("POST", "repos/o/r/git/refs", "ref=refs/tags/backup-pin/x", "sha=" + self.off_main), needle="shares no history")

    def test_h1_branch_create_at_old_history_blocked(self):
        self.blocked(self.api("POST", "repos/o/r/git/refs", "ref=refs/heads/backup-pin", "sha=" + self.off_main))

    def test_h1_main_moved_to_old_history_blocked(self):
        self.blocked(self.api("PATCH", "repos/o/r/git/refs/heads/main", "sha=" + self.off_main, "force=true"))

    def test_feature_branch_off_main_history_allowed(self):
        self.ok(self.api("POST", "repos/o/r/git/refs", "ref=refs/heads/feat", "sha=" + self.feature))

    def test_m1_release_tag_not_on_main_allowed(self):
        self.ok(self.api("POST", "repos/o/r/git/refs", "ref=refs/tags/rel-1", "sha=" + self.feature))

    def test_listed_pre_rewrite_commit_blocked_even_with_shared_history(self):
        self.blocked(self.api("POST", "repos/o/r/git/refs", "ref=refs/heads/x", "sha=" + self.listed), needle="pre-rewrite commit")

    def test_h2_stale_local_origin_main_does_not_count(self):
        git(self.repo, "update-ref", "refs/remotes/origin/main", self.off_main)  # a clone that never fetched after the rewrite
        try:
            self.blocked(self.api("POST", "repos/o/r/git/refs", "ref=refs/tags/backup-pin/x", "sha=" + self.off_main))
        finally:
            git(self.repo, "update-ref", "refs/remotes/origin/main", self.on_main)

    def test_h2_fetch_failure_fails_closed(self):
        broken = os.path.join(self.tmp.name, "broken")
        os.mkdir(broken)
        git(broken, "init", "-q", "-b", "main")
        git(broken, "remote", "add", "origin", "https://github.com/o/r.git")
        git(broken, "config", "url.%s.insteadOf" % os.path.join(self.tmp.name, "nowhere.git"), "https://github.com/o/r.git")
        self.blocked(self.api("POST", "repos/o/r/git/refs", "ref=refs/tags/v1", "sha=" + self.on_main), cwd=broken, needle="cannot fetch")

    # --- H3: other routes ----------------------------------------------------------------------------------------
    def test_h3_release_target_old_blocked_main_allowed(self):
        self.blocked(self.api("POST", "repos/o/r/releases", "tag_name=b", "target_commitish=" + self.off_main))
        self.ok(self.api("POST", "repos/o/r/releases", "tag_name=b", "target_commitish=" + self.on_main))
        self.ok(self.api("POST", "repos/o/r/releases", "tag_name=b", "target_commitish=main"))
        self.ok(self.api("POST", "repos/o/r/releases", "tag_name=b"))

    def test_h3_release_target_unknown_blocked(self):
        self.blocked("gh api -X POST repos/o/r/releases -f tag_name=b -f target_commitish=$SHA")

    def test_h3_gh_release_create_target(self):
        self.blocked("gh release create b --target %s -R o/r" % self.off_main)
        self.ok("gh release create b --target %s -R o/r" % self.on_main)
        self.ok("gh release create b --notes hi")
        self.blocked("gh release create b --target $SHA")

    def test_h3_graphql_create_ref(self):
        q = 'mutation { createRef(input:{repositoryId:"R_x", name:"refs/tags/b", oid:"%s"}) { ref { name } } }'
        self.blocked("gh api graphql -f query='%s'" % (q % self.off_main))
        self.ok("gh api graphql -f query='%s'" % (q % self.on_main))
        self.blocked("gh api graphql -f query='mutation($o: GitObjectID!) { createRef(input:{repositoryId:\"R_x\", name:\"refs/tags/b\", oid:$o}) { ref { name } } }' -f o=%s" % self.on_main)

    def test_h3_graphql_update_refs(self):
        q = 'mutation { updateRefs(input:{repositoryId:"R_x", refUpdates:[{name:"refs/heads/main", afterOid:"%s"}]}) { clientMutationId } }'
        self.blocked("gh api graphql -f query='%s'" % (q % self.off_main))

    def test_h3_api_commit_with_old_parent_blocked(self):
        tree = git(self.repo, "rev-parse", self.on_main + "^{tree}")
        self.blocked("gh api -X POST repos/o/r/git/commits -f message=m -f tree=%s -f 'parents[]=%s'" % (tree, self.off_main))
        self.ok("gh api -X POST repos/o/r/git/commits -f message=m -f tree=%s -f 'parents[]=%s'" % (tree, self.on_main))

    def test_h3_annotated_tag_object_blocked(self):
        self.blocked(self.api("POST", "repos/o/r/git/tags", "tag=v2", "message=m", "object=" + self.off_main, "type=commit"))

    # --- H4: parser tricks ----------------------------------------------------------------------------------------
    def test_h4_ref_from_file_still_judged(self):
        self.blocked("gh api -X POST repos/o/r/git/refs -F ref=@ref.txt -f sha=%s" % self.off_main)

    def test_h4_sha_from_file_blocked(self):
        self.blocked("gh api -X POST repos/o/r/git/refs -f ref=refs/tags/v1 -F sha=@sha.txt")

    def test_h4_input_with_decoy_fields_blocked(self):
        self.blocked("gh api -X POST repos/o/r/git/refs -f ref=refs/heads/decoy --input body.json")
        self.blocked("gh api -X POST repos/o/r/git/refs -f ref=refs/heads/decoy -f sha=%s --input body.json" % self.on_main)

    def test_runtime_and_short_sha_blocked(self):
        self.blocked("gh api -X POST repos/o/r/git/refs -f ref=refs/tags/v1 -f sha=$SHA")
        self.blocked(self.api("POST", "repos/o/r/git/refs", "ref=refs/tags/v1", "sha=" + self.on_main[:10]))
        self.blocked(self.api("POST", "repos/o/r/git/refs", "ref=refs/tags/v1", "sha=" + "c" * 40))

    def test_l1_percent_encoded_tag_path(self):
        self.blocked(self.api("PATCH", "repos/o/r/git/refs/tags%2Fv1", "sha=" + self.off_main))

    def test_l2_lookalike_remote_is_not_the_repo(self):
        self.blocked(self.api("POST", "repos/o/r/git/refs", "ref=refs/tags/v1", "sha=" + self.on_main), cwd=self.lookalike)

    # --- M2: size -------------------------------------------------------------------------------------------------
    def test_m2_contents_api_evidence_path_blocked(self):
        self.blocked("gh api -X PUT repos/o/r/contents/.lanes/x/big.zip -f message=m -f content=QUJD")
        self.blocked("gh api -X PUT repos/o/r/contents/Plans/Evidence/y/e.log -f message=m -f content=QUJD")
        self.ok("gh api -X PUT repos/o/r/contents/docs/readme.md -f message=m -f content=QUJD")

    def test_m2_contents_big_file_blocked(self):
        self.blocked("gh api -X PUT repos/o/r/contents/docs/big.bin -f message=m -F content=@%s" % self.bigfile)

    def test_m2_blob_api_runtime_or_big_content_blocked(self):
        self.blocked("gh api -X POST repos/o/r/git/blobs -f content=$(base64 -i big.bin) -f encoding=base64")
        self.blocked("gh api -X POST repos/o/r/git/blobs -F content=@%s -f encoding=base64" % self.bigfile)
        self.ok("gh api -X POST repos/o/r/git/blobs -f content=hello -f encoding=utf-8")

    # --- B5: skipping the client guard ----------------------------------------------------------------------------
    def test_b5_push_no_verify_and_hookspath_blocked(self):
        for cmd in ("git push --no-verify origin feat", "git push origin feat --no-verify", "git push --no-ver origin feat",
                    "git -c core.hooksPath=/dev/null push origin feat", "git -c core.hookspath=/x push origin feat",
                    "GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.hooksPath GIT_CONFIG_VALUE_0=/dev/null git push origin feat",
                    "bash -c 'git push --no-verify origin feat'"):
            self.blocked(cmd, needle="pre-push")

    def test_b5_plain_feature_push_allowed(self):
        self.ok("git push origin feat")
        self.ok("git push -u origin my-branch")

    # --- general --------------------------------------------------------------------------------------------------
    def test_delete_and_read_never_blocked(self):
        self.ok("gh api -X DELETE repos/o/r/git/refs/tags/backup-pin/x")
        self.ok("gh api repos/o/r/git/refs/tags")

    def test_not_a_checkout_blocked(self):
        self.blocked(self.api("POST", "repos/o/r/git/refs", "ref=refs/tags/v1", "sha=" + self.on_main), cwd=self.plain)

    def test_other_repo_checkout_blocked(self):
        self.blocked(self.api("POST", "repos/x/y/git/refs", "ref=refs/tags/v1", "sha=" + self.on_main))

    def test_wrapped_in_bash_c_blocked(self):
        inner = self.api("POST", "repos/o/r/git/refs", "ref=refs/tags/v1", "sha=" + self.off_main)
        self.blocked("bash -c '%s'" % inner)

    def test_cd_elsewhere_blocked(self):
        self.blocked("cd /somewhere/else && " + self.api("POST", "repos/o/r/git/refs", "ref=refs/tags/v1", "sha=" + self.on_main))

    def test_missing_sha_list_fails_closed(self):
        os.environ["MERGE_GATE_OLD_SHAS"] = os.path.join(self.tmp.name, "absent.gz")
        self.blocked(self.api("POST", "repos/o/r/git/refs", "ref=refs/heads/x", "sha=" + self.on_main), needle="sha list")

    # --- delta red-team (round 2) --------------------------------------------------------------------------------------
    def test_h2_forged_local_origin_main_with_no_tracking_update(self):
        # without remote.origin.fetch the fetch cannot repair refs/remotes/origin/main, so a mutant that trusts it survives
        # every other test; the real code uses FETCH_HEAD
        git(self.repo, "config", "--unset-all", "remote.origin.fetch")
        git(self.repo, "update-ref", "refs/remotes/origin/main", self.off_main)
        try:
            self.blocked(self.api("POST", "repos/o/r/git/refs", "ref=refs/tags/backup-pin/x", "sha=" + self.off_main), needle="shares no history")
        finally:
            git(self.repo, "config", "--add", "remote.origin.fetch", "+refs/heads/*:refs/remotes/origin/*")
            git(self.repo, "update-ref", "refs/remotes/origin/main", self.on_main)

    def test_n1_insteadof_redirect_refuses(self):
        mg.ALLOW_INSTEADOF = False
        self.blocked(self.api("POST", "repos/o/r/git/refs", "ref=refs/tags/v1", "sha=" + self.on_main), needle="insteadOf")

    def test_n2_repositories_alias(self):
        self.blocked("gh api -X POST repositories/123456/git/refs -f ref=refs/tags/b -f sha=" + self.off_main)
        self.ok("gh api -X POST repositories/123456/git/refs -f ref=refs/tags/b -f sha=" + self.on_main)
        self.blocked("gh api -X POST repositories/123456/releases -f tag_name=b -f target_commitish=" + self.off_main)
        self.blocked("gh api -X PUT repositories/123456/contents/.lanes/x/e.zip -f message=m -f content=QUJD")
        self.blocked("gh api -X POST /repositories/123456/git/refs -f ref=refs/tags/b -f sha=" + self.off_main)

    GQL = 'mutation { createRef(input:{repositoryId:"R_x", name:"refs/tags/b", oid:%s}) { ref { name } } }'

    def test_n3_block_string_and_decoy_comment(self):
        quoted = self.GQL % ('"""%s"""' % self.off_main)
        self.blocked("gh api graphql -f query='%s # oid:\"%s\"'" % (quoted, self.on_main))
        self.blocked("gh api graphql -f query='%s'" % quoted)
        decoy = self.GQL % ('"%s"' % self.off_main)
        self.blocked("gh api graphql -f query='%s # oid:\"%s\"'" % (decoy, self.on_main))

    def test_n4_unicode_escape_in_aliased_mutation(self):
        q = ('mutation { a: createRef(input:{repositoryId:"R_x", name:"refs/tags/a", oid:"%s"}) { clientMutationId } '
             'b: createRef(input:{repositoryId:"R_x", name:"refs/tags/b", oid:"\\u0030%s"}) { clientMutationId } }') % (self.on_main, self.off_main[1:])
        self.blocked("gh api graphql -f query='%s'" % q)

    def test_n4_plain_aliases_each_judged(self):
        q = ('mutation { a: createRef(input:{repositoryId:"R_x", name:"refs/tags/a", oid:"%s"}) { clientMutationId } '
             'b: createRef(input:{repositoryId:"R_x", name:"refs/tags/b", oid:"%s"}) { clientMutationId } }')
        self.blocked("gh api graphql -f query='%s'" % (q % (self.on_main, self.off_main)))
        self.ok("gh api graphql -f query='%s'" % (q % (self.on_main, self.feature)))

    def test_n4_call_without_oid_blocked(self):
        self.blocked("gh api graphql -f query='mutation { createRef(input:{repositoryId:\"R_x\", name:\"refs/tags/b\"}) { clientMutationId } }'")

    def test_n5_create_commit_on_branch_evidence_path(self):
        q = ('mutation { createCommitOnBranch(input:{branch:{repositoryNameWithOwner:"o/r", branchName:"feat"}, message:{headline:"m"}, '
             'expectedHeadOid:"%s", fileChanges:{additions:[{path:"%s", contents:"QUJD"}]}}) { commit { oid } } }')
        self.blocked("gh api graphql -f query='%s'" % (q % (self.on_main, ".lanes/x/big.zip")))
        self.blocked("gh api graphql -f query='%s'" % (q % (self.on_main, "Plans/Evidence/y/e.log")))
        self.ok("gh api graphql -f query='%s'" % (q % (self.on_main, "docs/readme.md")))
        self.blocked("gh api graphql -f query='mutation($c: Base64String!) { createCommitOnBranch(input:{fileChanges:{additions:[{path:\"d.bin\", contents:$c}]}}) { commit { oid } } }' -F c=@%s" % self.bigfile)

    def test_n6_api_commit_must_reuse_a_tree_of_main(self):
        old_tree = git(self.repo, "rev-parse", self.off_main + "^{tree}")
        main_tree = git(self.repo, "rev-parse", self.on_main + "^{tree}")
        cmd = "gh api -X POST repos/o/r/git/commits -f message=m -f tree=%s -f 'parents[]=%s'"
        self.blocked(cmd % (old_tree, self.on_main), needle="not in main")
        self.blocked(cmd % ("a" * 40, self.on_main))
        self.blocked("gh api -X POST repos/o/r/git/commits -f message=m -f 'parents[]=%s'" % self.on_main)
        self.ok(cmd % (main_tree, self.on_main))

    def test_n6_git_trees_route_blocked(self):
        self.blocked("gh api -X POST repos/o/r/git/trees -f base_tree=%s" % self.on_main)

    def test_b5_config_writes_and_exports(self):
        for cmd in ("git config core.hooksPath /tmp/none && git push origin feat", "git config --global core.hooksPath /tmp/none",
                    "git config include.path /tmp/evil.cfg", "git config --add includeIf.gitdir:/x.path /tmp/e.cfg",
                    "export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.hooksPath GIT_CONFIG_VALUE_0=/dev/null; git push origin feat",
                    "declare -x GIT_CONFIG_COUNT=1; git push origin feat", "GIT_DIR=/other/.git git push origin feat"):
            self.blocked(cmd)
        for cmd in ("git config --get core.hooksPath", "git config user.name 'T'", "git config --unset core.hooksPath",
                    "git config --list"):
            self.ok(cmd)

    def test_n12_git_dir_and_work_tree_on_push(self):
        self.blocked("git --git-dir=/other/.git push origin feat")
        self.blocked("git --git-dir /other/.git push origin feat")
        self.blocked("git --work-tree=/other push origin feat")
        self.ok("git -C /some/worktree push origin feat")

    def test_f1_wal_note_quoting_a_command_is_not_that_command(self):
        home = str(Path.home())
        note = "probe gh api -X POST repos/o/r/git/refs with -f sha=%s and gh release create b --target %s" % (self.off_main, self.off_main)
        self.ok("python3 %s/.claude/hooks/wal_note.py --wal /x --event risk --note '%s'" % (home, note))
        self.ok("python3 ~/.claude/hooks/wal_note.py --wal /x --event risk --note '%s'" % note)
        self.blocked("python3 %s/.claude/hooks/wal_note.py --note \"$(gh api -X POST repos/o/r/git/refs -f ref=refs/tags/b -f sha=%s)\"" % (home, self.off_main))
        self.blocked("python3 /tmp/other.py '%s'" % ("gh api -X POST repos/o/r/git/refs -f ref=refs/tags/b -f sha=" + self.off_main))

    def test_cases_not_vacuous(self):
        self.assertNotEqual(self.on_main, self.off_main)
        self.assertEqual(len(self.on_main), 40)
        self.assertEqual(git(self.repo, "merge-base", self.feature, self.on_main), self.on_main)


if __name__ == "__main__":
    unittest.main()
