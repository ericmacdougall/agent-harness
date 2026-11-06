"""goodqa#14908: prod_delete_guard, ported from Hawkeye's hawkeye-prod-delete-guard.py.

The detection cases are Hawkeye's own (tests/test-prod-delete-guard.py: H-1, H-1b, H-1c, the H-2
accepted limitations and the BLOCKER 1-3 regression pins). Grants replace hawk_ask with a
user-sourced file under ~/.agent-harness/state. Every test uses its own temporary HOME. Commands are
judged by evaluate() or by the hook run as a child process, and are never executed.
PDG_HOOKS_DIR points the suite at another implementation; the mutants in the review packet use it
to show the suite failing first.
"""

import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOOKS = Path(os.environ.get("PDG_HOOKS_DIR") or ROOT / "harness/hooks")
sys.path.insert(0, str(HOOKS))

import prod_delete_guard as pdg  # noqa: E402

SID = "sess-pdg"


def bash(command):
    return {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": command}}


def ok_resolver(source, home=None):
    return {"text": "yes", "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}


class Case(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="pdg-")
        self.home = Path(os.path.realpath(self._tmp.name))
        self._env = {k: os.environ.get(k) for k in ("HOME", "CLAUDE_CONFIG_DIR")}
        os.environ["HOME"] = str(self.home)
        os.environ.pop("CLAUDE_CONFIG_DIR", None)
        self.wal = self.home / ".claude/wals/s/agent-pdg.jsonl"
        self.wal.parent.mkdir(parents=True)

    def tearDown(self):
        for key, value in self._env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self._tmp.cleanup()

    def verdict(self, ev, **kw):
        kw.setdefault("home", str(self.home))
        result = pdg.evaluate(ev, **kw)
        return result[0] if result else "allow"

    def assertDenied(self, command, **kw):
        self.assertEqual(self.verdict(bash(command), **kw), "deny", command)

    def assertAllowed(self, command, **kw):
        self.assertEqual(self.verdict(bash(command), **kw), "allow", command)

    def human_turn(self, text="Yes, drop it (Recommended)", when=None):
        uid = str(uuid.uuid4())
        stamp = when or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        path = self.home / ".claude/projects/p" / (SID + ".jsonl")
        path.parent.mkdir(parents=True, exist_ok=True)
        record = {"type": "user", "uuid": uid, "timestamp": stamp, "sessionId": SID, "origin": {"kind": "human"},
                  "message": {"role": "user", "content": text}}
        with open(path, "a") as fh:
            fh.write(json.dumps(record) + "\n")
        return "user:%s/%s" % (SID, uid)

    def write_grants(self, grants):
        path = pdg.grants_path(str(self.home))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"grants": grants}))
        return path


class Detection(Case):
    """Hawkeye's cases, as end-to-end verdicts with no grant recorded."""

    def test_h1_at_sign_before_prod(self):
        self.assertDenied("psql 'postgresql://u:p@prod-db.example.com/main' -c 'DROP TABLE users'")
        self.assertDenied("psql 'postgresql://u:p@prod.example.com/main' -c 'DROP TABLE users'")

    def test_h1b_colon_after_prod(self):
        self.assertDenied("psql 'postgresql://u:p@prod:5432/main' -c 'DROP TABLE users'")

    def test_h1c_query_and_fragment_after_prod(self):
        self.assertDenied("psql 'postgresql://u:p@prod?sslmode=require' -c 'DROP TABLE users'")
        self.assertDenied("psql 'postgresql://u:p@prod#frag' -c 'DROP TABLE users'")

    def test_controls_flag_targets(self):
        self.assertDenied("psql 'postgresql://u:p@db-prod.example.com/main' -c 'DROP TABLE users'")
        self.assertDenied("psql --host=prod-db.example.com -c 'TRUNCATE sessions'")
        self.assertDenied("mysql -h prod.internal -e 'DROP DATABASE app'")
        self.assertDenied("mysqldump --host=prod.example.com --all-databases | mysql --host=other && "
                          "mysql -h prod-shard-1 -e 'DROP DATABASE app'")
        self.assertDenied("mongosh --host production.cluster --eval 'db.x.drop()' ; psql -d production -c 'DELETE FROM t'")

    def test_d1_remote_and_file_payload(self):
        self.assertDenied('wrangler d1 execute mydb --remote --command="DELETE FROM users"')
        self.assertDenied('python3 -c "import subprocess" && wrangler d1 execute mydb --remote --command="DELETE FROM users"')
        sql = self.home / "payload.sql"
        sql.write_text("DELETE FROM users;\n")
        self.assertDenied("wrangler d1 execute mydb --remote --file=%s" % sql)
        self.assertAllowed("wrangler d1 execute mydb --file=%s" % sql)  # local D1 is a throwaway file
        sql.write_text("SELECT 1;\n")
        self.assertAllowed("wrangler d1 execute mydb --remote --file=%s" % sql)

    def test_accepted_limitations_and_blocker_pins_still_deny(self):
        for command in (
                "python3 -c \"print('example: wrangler d1 execute mydb --remote --command=\\\"DELETE FROM users\\\"')\"",
                "cat >> notes.md <<'EOF'\n## finding\nDROP TABLE against postgresql://u:p@prod-db.example.com/main\nEOF\n",
                "python3 -c \"import subprocess; subprocess.run(['psql', '--host=prod-db.example.com', '-c', 'DROP TABLE users'])\"",
                "cat >> notes.md <<EOF\n$(psql 'postgresql://u:p@prod-db.example.com/main' -c 'DROP TABLE users')\nEOF\n",
                "cat >>script.sh <<'EOF'\npsql 'postgresql://u:p@prod-db.example.com/main' -c 'DROP TABLE users'\nEOF\nbash script.sh\n",
                "psql 'postgresql://u:p@prod-db.example.com/main' <<'EOF'\nDELETE FROM users WHERE 1=1;\nEOF\n",
                "bash <<'EOF'\nwrangler d1 execute mydb --remote --command=\"DELETE FROM users\"\nEOF\n"):
            with self.subTest(command=command[:60]):
                self.assertDenied(command)

    def test_non_production_and_non_destructive_are_allowed(self):
        for command in (
                "psql 'postgresql://u:p@localhost:5432/dev' -c 'DROP TABLE scratch'",
                "psql --host=prod-db.example.com -c 'SELECT count(*) FROM users'",
                "psql -h staging.example.com -c 'TRUNCATE sessions'",
                "grep -n 'DELETE FROM' notes/production-incident.md",
                "docker run -d prod-image sh -c 'echo DROP TABLE'",
                "psql -h reproduction.example.com -c 'DROP TABLE t'",  # 'prod' inside a word is not a segment
                "ls -la", ""):
            with self.subTest(command=command):
                self.assertAllowed(command)

    def test_mcp_tool_paths(self):
        d1 = {"tool_name": "mcp__cloudflare__d1_database_query", "tool_input": {"sql": "DELETE FROM devices"}}
        self.assertEqual(self.verdict(d1), "deny")
        d1["tool_input"] = {"sql": "SELECT * FROM devices"}
        self.assertEqual(self.verdict(d1), "allow")
        run = {"tool_name": "mcp__hawkeye__run",
               "tool_input": {"command": "ls", "payload": ["wrangler d1 execute db --remote --command='DROP TABLE x'"]}}
        self.assertEqual(self.verdict(run), "deny")
        sql = {"tool_name": "mcp__pg__execute_sql", "tool_input": {"statement": "psql -h prod-1 -c 'TRUNCATE t'"}}
        self.assertEqual(self.verdict(sql), "deny")
        sql["tool_input"] = {"sql": "DROP TABLE t"}  # no named target and not production by construction
        self.assertEqual(self.verdict(sql), "allow")
        hyper = {"tool_name": "mcp__cloudflare__hyperdrive_query", "tool_input": {}}
        self.assertEqual(self.verdict(hyper), "allow")  # no field it reads: nothing to judge
        self.assertEqual(self.verdict({"tool_name": "Write", "tool_input": {"content": "DROP TABLE x --host=prod"}}),
                         "allow")

    def test_malformed_events_allow(self):
        for ev in (None, [], {"tool_name": "Bash"}, {"tool_name": "Bash", "tool_input": "x"}, {"tool_input": {}}):
            with self.subTest(ev=ev):
                self.assertEqual(self.verdict(ev), "allow")

    def test_matcher_covers_every_judged_tool_shape(self):
        for name in ("Bash", "mcp__hawkeye__run", "mcp__cloudflare__d1_database_query", "mcp__pg__execute_sql",
                     "mcp__x__run_sql", "mcp__x__query", "mcp__x__sql", "mcp__cloudflare__hyperdrive_configs_list"):
            with self.subTest(name=name):
                self.assertTrue(re.fullmatch(pdg.MATCHER, name))
        for name in ("Write", "Edit", "Read", "Agent"):
            self.assertFalse(re.fullmatch(pdg.MATCHER, name), name)


class Grants(Case):
    CMD = "psql --host=prod-db.example.com -c 'TRUNCATE sessions'"

    def grant_entry(self, **over):
        now = int(time.time())
        entry = {"scope": "prod-db", "target": "prod-db.example.com", "user_source": "user:%s/x" % SID,
                 "granted_at": now, "expires_at": now + 600}
        entry.update(over)
        return entry

    def test_live_grant_for_named_target_allows(self):
        self.write_grants([self.grant_entry()])
        self.assertAllowed(self.CMD, resolver=ok_resolver)

    def test_grant_for_other_target_still_denies(self):
        self.write_grants([self.grant_entry(target="prod-other.example.com")])
        self.assertDenied(self.CMD, resolver=ok_resolver)

    def test_expired_grant_denies_and_says_so(self):
        self.write_grants([self.grant_entry(expires_at=int(time.time()) - 1)])
        result = pdg.evaluate(bash(self.CMD), home=str(self.home), resolver=ok_resolver)
        self.assertEqual(result[0], "deny")
        self.assertIn("expired", result[1])

    def test_grant_whose_source_no_longer_resolves_denies(self):
        self.write_grants([self.grant_entry()])
        self.assertDenied(self.CMD)  # real resolver: user:sess-pdg/x has no transcript

    def test_wrong_scope_or_short_target_is_ignored(self):
        self.write_grants([self.grant_entry(scope="*"), self.grant_entry(target="pr")])
        self.assertDenied("psql --host=prod-db.example.com -c 'TRUNCATE sessions' # pr", resolver=ok_resolver)

    def test_unreadable_store_asks_missing_store_denies(self):
        self.assertDenied(self.CMD)
        path = pdg.grants_path(str(self.home))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{not json")
        self.assertEqual(self.verdict(bash(self.CMD)), "ask")
        path.write_text('{"grants": 3}')
        self.assertEqual(self.verdict(bash(self.CMD)), "ask")
        path.unlink()
        path.mkdir()
        self.assertEqual(self.verdict(bash(self.CMD)), "ask")
        self.assertAllowed("ls")  # an unreadable store never touches non-matching commands

    def test_error_after_match_denies(self):
        saved = pdg.matching_grant
        pdg.matching_grant = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
        try:
            self.assertDenied(self.CMD)
        finally:
            pdg.matching_grant = saved

    def test_real_grant_round_trip_through_provenance_and_wal(self):
        source = self.human_turn()
        entry = pdg.grant(source, "prod-db.example.com", str(self.wal), ttl=600, home=str(self.home))
        self.assertEqual(entry["scope"], "prod-db")
        path = pdg.grants_path(str(self.home))
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertAllowed(self.CMD)  # real resolver, re-resolved at check time
        wal = [json.loads(line) for line in self.wal.read_text().splitlines()]
        self.assertTrue(any("prod_delete_guard grant" in r.get("note", "") and r.get("source") == source for r in wal))

    def test_grant_refusals_write_nothing(self):
        source = self.human_turn()
        old = self.human_turn(when="2026-01-01T00:00:00Z")
        cases = (
            dict(user_source="inferred: from me -- x"),
            dict(user_source="ticket:GoodQA goodqa#1"),
            dict(user_source="user:%s/%s" % (SID, uuid.uuid4())),
            dict(user_source=old),
            dict(target="pr"),
            dict(target=" prod-db "),
            dict(ttl=0), dict(ttl=pdg.MAX_TTL + 1),
            dict(wal=""),
        )
        for over in cases:
            kw = dict(user_source=source, target="prod-db.example.com", wal=str(self.wal), ttl=600,
                      home=str(self.home))
            kw.update(over)
            with self.subTest(over=over):
                with self.assertRaises(ValueError):
                    pdg.grant(**kw)
                self.assertFalse(pdg.grants_path(str(self.home)).exists())

    def test_failed_wal_record_writes_no_grant(self):
        source = self.human_turn()
        with self.assertRaises(ValueError):
            pdg.grant(source, "prod-db.example.com", str(self.wal), home=str(self.home), record=lambda *a: False)
        self.assertFalse(pdg.grants_path(str(self.home)).exists())

    def test_expired_grants_are_pruned_on_write(self):
        self.write_grants([self.grant_entry(expires_at=1)])
        pdg.grant("user:%s/y" % SID, "prod-db.example.com", str(self.wal), home=str(self.home),
                  resolver=ok_resolver, record=lambda *a: True)
        self.assertEqual(len(pdg.load_grants(str(self.home))), 1)


class HookProcess(Case):
    """The installed shape: python3 -I <script>, payload on stdin, like doctor's canary."""

    def hook(self, payload):
        return subprocess.run([sys.executable, "-I", str(HOOKS / "prod_delete_guard.py")], input=json.dumps(payload),
                              capture_output=True, text=True, env=dict(os.environ), timeout=60, check=False)

    def test_deny_and_allow_on_stdout_exit_zero(self):
        denied = self.hook(bash("psql --host=prod-db.example.com -c 'TRUNCATE sessions'"))
        self.assertEqual(denied.returncode, 0, denied.stderr)
        self.assertEqual(json.loads(denied.stdout)["hookSpecificOutput"]["permissionDecision"], "deny")
        allowed = self.hook(bash("ls"))
        self.assertEqual((allowed.returncode, allowed.stdout, allowed.stderr), (0, "", ""))

    def test_garbage_stdin_allows(self):
        r = subprocess.run([sys.executable, "-I", str(HOOKS / "prod_delete_guard.py")], input="{nope",
                           capture_output=True, text=True, timeout=60, check=False)
        self.assertEqual((r.returncode, r.stdout), (0, ""))

    def test_cli_grant_and_list(self):
        source = self.human_turn()
        cmd = [sys.executable, str(HOOKS / "prod_delete_guard.py")]
        r = subprocess.run(cmd + ["grant", "--user-source", source, "--target", "prod-db.example.com", "--wal",
                                  str(self.wal), "--ttl", "120"], capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout)["status"], "GRANTED")
        listed = subprocess.run(cmd + ["list"], capture_output=True, text=True, timeout=60)
        self.assertEqual([g["target"] for g in json.loads(listed.stdout)], ["prod-db.example.com"])
        refused = subprocess.run(cmd + ["grant", "--user-source", "inferred: x", "--target", "prod-db", "--wal",
                                        str(self.wal)], capture_output=True, text=True, timeout=60)
        self.assertEqual(refused.returncode, 2)
        self.assertEqual(json.loads(refused.stderr)["status"], "REFUSED")


class Install(unittest.TestCase):
    def test_installer_registers_guard_fail_open_with_matcher(self):
        sys.path.insert(0, str(ROOT))
        import install
        claude = Path("/h/.claude")
        groups = [g for g in install.managed_hooks(claude)["PreToolUse"]
                  if any(str(claude / "hooks" / "prod_delete_guard.py") in (h.get("args") or []) for h in g["hooks"])]
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["matcher"], pdg.MATCHER)
        self.assertNotIn("onFailure", groups[0]["hooks"][0])
        self.assertIn("prod_delete_guard.py", install.HOOKS)
        self.assertIn(str(claude / "hooks" / "prod_delete_guard.py"), install.managed_scripts(claude))


if __name__ == "__main__":
    unittest.main()
