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
    TARGET = "prod-db.example.com"

    def real_grant(self, target=None, ttl=600, **kw):
        source = self.human_turn()
        return pdg.grant(source, target or self.TARGET, str(self.wal), ttl=ttl, home=str(self.home), **kw)

    def stored(self):
        return json.loads(pdg.grants_path(str(self.home)).read_text())["grants"]

    def store(self, grants):
        pdg.grants_path(str(self.home)).parent.mkdir(parents=True, exist_ok=True)
        pdg.grants_path(str(self.home)).write_text(json.dumps({"grants": grants}))

    def test_signed_grant_for_exact_target_allows(self):
        self.real_grant()
        self.assertAllowed(self.CMD)
        self.assertAllowed(self.CMD)  # reusable until it expires (stated design)

    def test_target_is_an_exact_token_never_a_substring(self):
        # native review F2: each of these grants used to widen into every prod delete
        cases = (("prod-db-1", "psql -h prod-db-10 -c 'DELETE FROM users'"),
                 ("staging-x", "psql -h prod-main -c 'DELETE FROM users' # staging-x"),
                 ("prod-db.example", "psql -h prod-db.example.com -c 'DELETE FROM users'"))
        for target, command in cases:
            with self.subTest(target=target):
                self.real_grant(target)
                self.assertDenied(command)

    def test_keyword_and_client_targets_refused(self):
        for target in ("DELETE", "psql", "TRUNCATE", "drop", "mysql", "a b", "pr", "prod*", " x-db"):
            with self.subTest(target=target):
                with self.assertRaises(ValueError):
                    self.real_grant(target)

    def test_every_prod_target_needs_its_own_grant(self):
        self.real_grant("prod-a")
        cmd = "psql -h prod-a -c 'DELETE FROM t'; mysql -h prod-b -e 'DROP DATABASE x'"
        self.assertDenied(cmd)
        self.real_grant("prod-b")
        self.assertAllowed(cmd)

    def test_connection_string_grant_names_host_or_database(self):
        cmd = "psql 'postgresql://u:p@prod-db.example.com:5432/main' -c 'DROP TABLE users'"
        self.assertDenied(cmd)
        self.real_grant("prod-db.example.com")
        self.assertAllowed(cmd)

    def test_hand_written_unsigned_grant_denies(self):
        # native review F1: a JSON entry with a far expiry and an old real source used to allow
        source = self.human_turn(when="2020-01-01T00:00:00Z")
        self.store([{"scope": "prod-db", "target": self.TARGET, "user_source": source, "granted_at": 1,
                     "expires_at": 4102444800, "source_ts": 1577836800}])
        self.assertDenied(self.CMD)

    def test_tampered_or_overlong_signed_grant_denies(self):
        self.real_grant()
        good = self.stored()[0]
        for field, value in (("expires_at", good["granted_at"] + pdg.MAX_TTL + 600), ("target", "prod-other"),
                             ("source_ts", good["source_ts"] - 2 * 86400)):
            with self.subTest(field=field):
                bad = dict(good, **{field: value})
                self.store([bad])
                self.assertDenied(self.CMD if field != "target" else "psql -h prod-other -c 'TRUNCATE x'")
                # re-signed with the real key, the bounds still deny an overlong or stale grant
                key = pdg._read_key(str(self.home))
                bad["mac"] = pdg._mac(key, bad)
                self.store([bad])
                if field != "target":
                    self.assertDenied(self.CMD)

    def test_signed_grant_of_another_scope_denies(self):
        self.real_grant()
        bad = dict(self.stored()[0], scope="log-delete")
        bad["mac"] = pdg._mac(pdg._read_key(str(self.home)), bad)
        self.store([bad])
        self.assertDenied(self.CMD)

    def test_expired_grant_denies_and_says_so(self):
        self.real_grant(ttl=1)
        result = pdg.evaluate(bash(self.CMD), home=str(self.home), now=time.time() + 5)
        self.assertEqual(result[0], "deny")
        self.assertIn("expired", result[1])

    def test_grant_whose_source_no_longer_resolves_denies(self):
        self.real_grant()
        (self.home / ".claude/projects/p" / (SID + ".jsonl")).write_text("")
        self.assertDenied(self.CMD)

    def test_source_lookup_ignores_claude_config_dir(self):
        fake = self.home / "fake-claude"
        (fake / "projects/x").mkdir(parents=True)
        uid = str(uuid.uuid4())
        (fake / "projects/x" / (SID + ".jsonl")).write_text(json.dumps({
            "type": "user", "uuid": uid, "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "origin": {"kind": "human"}, "message": {"content": "yes"}}) + "\n")
        os.environ["CLAUDE_CONFIG_DIR"] = str(fake)
        with self.assertRaises(ValueError):
            pdg.grant("user:%s/%s" % (SID, uid), self.TARGET, str(self.wal), home=str(self.home))

    def test_corrupt_unreadable_or_unkeyed_store_denies(self):
        # native review F4: these used to give "ask"
        path = pdg.grants_path(str(self.home))
        path.parent.mkdir(parents=True, exist_ok=True)
        for content in ("{not json", '{"grants": 3}', '{"grants": [1]}'):
            with self.subTest(content=content):
                path.write_text(content)
                self.assertEqual(self.verdict(bash(self.CMD)), "deny")
        path.unlink()
        self.real_grant()
        pdg.key_path(str(self.home)).unlink()
        self.assertDenied(self.CMD)
        path.unlink()
        path.mkdir()
        self.assertDenied(self.CMD)
        self.assertAllowed("ls")  # a broken store never touches non-matching commands

    def test_error_after_match_denies(self):
        saved = pdg.matching_grants
        pdg.matching_grants = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
        try:
            self.assertDenied(self.CMD)
        finally:
            pdg.matching_grants = saved

    def test_real_grant_round_trip_through_provenance_and_wal(self):
        entry = self.real_grant()
        self.assertEqual(entry["scope"], "prod-db")
        for path in (pdg.grants_path(str(self.home)), pdg.key_path(str(self.home))):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        wal = [json.loads(line) for line in self.wal.read_text().splitlines()]
        self.assertTrue(any("prod_delete_guard grant" in r.get("note", "") for r in wal))

    def test_grant_refusals_write_nothing(self):
        source = self.human_turn()
        old = self.human_turn(when="2026-01-01T00:00:00Z")
        cases = (dict(user_source="inferred: from me -- x"), dict(user_source="ticket:GoodQA goodqa#1"),
                 dict(user_source="user:%s/%s" % (SID, uuid.uuid4())), dict(user_source=old),
                 dict(target="pr"), dict(target=" prod-db "), dict(ttl=0), dict(ttl=pdg.MAX_TTL + 1), dict(wal=""))
        for over in cases:
            kw = dict(user_source=source, target=self.TARGET, wal=str(self.wal), ttl=600, home=str(self.home))
            kw.update(over)
            with self.subTest(over=over):
                with self.assertRaises(ValueError):
                    pdg.grant(**kw)
                self.assertFalse(pdg.grants_path(str(self.home)).exists())

    def test_failed_wal_record_writes_no_grant(self):
        with self.assertRaises(ValueError):
            self.real_grant(record=lambda *a: False)
        self.assertFalse(pdg.grants_path(str(self.home)).exists())

    def test_expired_and_unsigned_grants_are_pruned_on_write(self):
        self.store([{"scope": "prod-db", "target": "prod-old", "expires_at": 1}])
        self.real_grant()
        self.assertEqual([g["target"] for g in self.stored()], [self.TARGET])


class Bypasses(Case):
    """native review F3: each of these used to be allowed with no grant."""

    def sql_file(self, name="drop.sql", text="DROP TABLE users;\n"):
        path = self.home / name
        path.write_text(text)
        return path

    def test_file_and_redirect_inputs(self):
        self.sql_file()
        for command in ("psql -h prod-db -f %s" % (self.home / "drop.sql"), "psql -h prod-db < %s" % (self.home / "drop.sql"),
                        "psql -h prod-db -f drop.sql"):
            with self.subTest(command=command):
                self.assertEqual(self.verdict(dict(bash(command), cwd=str(self.home))), "deny")
        self.assertAllowed("psql -h prod-db -f %s" % self.sql_file("ok.sql", "SELECT 1;\n"))

    def test_unreadable_sql_file_on_a_prod_target_denies(self):
        # a file the guard cannot read (missing at hook time, e.g. written earlier in the same command,
        # or unreadable) cannot be judged, so a prod-targeted run of it fails closed
        made = "printf 'DROP TABLE users;' > /tmp/pdg-x.sql && psql -h prod-db -f /tmp/pdg-nonexistent-x.sql"
        for command in (made, "wrangler d1 execute appdb --remote --file=~/pdg-nonexistent.sql",
                        "psql -h prod-db < %s" % (self.home / "missing.sql")):
            with self.subTest(command=command):
                self.assertEqual(self.verdict(dict(bash(command), cwd=str(self.home))), "deny")
        self.assertAllowed("psql -h localhost -f %s" % (self.home / "missing.sql"))  # not production

    def test_wrangler_relative_file_resolves_against_event_cwd(self):
        self.sql_file()
        ev = dict(bash("wrangler d1 execute appdb --remote --file=drop.sql"), cwd=str(self.home))
        self.assertEqual(self.verdict(ev), "deny")

    def test_attached_flags_env_and_positional_targets(self):
        for command in ("psql -hprod-db -c 'DELETE FROM users'", "mysql -hprod.internal -e 'DROP DATABASE app'",
                        "PGHOST=prod-db psql -c 'DELETE FROM users'",
                        "DATABASE_URL=postgres://u@prod-db/app psql \"$DATABASE_URL\" -c 'DELETE FROM t'",
                        "psql -U app prod -c 'DELETE FROM users'", "psql -U app app_production -c 'TRUNCATE t'"):
            with self.subTest(command=command):
                self.assertDenied(command)

    def test_hook_environment_variables(self):
        self.assertDenied("psql \"$DATABASE_URL\" -c 'DELETE FROM t'", env={"DATABASE_URL": "postgres://u@prod-db/app"})
        self.assertDenied("psql -c 'DELETE FROM t'", env={"PGHOST": "prod-db"})
        self.assertAllowed("psql -h localhost -c 'DELETE FROM t'", env={"PGHOST": "prod-db"})
        self.assertAllowed("psql -c 'DELETE FROM t'", env={"PGHOST": "localhost"})

    def test_ssh_and_docker_exec(self):
        self.assertDenied("ssh prod-db.internal \"psql -c 'DELETE FROM users'\"")
        self.assertDenied("ssh -i k -p 22 deploy@prod-db \"psql -c 'TRUNCATE t'\"")
        self.assertDenied("docker exec -it prod-postgres psql -U app -c 'DELETE FROM users'")
        self.assertAllowed("ssh prod-web.internal 'ls /var/log'")
        self.assertAllowed("docker exec dev-postgres psql -c 'DELETE FROM users'")

    def test_disguised_and_extra_statements(self):
        for command in ("psql -h prod-db -c \"DEL\"\"ETE FROM users\"", "psql -h prod-db -c 'DELETE/**/FROM users'",
                        "psql -h prod-db -c 'DROP SCHEMA public CASCADE'", "psql -h prod-db -c 'UPDATE users SET email=null'"):
            with self.subTest(command=command):
                self.assertDenied(command)
        self.assertAllowed("psql -h prod-db -c 'UPDATE users SET email=null WHERE id=4'")

    def test_d1_tool_grant_names_database_id(self):
        ev = {"tool_name": "mcp__cloudflare__d1_database_query",
              "tool_input": {"database_id": "panel-prod-d1", "sql": "DELETE FROM devices"}}
        self.assertEqual(self.verdict(ev), "deny")
        pdg.grant(self.human_turn(), "panel-prod-d1", str(self.wal), home=str(self.home))
        self.assertEqual(self.verdict(ev), "allow")
        ev["tool_input"] = {"sql": "DELETE FROM devices"}  # no database named: nothing a grant can cover
        self.assertEqual(self.verdict(ev), "deny")


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
