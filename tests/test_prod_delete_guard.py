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

SID = "0f4c2b6e-8d1a-4e5b-9c3d-7a2e1f6b5c4d"  # Claude Code session ids are UUIDs (provenance answer: form)


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
        """An AskUserQuestion answer whose selected option is `text` (grants come only from answers)."""
        return self.answer("Which action should I take?", text, when=when)

    def typed_turn(self, text, when=None):
        uid = str(uuid.uuid4())
        stamp = when or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        path = self.home / ".claude/projects/p" / (SID + ".jsonl")
        path.parent.mkdir(parents=True, exist_ok=True)
        record = {"type": "user", "uuid": uid, "timestamp": stamp, "sessionId": SID, "origin": {"kind": "human"},
                  "message": {"role": "user", "content": text}}
        with open(path, "a") as fh:
            fh.write(json.dumps(record) + "\n")
        return "user:%s/%s" % (SID, uid)

    def answer(self, question, choice, options=None, when=None):
        use, uid = "toolu_%s" % uuid.uuid4().hex[:16], str(uuid.uuid4())
        stamp = when or time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
        opts = [{"label": o, "description": o} for o in (options or [choice, "No"])]
        ask = {"type": "assistant", "uuid": str(uuid.uuid4()), "timestamp": stamp, "sessionId": SID,
               "message": {"role": "assistant", "content": [{"type": "tool_use", "id": use, "name": "AskUserQuestion",
                                                             "input": {"questions": [{"question": question,
                                                                                      "options": opts}]}}]}}
        reply = {"type": "user", "uuid": uid, "timestamp": stamp, "sessionId": SID,
                 "message": {"role": "user", "content": [{"type": "tool_result", "tool_use_id": use, "content": "ok"}]},
                 "toolUseResult": {"answers": {question: choice}}}
        path = self.home / ".claude/projects/p" / (SID + ".jsonl")
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a") as fh:
            fh.write(json.dumps(ask) + "\n" + json.dumps(reply) + "\n")
        return "answer:%s/%s" % (SID, uid)

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
        source = self.human_turn("Yes, run the delete on %s" % (target or self.TARGET))
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
        # the answer lives only under CLAUDE_CONFIG_DIR: a lookup that honoured it would grant (mutant M23)
        question, label = "Delete on %s?" % self.TARGET, "Yes, run the delete on %s" % self.TARGET
        source = self.answer(question, label)
        in_home = self.home / ".claude/projects/p" / (SID + ".jsonl")
        fake = self.home / "fake-claude"
        (fake / "projects/x").mkdir(parents=True)
        moved = fake / "projects/x" / (SID + ".jsonl")
        moved.write_text(in_home.read_text())
        in_home.write_text("")
        os.environ["CLAUDE_CONFIG_DIR"] = str(fake)
        with self.assertRaises(ValueError):
            pdg.grant(source, self.TARGET, str(self.wal), home=str(self.home))
        # control: the same answer under <home>/.claude grants, so the refusal above is about the location
        in_home.write_text(moved.read_text())
        pdg.grant(source, self.TARGET, str(self.wal), home=str(self.home))

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
        source = self.human_turn("delete on %s" % self.TARGET)
        old = self.human_turn("delete on %s" % self.TARGET, when="2026-01-01T00:00:00Z")
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
        pdg.grant(self.human_turn("ok, delete on panel-prod-d1"), "panel-prod-d1", str(self.wal), home=str(self.home))
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
        source = self.human_turn("Yes, truncate on prod-db.example.com")
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


class Round3(Case):
    """Native re-review of 71d7e78 (hk-wave1-r2-71d7e78.md): R1-R6."""
    TARGET = "prod-db"

    def sql(self, name, text):
        (self.home / name).write_text(text)
        return self.home / name

    def ev(self, command):
        return dict(bash(command), cwd=str(self.home))

    def test_r1_huge_destructive_command_decides_fast(self):
        body = "DELETE FROM a; " * 200000  # about 3 MB in one quoted token
        for command, want in (("psql -h prod-db -c '%s'" % body, "deny"), ("psql -h localhost -c '%s'" % body, "allow")):
            with self.subTest(want=want):
                start = time.monotonic()
                self.assertEqual(self.verdict(bash(command)), want)
                self.assertLess(time.monotonic() - start, 5.0)  # measured 1.3 s on the Mac; hook timeout is 30 s

    def test_r2_fifo_sql_file_denies_without_hanging(self):
        import threading
        fifo = self.home / "q.sql"
        os.mkfifo(fifo)
        got = []
        worker = threading.Thread(target=lambda: got.append(self.verdict(self.ev("psql -h prod-db -f %s" % fifo))),
                                  daemon=True)
        worker.start()
        worker.join(3)
        try:
            self.assertFalse(worker.is_alive(), "the hook blocked on a FIFO")
            self.assertEqual(got, ["deny"])
        finally:
            if worker.is_alive():  # release the blocked reader so the thread can end
                os.close(os.open(fifo, os.O_WRONLY | os.O_NONBLOCK))

    def test_r3_other_ways_of_feeding_a_file(self):
        self.sql("evil.sql", "DROP TABLE users;\n")
        self.sql("q.sql", "SELECT 1;\n")
        for command in ("cat evil.sql | psql -h prod-db", "psql -h prod-db -c '\\i evil.sql'",
                        "psql -h prod-db -c '\\ir evil.sql'", 'psql -h prod-db <<< "$(cat evil.sql)"',
                        'psql -h prod-db <<< "$(< evil.sql)"', "mysql -h prod-db -e 'source evil.sql'",
                        "sqlite3 /srv/prod.db '.read evil.sql'",
                        "cp evil.sql q.sql && psql -h prod-db -f q.sql",
                        "base64 -d enc.b64 > q.sql; psql -h prod-db -f q.sql",
                        "sed -i 's/SELECT 1/SELECT 2/' q.sql && psql -h prod-db < q.sql"):
            with self.subTest(command=command):
                self.assertEqual(self.verdict(self.ev(command)), "deny")
        for command in ("cat q.sql | psql -h prod-db", "psql -h prod-db -f q.sql", "cat evil.sql | psql -h localhost"):
            with self.subTest(command=command):
                self.assertEqual(self.verdict(self.ev(command)), "allow")

    def test_r4_a_turn_that_does_not_name_the_target_funds_no_grant(self):
        for text in ("thanks, looks good", "hi", "yes, delete on prod-db-10", "drop prod-dbx"):
            with self.subTest(text=text):
                with self.assertRaises(ValueError) as caught:
                    pdg.grant(self.human_turn(text), "prod-db", str(self.wal), home=str(self.home))
                self.assertIn("does not name", str(caught.exception))
        self.assertFalse(pdg.grants_path(str(self.home)).exists())
        pdg.grant(self.human_turn("Yes, DELETE the rows on PROD-DB."), "prod-db", str(self.wal), home=str(self.home))
        self.assertAllowed("psql -h prod-db -c 'DELETE FROM t'")

    def test_r4_source_older_than_an_hour_refused(self):
        stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 2 * 3600))
        with self.assertRaises(ValueError):
            pdg.grant(self.human_turn("delete on prod-db", when=stamp), "prod-db", str(self.wal), home=str(self.home))

    def test_r4_answer_selecting_an_option_naming_the_target_funds_a_grant(self):
        good = self.answer("Run DELETE FROM sessions?", "Approve DELETE on prod-db (Recommended)")
        pdg.grant(good, "prod-db", str(self.wal), home=str(self.home))
        self.assertAllowed("psql -h prod-db -c 'DELETE FROM sessions'")
        other = self.answer("Ship the release notes?", "Yes")
        with self.assertRaises(ValueError):
            pdg.grant(other, "prod-other", str(self.wal), home=str(self.home))

    def test_r5_d1_target_skips_flags_and_flag_targets_refused(self):
        desc, groups = pdg.targets_production("wrangler d1 execute --remote mydb --command 'DELETE FROM t'")
        self.assertEqual(groups, [("mydb",)])
        with self.assertRaises(ValueError):
            pdg.grant(self.human_turn("delete on --remote"), "--remote", str(self.wal), home=str(self.home))

    def test_r6_key_must_be_a_private_regular_file(self):
        pdg.grant(self.human_turn("delete on prod-db"), "prod-db", str(self.wal), home=str(self.home))
        key = pdg.key_path(str(self.home))
        self.assertAllowed("psql -h prod-db -c 'DELETE FROM t'")
        os.chmod(key, 0o644)
        self.assertDenied("psql -h prod-db -c 'DELETE FROM t'")
        os.chmod(key, 0o600)
        os.link(key, self.home / "key-copy")
        self.assertDenied("psql -h prod-db -c 'DELETE FROM t'")
        os.unlink(self.home / "key-copy")
        planted = self.home / "public.key"
        planted.write_bytes(key.read_bytes())
        os.chmod(planted, 0o600)
        key.unlink()
        os.symlink(planted, key)
        self.assertDenied("psql -h prod-db -c 'DELETE FROM t'")


class Round4(Case):
    """Native delta re-review of ca56501 (hk-wave1-r3-ca56501.md): B1-B7 and N1."""

    def test_b4_database_past_the_option_scan_bound_fails_closed(self):
        # past AFTER_SCAN option words the guard cannot tell which database psql uses: a delete denies (M49)
        many = "psql " + "-v a=b " * 200 + "devdb -c 'DELETE FROM users'"
        self.assertDenied(many)
        self.assertIn("too long to judge its database", pdg.evaluate(bash(many), home=str(self.home))[1])
        self.assertAllowed("psql " + "-v a=b " * 5 + "devdb -c 'DELETE FROM users'")  # control: within the bound

    def test_source_compiles_without_warnings(self):
        # dev2 (Python 3.12) printed "SyntaxWarning: invalid escape sequence" on every hook run
        import warnings
        source = (HOOKS / "prod_delete_guard.py").read_text()
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            compile(source, "prod_delete_guard.py", "exec")

    def sql(self, name, text):
        (self.home / name).write_text(text)
        return self.home / name

    def ev(self, command):
        return dict(bash(command), cwd=str(self.home))

    def refused(self, source, target="prod-db"):
        with self.assertRaises(ValueError):
            pdg.grant(source, target, str(self.wal), home=str(self.home))

    def test_b1_only_the_selected_answer_counts(self):
        self.refused(self.answer("Delete the users table rows on prod-db?", "No"))
        self.refused(self.answer("Which database should I clean up?", "staging-db", options=["staging-db", "prod-db"]))
        self.refused(self.answer("Run the migration on staging-db first, before anything touches prod-db?", "Yes"))
        self.refused(self.answer("Delete rows?", "No, keep prod-db as it is", options=["Delete on prod-db",
                                                                                   "No, keep prod-db as it is"]))
        self.refused(self.typed_turn("do NOT touch prod-db under any circumstances"))
        self.refused(self.typed_turn("yes, delete on prod-db"))  # typed turns cannot be told from negations
        self.assertFalse(pdg.grants_path(str(self.home)).exists())
        self.assertDenied("psql -h prod-db -c 'DELETE FROM users'")
        pdg.grant(self.answer("Delete the stale rows?", "Approve DELETE on prod-db"), "prod-db", str(self.wal),
                  home=str(self.home))
        self.assertAllowed("psql -h prod-db -c 'DELETE FROM users'")

    def test_b6_target_must_stand_alone_and_db_only_grants_do_not_cover_prod_hosts(self):
        self.refused(self.human_turn("Approve: prod-db.example.com:5432 failed"))
        self.refused(self.human_turn("Approve restore of /srv/backups/prod-db/latest.sql"))
        pdg.grant(self.human_turn("Approve DELETE on app"), "app", str(self.wal), home=str(self.home))
        self.assertDenied("psql 'postgresql://u@prod-billing/app' -c 'DROP TABLE users'")
        self.assertDenied("psql 'postgres://u@prod-auth.example.com/app' -c 'DROP DATABASE app'")

    def test_b2_oversized_command_keeps_a_positional_prod_database(self):
        filler = "SELECT 1; " * 7000  # about 70 KB inside the quoted -c
        self.assertDenied("psql -c '%s DELETE FROM users' app_production" % filler)
        self.assertAllowed("psql -c '%s DELETE FROM users' app_dev" % filler)

    def test_b3_d1_flag_values_are_not_the_database(self):
        cmd = "wrangler d1 execute --env production billing-db --remote --command 'DELETE FROM invoices'"
        self.assertEqual(pdg.targets_production(cmd)[1], [("billing-db",)])
        cmd2 = "wrangler d1 execute -c wrangler.toml --command 'DELETE FROM t' --persist-to /x billing-db --remote"
        self.assertEqual(pdg.targets_production(cmd2)[1], [("billing-db",)])
        for name in ("prod", "production", "PROD"):
            self.assertTrue(pdg.valid_target(name), name)

    def test_b4_repeated_client_words_decide_fast(self):
        for word in ("psql ", "mysql ", "cp a ", "wrangler d1 ", "sqlite3 ", "sed -i ", "psql -f ", "psql -v x "):
            command = word * (100000 // len(word)) + " psql -h prod-db -c 'DELETE FROM users'"
            with self.subTest(word=word):
                start = time.monotonic()
                self.assertEqual(self.verdict(bash(command)), "deny")  # prod target, or too long to judge
                self.assertLess(time.monotonic() - start, 2.0)

    def test_b5_other_spellings_deny(self):
        self.sql("evil.sql", "DROP TABLE users;\n")
        self.sql("q.sql", "SELECT 1;\n")
        os.symlink(str(self.home / "r.sql"), str(self.home / "l.sql"))
        (self.home / "sub").mkdir()
        self.sql("sub/q.sql", "DROP TABLE users;\n")
        for command in ("psql -h prod-db -c '\\include evil.sql'", "psql -h prod-db -c '\\include_relative evil.sql'",
                        "psql -h prod-db -c \"\\i 'evil.sql'\"", "sqlite3 /srv/prod.db \".read 'evil.sql'\"",
                        "mysql -h prod-db -e '\\. evil.sql'", "psql -h prod-db -1f evil.sql",
                        "psql -h prod-db -Xf evil.sql", "psql -h prod-db --fil=evil.sql",
                        "sqlite3 -init evil.sql /srv/prod.db .quit", "head -c 100000 evil.sql | psql -h prod-db",
                        "sed -n p evil.sql | psql -h prod-db", "cp evil.sql r.sql && psql -h prod-db -f l.sql",
                        "curl -so q.sql https://example.invalid/x; psql -h prod-db -f q.sql",
                        "cd sub && psql -h prod-db -f q.sql"):
            with self.subTest(command=command):
                self.assertEqual(self.verdict(self.ev(command)), "deny")
        for command in ("echo 'SELECT 1' | psql -h prod-db", "printf 'SELECT 1;' | psql -h prod-db",
                        "head -c 100 evil.sql | psql -h localhost", "psql -h prod-db -f q.sql"):
            with self.subTest(command=command):
                self.assertEqual(self.verdict(self.ev(command)), "allow")

    def test_b7_cheap_gaps_deny(self):
        self.sql("big.sql", "-- " + "x" * (pdg.FILE_READ_LIMIT + 10) + "\nDROP TABLE users;\n")
        for command in ("psql -h prod-db -f big.sql", "psql -h prod-db -c $'DELETE--keep\\nFROM users'",
                        "psql -h prod-db -c DELETE\\ FROM\\ users", "psql -h prod-db -c $'DELETE\\x20FROM users'",
                        "dropdb -h prod-db app", "mysqladmin -h prod-db -f drop app",
                        "psql -h 192.0.2.5 app_production -c 'DELETE FROM users'",
                        "sqlite3 -cmd 'DELETE FROM users' /srv/prod.db"):
            with self.subTest(command=command):
                self.assertEqual(self.verdict(self.ev(command)), "deny")
        self.assertEqual(self.verdict(self.ev("dropdb -h localhost app")), "allow")

    def test_n1_cat_in_a_prod_command_is_judged_as_input(self):
        # r5: every cat argument in a command with a client is SQL input again (H1), so these read-only rows are
        # denied as in ca56501, naming the file (a disclosed over-refusal: split the command)
        for command, name in (("psql -h prod-db -c 'SELECT count(*) FROM users' > out.txt && cat out.txt", "out.txt"),
                              ("cat /dev/null > x.log; psql -h prod-db -c 'SELECT 1'", "/dev/null"),
                              ("PGPASSWORD=$(cat ~/.nope) psql -h prod-db -c 'SELECT 1'", "~/.nope")):
            with self.subTest(command=command):
                result = pdg.evaluate(self.ev(command), home=str(self.home))
                self.assertEqual(result[0], "deny")
                self.assertIn(name, result[1])
        for command in ("psql -h prod-db -c 'SELECT count(*) FROM users' > out.txt",
                        "psql -h prod-db -c 'SELECT 1' | cat"):
            with self.subTest(command=command):
                self.assertEqual(self.verdict(self.ev(command)), "allow")


class Round5(Case):
    """Native delta re-review of 33f1695 (hk-wave1-r4-33f1695.md): H1-H4 and L1 A8, through the real hook."""

    def setUp(self):
        super().setUp()
        self.cwd = self.home / "cwd"
        self.cwd.mkdir()
        for name, body in {"evil.sql": "DROP TABLE users;\n", "ok.sql": "SELECT 1;\n", "q.sql": "SELECT 1;\n",
                           "migration.sql": "DELETE FROM sessions;\n"}.items():
            (self.cwd / name).write_text(body)

    def hook(self, command):
        payload = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": command},
                   "cwd": str(self.cwd)}
        env = dict(os.environ, HOME=str(self.home))
        env.pop("CLAUDE_CONFIG_DIR", None)
        r = subprocess.run([sys.executable, "-I", str(HOOKS / "prod_delete_guard.py")], input=json.dumps(payload),
                           capture_output=True, text=True, env=env, timeout=60, check=False)
        self.assertEqual((r.returncode, r.stderr), (0, ""), command)
        return json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"] if r.stdout.strip() else "allow"

    def check(self, rows, want):
        for command in rows:
            with self.subTest(command=command):
                self.assertEqual(self.hook(command), want, command)

    def test_h1_cat_into_a_wrapped_or_remote_client_denies(self):
        self.check(("cat evil.sql | ssh prod-db-1 psql app", "cat evil.sql | ssh prod-db-1 'psql app'",
                    "cat evil.sql | docker exec -i prod-pg psql -U postgres app",
                    "cat evil.sql | sudo -u postgres psql -h prod-db", "cat evil.sql | env PGPASSWORD=x psql -h prod-db",
                    "cat evil.sql | timeout 60 psql -h prod-db", "cat migration.sql | ssh prod-db-1 psql app; true"),
                   "deny")

    def test_h1_cat_substitution_anywhere_denies(self):
        self.check(('psql -h prod-db -c "$(cat ok.sql evil.sql)"', 'psql -h prod-db --command="$(cat evil.sql)"',
                    'psql -h prod-db -c "SELECT 1; $(cat evil.sql)"', 'mysql -h prod-db --execute="$(cat evil.sql)"',
                    'psql -h prod-db -c "$(cat evil.sql)"', "psql -h prod-db -c `cat evil.sql`"), "deny")

    def test_h2_flags_that_do_not_replace_stdin_still_deny(self):
        self.check(("head -c 999 evil.sql | psql -h prod-db -e", "head -c 999 evil.sql | mysql -h prod-db -f",
                    "head -c 999 evil.sql | mysql -h prod-db -c",
                    "head -c 999 evil.sql | sqlite3 -cmd '.mode list' /srv/prod.db",
                    "head -c 999 evil.sql | sqlite3 -init ok.sql /srv/prod.db",
                    "sed -n p evil.sql | psql -h prod-db --echo-errors -e",
                    "head -c 999 evil.sql | sudo -u postgres psql -h prod-db",
                    'psql -h prod-db -c "$(head -c 999 evil.sql)"'), "deny")

    def test_h3_same_step_writers_deny(self):
        self.check(("dd if=evil.sql of=q.sql 2>/dev/null | xargs psql -h prod-db -f q.sql",
                    "psql -h prod-db -f q.sql -v x=$(dd if=evil.sql of=q.sql 2>/dev/null)",
                    "psql -h prod-db -f q.sql -v x=`dd if=evil.sql of=q.sql`",
                    "curl -so q.sql http://127.0.0.1:9/x | xargs psql -h prod-db -f q.sql",
                    "psql -h prod-db -f q.sql <(dd if=evil.sql of=q.sql)",
                    "PGOPTIONS=$(dd if=evil.sql of=q.sql) psql -h prod-db -f q.sql"), "deny")

    def test_read_only_and_non_prod_controls_allow(self):
        self.check(("cat ok.sql | ssh prod-db-1 psql app", "head ok.sql | psql -h localhost",
                    "cd /srv && psql -h localhost -f ok.sql", "psql -h prod-db -c 'SELECT 1' 2>&1 | tee log.txt",
                    "psql -h prod-db -f ok.sql 2>&1", "psql -h prod-db -f ok.sql &> log.txt",
                    "head -c 999 ok.sql | psql -h prod-db -c 'SELECT 2'", "head -c 99 ok.sql | psql -h prod-db -f q.sql",
                    "head -c 99 evil.sql | mysql -h prod-db -e 'SELECT 1'", "psql -h prod-db -c \"$(cat ok.sql)\"",
                    "PGPASSWORD=$(cat ok.sql) psql -h localhost -c 'SELECT 1'",
                    "git commit -m 'note: psql DELETE FROM users on prod' "), "allow")

    def test_h5_attached_option_values_do_not_replace_stdin(self):
        (self.cwd / "dump.sql.gz").write_bytes(b"\x1f\x8b")
        self.check(("zcat dump.sql.gz | mysql -h prod-db -uroot -pchangeme app",
                    "gunzip -c dump.sql.gz | mysql -h prod-db -Dstore", "head -c 999 evil.sql | mysql -h prod-db -pe app",
                    "head -c 999 evil.sql | mysql -h prod-db --init-command='SET x=1' -De",
                    "head -c 999 evil.sql | psql -h prod-db -Usvc app", "head -c 999 evil.sql | psql -h prod-db -v x=-f",
                    "head -c 999 evil.sql | psql -h prod-db -v 'x= -c'", "head -c 999 evil.sql | psql -h prod-db -v '<x'",
                    "head -c 999 evil.sql | psql -h prod-db -v 'x=< ok.sql '",
                    "head -c 999 evil.sql | mariadb -h prod-db -pse app"), "deny")
        self.check(("head -c 99 evil.sql | mysql -h prod-db -Be 'SELECT 1'",
                    "head -c 99 evil.sql | mysql -h prod-db --execute='SELECT 1'",
                    "head -c 99 evil.sql | psql -h prod-db -Xc 'SELECT 1'",
                    "head -c 99 evil.sql | psql -h prod-db --command='SELECT 1'",
                    "head -c 99 evil.sql | psql -h prod-db -U svc -c 'SELECT 1'",
                    "head -c 99 evil.sql | psql -h prod-db app < ok.sql"), "allow")

    def test_h4_declining_or_second_target_answers_fund_nothing(self):
        for text in ("Don’t delete prod-db", "Nope, prod-db stays", "Abort: prod-db must be preserved",
                     "Reject DELETE on prod-db", "Delete on staging-db; prod-db untouched", "Nah, prod-db",
                     "Approve DELETE on staging-db (prod-db only after the backup)", "Deny prod-db"):
            with self.subTest(text=text):
                self.assertFalse(pdg.names_target({"text": text}, "prod-db"), text)
        self.assertTrue(pdg.names_target({"text": "Approve DELETE on prod-db"}, "prod-db"))
        self.assertTrue(pdg.names_target({"text": "Approve DELETE on hold-db"}, "hold-db"))  # was an over-refusal


class GrantWalCitation(Case):
    """wal_note.py (goodqa#14927) refuses an answer: source with no verbatim excerpt; the grant cites one."""

    def test_grant_records_a_resolvable_cited_answer_in_the_wal(self):
        source = self.human_turn('Yes, run the delete on prod-db.example.com "now"')
        pdg.grant(source, "prod-db.example.com", str(self.wal), home=str(self.home))
        rows = [json.loads(line) for line in self.wal.read_text().splitlines() if line.strip()]
        row = [r for r in rows if "prod_delete_guard grant" in str(r.get("note"))][-1]
        self.assertEqual(row["source"], '%s "Yes, run the delete on prod-db.example.com"' % source)
        self.assertFalse(row.get("assumption") or row.get("quarantined"), row)

    def test_answer_too_short_to_cite_is_refused_with_a_reason(self):
        source = self.human_turn("db-x1")
        with self.assertRaisesRegex(ValueError, "too short to cite"):
            pdg.grant(source, "db-x1", str(self.wal), home=str(self.home))
        self.assertFalse(pdg.grants_path(str(self.home)).exists() and pdg.load_grants(str(self.home)))

    def test_wal_refusal_reason_reaches_the_caller(self):
        source = self.human_turn("Approve DELETE on prod-db")
        with self.assertRaisesRegex(ValueError, r"no grant was written \(nope\)"):
            pdg.grant(source, "prod-db", str(self.wal), home=str(self.home), record=lambda *a: "nope")



class RevisedSql(Case):
    """goodqa#15036 (Kimi revised R02-R04): top-level WHERE, bounded include closure, Hyperdrive, executable comments."""

    def ev(self, command):
        return dict(bash(command), cwd=str(self.home))

    def test_update_requires_a_top_level_where(self):
        hostile = (
            "UPDATE users SET note='WHERE'",
            "UPDATE users SET flag=(SELECT true WHERE true)",
            "UPDATE ONLY users SET admin=true",
            "UPDATE users AS u SET admin=true",
            "UPDATE users u SET note='x' -- WHERE id=1",
            "UPDATE users SET note='unterminated",
            "UPDATE t1, t2 SET t1.a=1",
        )
        for statement in hostile:
            with self.subTest(statement=statement):
                self.assertTrue(pdg.destructive_match(statement))
                command = 'psql -h prod-db -c "%s"' % statement.replace('"', '\\"')
                self.assertEqual(self.verdict(self.ev(command)), "deny")
        legitimate = (
            "UPDATE users SET note='WHERE' WHERE id=4",
            "UPDATE ONLY users SET admin=true WHERE id=4",
            "UPDATE users AS u SET admin=true WHERE u.id=4",
            "UPDATE users SET flag=(SELECT true WHERE true) WHERE id=4",
            "SELECT * FROM users WHERE id=4 FOR UPDATE",
        )
        for statement in legitimate:
            with self.subTest(statement=statement):
                self.assertFalse(pdg.destructive_match(statement))
                self.assertAllowed('psql -h prod-db -c "%s"' % statement)

    def test_nested_include_relative_to_including_file(self):
        (self.home / "scripts/nested").mkdir(parents=True)
        (self.home / "scripts/root.sql").write_text("\\ir nested/one.sql\n")
        (self.home / "scripts/nested/one.sql").write_text("\\ir two.sql\n")
        (self.home / "scripts/nested/two.sql").write_text("DELETE FROM users;\n")
        self.assertEqual(self.verdict(self.ev("psql -h prod-db -f scripts/root.sql")), "deny")

    def test_plain_include_stays_relative_to_event_cwd(self):
        (self.home / "scripts").mkdir()
        (self.home / "scripts/root.sql").write_text("\\i cwd-only.sql\n")
        (self.home / "scripts/cwd-only.sql").write_text("SELECT 1;\n")
        (self.home / "cwd-only.sql").write_text("DROP TABLE users;\n")
        self.assertEqual(self.verdict(self.ev("psql -h prod-db -f scripts/root.sql")), "deny")

    def test_include_cycle_depth_missing_and_total_byte_limits_fail_closed(self):
        (self.home / "cycle.sql").write_text("\\ir cycle.sql\nSELECT 1;\n")
        self.assertEqual(self.verdict(self.ev("psql -h prod-db -f cycle.sql")), "deny")
        (self.home / "missing-parent.sql").write_text("\\ir absent-child.sql\nSELECT 1;\n")
        self.assertEqual(self.verdict(self.ev("psql -h prod-db -f missing-parent.sql")), "deny")
        for index in range(11):
            body = "\\ir deep-%d.sql\n" % (index + 1) if index < 10 else "SELECT 1;\n"
            (self.home / ("deep-%d.sql" % index)).write_text(body)
        self.assertEqual(self.verdict(self.ev("psql -h prod-db -f deep-0.sql")), "deny")
        (self.home / "wide-root.sql").write_text("\\ir wide-a.sql\n\\ir wide-b.sql\n")
        for name in ("wide-a.sql", "wide-b.sql"):
            (self.home / name).write_text("-- " + "x" * 120000 + "\nSELECT 1;\n")
        self.assertEqual(self.verdict(self.ev("psql -h prod-db -f wide-root.sql")), "deny")

    def test_nested_read_only_include_closure_allows(self):
        (self.home / "sql").mkdir()
        (self.home / "sql/root.sql").write_text("\\ir child.sql\n")
        (self.home / "sql/child.sql").write_text("UPDATE users SET admin=true WHERE id=4;\n")
        self.assertEqual(self.verdict(self.ev("psql -h prod-db -f %s" % (self.home / "sql/root.sql"))), "allow")

    def test_include_dag_has_hard_read_and_expansion_caps(self):
        for index in range(8):
            (self.home / ("dag-%d.sql" % index)).write_text(
                "".join("\\ir dag-%d.sql\n" % child for child in range(index + 1, 8)) + "SELECT 1;\n")
        real_read = pdg._read_sql_file
        calls = []
        pdg._read_sql_file = lambda path: calls.append(path) or real_read(path)
        try:
            unread = []
            pdg.sql_text_for("psql -h prod-db -f dag-0.sql", str(self.home), unread)
        finally:
            pdg._read_sql_file = real_read
        self.assertLessEqual(len(calls), 8, calls)
        self.assertTrue(any("expansion" in reason for reason in unread), unread)
        self.assertEqual(self.verdict(self.ev("psql -h prod-db -f dag-0.sql"), env={}), "deny")

    def test_valid_duplicate_includes_are_memoized_and_allowed(self):
        (self.home / "root.sql").write_text("\\ir child.sql\n\\ir child.sql\n")
        (self.home / "child.sql").write_text("SELECT 1;\n")
        real_read = pdg._read_sql_file
        calls = []
        pdg._read_sql_file = lambda path: calls.append(path) or real_read(path)
        try:
            unread = []
            text = pdg.sql_text_for("psql -h prod-db -f root.sql", str(self.home), unread)
        finally:
            pdg._read_sql_file = real_read
        # each distinct file is read and joined once; a repeat include adds nothing new to judge
        self.assertEqual((len(calls), unread, text.count("SELECT 1;")), (2, [], 1))
        self.assertEqual(self.verdict(self.ev("psql -h prod-db -f root.sql"), env={}), "allow")

    def test_hyperdrive_query_payload_is_inspected(self):
        event = {"tool_name": "mcp__cloudflare__hyperdrive_execute",
                 "tool_input": {"database_id": "prod-hyper", "query": "DELETE FROM users"}}
        self.assertEqual(self.verdict(event), "deny")
        event["tool_input"] = {"id": "abc123", "sql": "DELETE FROM users"}
        self.assertEqual(self.verdict(event), "deny")
        event["tool_input"] = {"database_id": "prod-hyper", "query": "SELECT * FROM users WHERE id=4"}
        self.assertEqual(self.verdict(event), "allow")
        event["tool_input"]["query"] = "  \n"
        self.assertEqual(self.verdict(event), "allow")

    def test_mysql_executable_comments_and_destructive_drop_forms(self):
        self.assertDenied("mysql -h prod-db -e '/*!50000 DELETE FROM users */'")
        self.assertDenied("mysql -h prod-db -e '/*M!100100 DROP TABLE users */'")
        self.assertAllowed("mysql -h prod-db -e '/*!50000 SELECT 1 */'")
        self.assertAllowed("mysql -h localhost -e 'DROP VIEW old_object'")
        for kind in ("VIEW", "FUNCTION", "PROCEDURE", "TRIGGER", "ROLE", "USER"):
            with self.subTest(kind=kind):
                self.assertDenied("mysql -h prod-db -e 'DROP %s old_object'" % kind)


class RevisedSsh(Case):
    """goodqa#15037 (Kimi revised R05): the effective ssh destination, from -o HostName and ssh config."""

    def ssh_config(self, text, name=".ssh/config"):
        path = self.home / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def test_command_line_hostname_names_the_destination(self):
        self.assertDenied("ssh -o HostName=prod-db.example.com bastion psql -c 'DELETE FROM users'")
        self.assertDenied("ssh -oHostname=prod-db.example.com bastion psql -c 'DELETE FROM users'")
        self.assertDenied("ssh -o 'HostName prod-db.example.com' bastion psql -c 'DELETE FROM users'")
        self.assertAllowed("ssh -o HostName=localhost bastion psql -c 'DELETE FROM users'")
        result = pdg.evaluate(bash("ssh -o HostName=prod-db.example.com bastion psql -c 'DELETE FROM users'"),
                              home=str(self.home))
        self.assertIn("prod-db.example.com", result[1])

    def test_config_alias_mapped_to_prod_denies(self):
        self.ssh_config("Host *\n  User someone\n  IdentityFile ~/.ssh/k\n\n"
                        "Host db1 db1.internal\n  HostName prod-db.example.com\n  Port 2222\n\n"
                        "Host dev2\n  HostName 192.0.2.10\n")
        for cmd in ("ssh db1 psql -c 'DELETE FROM users'", "ssh someone@db1 psql -c 'DELETE FROM users'",
                    "ssh db1.internal psql -c 'DELETE FROM users'"):
            with self.subTest(cmd=cmd):
                self.assertDenied(cmd)
        # unrelated directives and non-prod aliases keep their old verdict (no new over-refusal)
        self.assertAllowed("ssh dev2 psql -c 'DELETE FROM users'")
        self.assertAllowed("ssh other psql -c 'DELETE FROM users'")
        self.assertAllowed("ssh db1 psql -c 'SELECT 1'")

    def test_wildcards_negation_tokens_and_match_blocks(self):
        self.ssh_config("Host *.db !safe.db\n  HostName %h.prod.example.com\n\n"
                        "Match host weird\n  HostName prod-weird.example.com\n")
        self.assertDenied("ssh users.db psql -c 'DELETE FROM users'")
        self.assertAllowed("ssh safe.db psql -c 'DELETE FROM users'")
        self.assertDenied("ssh weird psql -c 'DELETE FROM users'")  # Match blocks are candidates

    def test_includes_are_followed_and_bounded(self):
        self.ssh_config("Include config.d/*\n")
        self.ssh_config("Host db2\n  HostName prod-db2.example.com\n", ".ssh/config.d/10-db")
        self.assertDenied("ssh db2 psql -c 'DELETE FROM users'")
        self.ssh_config("Include config\n")  # a self-include terminates
        self.assertAllowed("ssh db2 psql -c 'DELETE FROM users'")

    def test_alternate_config_file(self):
        alt = self.ssh_config("Host db3\n  HostName prod-db3.example.com\n", "alt_config")
        self.assertDenied("ssh -F %s db3 psql -c 'DELETE FROM users'" % alt)
        self.assertAllowed("ssh db3 psql -c 'DELETE FROM users'")

    def test_unreadable_config_keeps_the_literal_verdict(self):
        cfg = self.ssh_config("Host db1\n  HostName prod-db.example.com\n")
        cfg.write_bytes(b"\xff\xfe" * 10)
        self.assertAllowed("ssh dev2 psql -c 'DELETE FROM users'")
        self.assertDenied("ssh prod-db psql -c 'DELETE FROM users'")


class ReviewRound1(Case):
    """Native red-team findings on 71c723b (goodqa#15036, goodqa#15037): dialect readings, linear time, ssh routes."""

    def setUp(self):
        super().setUp()
        self.work = self.home / "w"
        self.work.mkdir()

    def ev(self, command):
        return dict(bash(command), cwd=str(self.work))

    def put(self, name, body):
        (self.work / name).write_text(body)
        return self.work / name

    def test_every_dialect_reading_must_find_the_where(self):
        files = {
            "nest.sql": "UPDATE users SET a=1 /* /* */ -- */ WHERE id=1\n",
            "dq.sql": 'UPDATE users SET "a\\" = 1 -- " WHERE id=1\n',
            "bs.sql": "UPDATE users SET a='x\\' -- ' WHERE id=1\n",
            "arr.sql": "UPDATE users SET a = ARRAY[']'];\nSELECT ' WHERE true\n",
            "xc.sql": "UPDATE users SET a=1 /*!99999 WHERE id=1 */\n",
            "hash.sql": "UPDATE users SET a=1 # WHERE id=1\n",
            "upd.sql": "UPDATE users SET a=1\n",
        }
        for name, body in files.items():
            self.put(name, body)
        P, M = "psql -h prod-db.example.com ", "mysql -h prod-db.example.com "
        D1 = "wrangler d1 execute prod-db --remote "
        for cmd in (M + '-e "UPDATE users SET a=1 # WHERE id=1"', M + "< hash.sql",
                    P + "-c \"UPDATE users SET a='x\\' -- ' WHERE id=1\"", P + "-f bs.sql",
                    D1 + "--command \"UPDATE users SET a='x\\' -- ' WHERE id=1\"", M + "< nest.sql",
                    D1 + "--file nest.sql", P + "-f dq.sql", P + "-f arr.sql", M + "< xc.sql",
                    P + '-c "UPDATE users SET a=1 /*! WHERE id=1 */"', P + "-v x=\\' -f upd.sql",
                    P + "-v 'x=\"' -f upd.sql"):
            with self.subTest(cmd=cmd):
                self.assertEqual(self.verdict(self.ev(cmd)), "deny", cmd)
        for sql in ("UPDATE users SET a='x\\' -- ' WHERE id=1", "UPDATE users SET a=1 /*! WHERE id=1 */"):
            with self.subTest(sql=sql):
                ev = {"tool_name": "mcp__cf__d1_database_query", "tool_input": {"database_id": "abc", "sql": sql}}
                self.assertEqual(self.verdict(ev), "deny")

    def test_upserts_ctes_and_joins_with_a_where_stay_allowed(self):
        P = 'psql -h prod-db.example.com -c "%s"'
        for sql in ("INSERT INTO t (id, a) VALUES (1, 2) ON CONFLICT (id) DO UPDATE SET a = 2",
                    "WITH x AS (UPDATE t SET a = 1 WHERE id = 1 RETURNING id) SELECT * FROM x",
                    "UPDATE t1 JOIN t2 ON t1.id = t2.id SET t1.a = 1 WHERE t2.b = 2",
                    "UPDATE users SET a=1 WHERE id=1"):
            with self.subTest(sql=sql):
                self.assertFalse(pdg.destructive_match(sql), sql)
                self.assertAllowed(P % sql)
        ev = {"tool_name": "mcp__cf__d1_database_query",
              "tool_input": {"database_id": "abc", "sql": "INSERT INTO t VALUES (1) ON CONFLICT (id) DO UPDATE SET a=2"}}
        self.assertEqual(self.verdict(ev), "allow")
        for sql in ("WITH x AS (UPDATE t SET a = 1 RETURNING id) SELECT * FROM x WHERE true",
                    "UPDATE t SET a = 1 RETURNING (SELECT 1 WHERE true)",
                    "WITH a AS (UPDATE t SET x=1 WHERE id=1), b AS (UPDATE t SET x=2) SELECT 1",
                    "UPDATE t SET a=1 WHERE id=1 " * 300):
            with self.subTest(sql=sql):
                self.assertTrue(pdg.destructive_match(sql), sql)

    def test_pathological_inputs_stay_linear(self):
        import time as _time
        cases = {
            "update-words.sql": "-- " + "update " * 27000 + ";\nUPDATE users SET a=1;\n",
            "exec-open.sql": "/*!" * 60000 + "\n",
            "comment-open.sql": "/*" * 90000 + "\n",
            "many-updates.sql": "UPDATE t SET a=1, " * 10000 + "\n",
        }
        for name, body in cases.items():
            self.put(name, body)
            with self.subTest(name=name):
                start = _time.monotonic()
                self.verdict(self.ev("psql -h prod-db.example.com -f %s" % name))
                self.verdict(self.ev("psql -h localhost -f %s" % name))
                self.assertLess(_time.monotonic() - start, 8.0, name)

    def test_ssh_routes_that_still_reached_prod(self):
        cfg = self.put("cfg", "Host db1\n  HostName prod-db.example.com\n")
        self.put("big", "Host *\n  HostName 192.0.2.1\n" + ("#" * 80 + "\n") * 900)
        self.put("lines", "\n" * 4100 + "Host db1\n  HostName prod-db.example.com\n")
        inc = self.work / "inc"
        inc.mkdir()
        for k in range(16):
            (inc / ("a%02d" % k)).write_text("Host other%d\n  User x\n" % k)
        (inc / "z99").write_text("Host db1\n  HostName prod-db.example.com\n")
        self.put("cfg_inc", "Include %s/*\n" % inc)
        self.ssh_home("Host db1\n  HostName prod-db.example.com\n")
        verb = "DEL" + "ETE FROM users"
        for cmd in ('ssh x1 -o HostName=prod-db.example.com psql -c "%s"',
                    'ssh -tF %s db1 psql -c "%%s"' % cfg, 'ssh -qoHostName=prod-db.example.com x1 psql -c "%s"',
                    'ssh -F big x1 psql -c "%s"', 'ssh -F lines db1 psql -c "%s"', 'ssh ssh://db1 psql -c "%s"',
                    'ssh ssh://someone@db1:22 psql -c "%s"', 'ssh -F cfg_inc db1 psql -c "%s"',
                    'ssh db1 -F %s psql -c "%%s"' % cfg, 'ssh -F missing.cfg x1 psql -c "%s"',
                    "ssh " + "-q " * 300 + 'prod-db psql -c "%s"'):
            with self.subTest(cmd=cmd[:60]):
                self.assertEqual(self.verdict(self.ev(cmd % verb)), "deny")
        self.assertEqual(self.verdict(self.ev('ssh dev2 psql -c "%s"' % verb)), "allow")
        self.assertEqual(self.verdict(self.ev('ssh -t dev2 -o BatchMode=yes psql -c "%s"' % verb)), "allow")

    def test_a_config_reader_error_keeps_the_literal_target(self):
        self.put("nul.cfg", "Include /tmp/a\x00/*\n")
        result = pdg.evaluate(self.ev('ssh -F nul.cfg prod-db psql -c "%s"' % ("DEL" + "ETE FROM users")),
                              home=str(self.home))
        self.assertEqual(result[0], "deny")
        self.assertIn("prod-db", result[1])

    def ssh_home(self, text):
        (self.home / ".ssh").mkdir(exist_ok=True)
        (self.home / ".ssh/config").write_text(text)


if __name__ == "__main__":
    unittest.main()


class KimiPrcR2(Case):
    """Kimi 3.1 Pro BLOCK of PR-C at 1aa61b3 (goodqa#14993): one test per reproduction in kimi-prc/report.md."""

    def setUp(self):
        super().setUp()
        self.work = self.home / "w"
        self.work.mkdir()

    def ev(self, command):
        return dict(bash(command), cwd=str(self.work))

    def put(self, name, body):
        path = self.work / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)
        return path

    def deny(self, command):
        self.assertEqual(self.verdict(self.ev(command)), "deny", command)

    def allow(self, command):
        self.assertEqual(self.verdict(self.ev(command)), "allow", command)

    def ssh_config(self, text, name=".ssh/config"):
        path = self.home / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def test_f1_nested_block_comments_do_not_hide_destructive_sql(self):
        self.deny("psql -h prod-db -c 'DELETE /* outer /* inner */ tail */ FROM users'")
        self.deny("psql -h prod-db -c 'DROP /* outer /* inner */ tail */ TABLE users'")
        self.deny("psql -h prod-db -c 'UPDATE /* a /* b */ c */ users SET admin=true'")

    def test_f2_single_quoted_do_body_is_judged(self):
        self.deny('psql -h prod-db -c "DO \'BEGIN UPDATE users SET admin=true; END\';"')
        self.deny('psql -h prod-db -c "DO LANGUAGE plpgsql \'BEGIN UPDATE users SET admin=true; END\';"')
        self.deny('psql -h prod-db -c "DO E\'BEGIN UPDATE users SET admin=true; END\';"')
        self.allow('psql -h prod-db -c "DO \'BEGIN UPDATE users SET admin=true WHERE id=4; END\';"')

    def test_f3_equivalent_file_input_spellings_are_read(self):
        self.put("evil.sql", "DELETE FROM users;\n")
        self.deny("psql -h prod-db -c \"$(cat 'evil.sql')\"")
        self.deny('psql -h prod-db -c "$(/bin/cat evil.sql)"')
        self.deny('psql -h prod-db -c "$(\\cat evil.sql)"')
        self.deny("psql -h prod-db --fi''le evil.sql")
        self.deny('psql -h prod-db "--file" evil.sql')
        self.deny("mysql -h prod-db -e 'SELECT 1;\nsource evil.sql'")
        self.deny("mysql -h prod-db -e 'SELECT 1; SOURCE evil.sql'")
        self.put("ok.sql", "SELECT 1;\n")
        self.allow("psql -h prod-db -c \"$(cat 'ok.sql')\"")
        self.allow("psql -h prod-db --fi''le ok.sql")

    def test_f4_a_remote_or_container_file_cannot_be_judged_from_a_local_one(self):
        self.put("remote.sql", "SELECT 1;\n")
        self.deny('ssh prod-db "psql -f remote.sql"')
        self.deny("ssh prod-db psql -f remote.sql")
        self.deny("docker exec -i prod-pg psql -f remote.sql")
        self.deny("kubectl exec prod-pg -- psql -f remote.sql")
        self.deny("podman exec -i prod-pg psql -f remote.sql")
        self.deny("ssh prod-db 'psql < remote.sql'")
        self.deny("ssh prod-db \"mysql -e 'source remote.sql'\"")
        # a local file fed to the remote client through the local shell is judged as before
        self.allow("cat remote.sql | ssh prod-db psql")
        self.allow("ssh prod-db psql < remote.sql")

    def test_f4_psql_cd_in_a_file_cannot_redirect_its_includes(self):
        self.put("root-cd.sql", "\\cd sub\n\\i payload.sql\n")
        self.put("payload.sql", "SELECT 1;\n")
        self.put("sub/payload.sql", "DELETE FROM users;\n")
        self.deny("psql -h prod-db -f root-cd.sql")
        self.deny("psql -h prod-db -c '\\cd sub' -c '\\i payload.sql'")

    def test_f5_ssh_options_with_values_are_not_the_host(self):
        self.deny("ssh -B lo prod-db psql -c 'DELETE FROM users'")
        self.deny("ssh -P tag prod-db psql -c 'DELETE FROM users'")
        # an option letter the guard does not know makes the destination uncertain
        self.deny("ssh -Z lo prod-db psql -c 'DELETE FROM users'")
        self.allow("ssh -B lo dev2 psql -c 'SELECT 1'")

    def test_f6_proxy_command_and_proxy_jump_fail_closed(self):
        self.deny("ssh -o ProxyCommand='nc prod-db.example.com 22' dev psql -c 'DELETE FROM users'")
        self.deny("ssh -o 'ProxyCommand nc prod-db.example.com 22' dev psql -c 'DELETE FROM users'")
        self.deny("ssh -o ProxyJump=jump dev psql -c 'DELETE FROM users'")
        self.deny("ssh -J jump dev psql -c 'DELETE FROM users'")
        self.ssh_config("Host dev\n  ProxyCommand nc prod-db.example.com 22\n")
        self.deny("ssh dev psql -c 'DELETE FROM users'")
        self.ssh_config("Host dev\n  HostName 192.0.2.5\n  ProxyJump bastion\n")
        self.deny("ssh dev psql -c 'DELETE FROM users'")
        self.deny("ssh -o HostName=192.0.2.5 dev psql -c 'DELETE FROM users'")  # config still read
        self.allow("ssh dev psql -c 'SELECT 1'")

    def test_f7_a_quoted_include_path_is_followed(self):
        self.ssh_config('Include "conf.d/prod route"\n')
        self.ssh_config("Host db\n  HostName prod-db.example.com\n", ".ssh/conf.d/prod route")
        self.deny("ssh db psql -c 'DELETE FROM users'")

    def test_f8_long_ssh_chains_and_update_floods_decide_quickly(self):
        cases = ("ssh " * 10000 + "psql -h prod-db.example.com -c 'DELETE FROM users'",
                 "psql -h prod-db -c '" + "UPDATE t SET a=1 WHERE id=1; " * 26000 + "UPDATE t SET a=1'",
                 "psql -h prod-db -c '" + "UPDATE t SET a=1 WHERE id=1 " * 28000 + "'")
        for command in cases:
            with self.subTest(size=len(command)):
                t0 = time.monotonic()
                self.assertEqual(self.verdict(self.ev(command)), "deny")
                self.assertLess(time.monotonic() - t0, 5.0)

    def test_f8_the_decision_deadline_fails_closed(self):
        old = pdg.DECISION_BUDGET
        pdg.DECISION_BUDGET = 0.0
        try:
            self.deny("psql -h prod-db -c 'SELECT 1'")
            self.allow("ls -la")  # nothing database-like: past the deadline it still allows
        finally:
            pdg.DECISION_BUDGET = old

    def test_f9_strings_and_comments_are_not_statements(self):
        self.allow("psql -h prod-db -c \"SELECT 'DELETE FROM users' AS example\"")
        self.allow("psql -h prod-db -c \"SELECT 'DROP TABLE users' AS example\"")
        self.put("comment-include.sql", "-- \\i absent.sql\nSELECT 1;\n")
        self.allow("psql -h prod-db -f comment-include.sql")
        self.put("string-include.sql", "SELECT '\\i absent.sql';\n")
        self.allow("psql -h prod-db -f string-include.sql")
        # shell quoting still cannot split a verb, and a real statement next to a string still denies
        self.deny('psql -h prod-db -c "DEL""ETE FROM users"')
        self.deny("psql -h prod-db -c \"SELECT 'x'; DELETE FROM users\"")
        self.deny("ssh prod-db \"psql -c 'DELETE FROM users'\"")

    # ---- red-team review of 2f508e5 (agent a84537ae62d582cfc): R1 crash, R2 string sinks, R3 remote files, R4 lexer

    def test_r1_whitespace_words_cannot_crash_the_guard_open(self):
        for command in ("psql -h prod-db.example.com -c 'DELETE FROM users' ' '",
                        "' ' ; psql -h prod-db -c 'DELETE FROM users'",
                        'psql -h prod-db -c "DELETE FROM users" "\n"',
                        '"   " psql -h prod-db -c "DELETE FROM users"',
                        'bash -c "\' \' ; psql -h prod-db -c \'DELETE FROM users\'"'):
            with self.subTest(command=command):
                self.deny(command)

    def test_r2_sql_that_runs_a_string_is_judged_with_its_strings(self):
        for command in ('mysql -h prod-db -e "PREPARE s FROM \'DELETE FROM users\'; EXECUTE s;"',
                        'mysql -h prod-db -e "SET @q=\'DELETE FROM users\'; PREPARE s FROM @q; EXECUTE s;"',
                        'psql -h prod-db -c "CREATE FUNCTION f() RETURNS void AS \'DELETE FROM users\' LANGUAGE sql; SELECT f();"',
                        'psql -h prod-db -c "CREATE PROCEDURE p() AS \'TRUNCATE users\' LANGUAGE sql; CALL p();"',
                        'psql -h prod-db -c "SELECT dblink_exec(\'dbname=app\', \'DROP TABLE users\')"',
                        'psql -h prod-db -c "COPY t FROM PROGRAM \'psql -c DELETE FROM users\'"',
                        "psql -h prod-db -c '\\! psql -c \"DELETE FROM users\"'",
                        'mysql -h prod-db -e "system mysql -e \'DELETE FROM users\'"',
                        "psql -h prod-db -c \"DO 'BEGIN EXECUTE ''DELETE FROM users''; END'\""):
            with self.subTest(command=command):
                self.deny(command)
        self.put("gexec.sql", "SELECT 'DELETE FROM users' \\gexec\n")
        self.deny("psql -h prod-db -f gexec.sql")
        self.put("setvar.sql", "\\set q 'DELETE FROM users'\n:q;\n")
        self.deny("psql -h prod-db -f setvar.sql")
        self.put("prep.sql", "PREPARE s FROM 'DELETE FROM users'; EXECUTE s;\n")
        self.deny("mysql -h prod-db < prep.sql")
        # a plain string is still a string
        self.allow("psql -h prod-db -c \"SELECT 'DELETE FROM users' AS example\"")

    def test_r3_a_file_named_on_the_far_side_of_a_remote_runner_is_unread(self):
        self.put("a.sql", "SELECT 1;\n")
        for command in ("ssh dev2 'cd /srv && psql -h prod-db -f a.sql'",
                        "ssh dev2 'export X=1; psql -h prod-db -f a.sql'",
                        "docker compose exec db psql -h prod-db -f a.sql",
                        "docker container exec db psql -h prod-db -f a.sql",
                        "kubectl -n prod exec pg-0 -- psql -h prod-db -f a.sql"):
            with self.subTest(command=command):
                self.deny(command)
        self.allow("psql -h prod-db -f a.sql")

    def test_r4_doubled_quotes_and_escapes_mask_in_linear_time(self):
        # Scaling, not wall-clock: 4x the input must cost well under 16x (quadratic) in a backslash reading. The
        # 2f508e5 lexer searched for the next backslash from every doubled quote, to the end of the text.
        def cost(n, unit):
            body = "SELECT '" + unit * n + "';"
            best = None
            for _ in range(3):
                t0 = time.perf_counter()
                pdg._mask_sql(body, True, True, True, False, True)
                took = time.perf_counter() - t0
                best = took if best is None else min(best, took)
            return best
        for unit in ("''", "\\x"):
            with self.subTest(unit=unit):
                small, large = cost(40000, unit), cost(160000, unit)
                self.assertLess(large / max(small, 1e-6), 8.0, (unit, small, large))

    def test_r5_shell_decoding_and_more_remote_runners(self):
        self.put("a.sql", "SELECT 1;\n")
        self.put("c.sql", "\\CD sub\n\\i a.sql\n")
        for command in ("lxc exec box -- psql -h prod-db -f a.sql",
                        "docker run --rm -v /srv:/srv postgres psql -h prod-db -f a.sql",
                        "mosh dev2 -- psql -h prod-db -f a.sql",
                        "psql -h prod-db -f c.sql",
                        'psql -h prod-db -c "DEL\\\nETE FROM users"',
                        "psql -h prod-db -c DELETE\\ FR\\\nOM\\ users",
                        "psql -h prod-db -c $'\\x44ELETE FROM users'",
                        'bash -c "psql -h prod-db -c \\\'DELETE FROM users\\\' \' \'"'):
            with self.subTest(command=command):
                self.deny(command)

