"""Transcript archive redaction gate (GoodQA #16650, spec "Redaction gate", red-team spec-review-redteam.md).

Every fake secret is assembled at runtime, so no realistic credential literal sits in this file and the repo's
leak scan passes without an allowlist entry. Assertions are booleans (`assertFalse(leaks(...))`) so a failure
can never print a value.
"""
import base64
import hashlib
import importlib.util
import json
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "harness" / "hooks"))
import transcript_redact as tr  # noqa: E402

# Synthetic values only. Each is unique so a leak can be traced to its case without printing it.
F = "Zq9X" + "w2Lm8Rt4" + "Vb7Np3Kc6"
F2 = "Hy5T" + "k8Pw3Rn6" + "Qd2Ls9Mx4"
F3 = "Ue7G" + "j4Vc1Bz8" + "Wo6Ia3Sf5"
ANT = "sk-" + "ant-" + "api03-" + "Z" * 12 + F
ANT_BODY = "api03-" + "Z" * 12 + F
# Column-aligned assignments: 9 to 100 spaces or tabs around the separator.
ALIGNED = ["password" + " " * 9 + "= " + F, "password =" + " " * 9 + F, "DB_PASSWORD" + " " * 20 + "= \"" + F + "\"",
           "api_key:" + " " * 12 + F, "client_secret\t\t\t\t\t\t\t\t\t\t= " + F, "secret" + " " * 100 + ": " + F,
           "PGPASSWORD" + " " * 12 + "= " + F, "Authorization:" + " " * 12 + F]


def run(obj_or_text, line_no=1):
    if isinstance(obj_or_text, (dict, list)):
        raw = json.dumps(obj_or_text, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    elif isinstance(obj_or_text, str):
        raw = obj_or_text.encode("utf-8")
    else:
        raw = obj_or_text
    return tr.redact_line(raw, line_no)


def leaks(out: bytes, *secrets: str) -> bool:
    return any(s.encode("utf-8") in out for s in secrets)


def parses(out: bytes) -> bool:
    try:
        json.loads(out.decode("utf-8"))
        return True
    except ValueError:
        return False


class KeyedValues(unittest.TestCase):
    KEYS = ["password", "passwd", "pwd", "pass", "secret", "token", "apikey", "api_key", "apiKey", "API-KEY",
            "access_key", "accessKey", "auth", "authorization", "cookie", "session", "sessionid", "sessionId",
            "session_token", "credential", "credentials", "private_key", "privateKey", "client_secret",
            "signature", "sig", "bearer", "otp", "GITHUB_TOKEN", "dbPassword", "x-api-key", "Secret-Key"]

    def test_each_credential_key_is_redacted_whole(self):
        for i, key in enumerate(self.KEYS):
            with self.subTest(case=i):
                out, counts, omitted = run({"input": {key: F, "keep": "visible"}})
                self.assertIsNone(omitted)
                self.assertFalse(leaks(out, F))
                self.assertTrue(b"[REDACTED:keyed]" in out)
                self.assertTrue(b"visible" in out)
                self.assertTrue(counts.get("keyed", 0) >= 1)

    def test_neg15_plural_and_short_credential_keys(self):
        # NEG-15 (r4): singularized key words, pw/jwt, token as the last word (red-team r3 CRITICAL).
        for i, rec in enumerate([{"api_keys": [F]}, {"tokens": [F]}, {"passwords": [F]},
                                 {"login": {"user": "x", "pw": F}}, {"tokenString": F}, {"jwt": F},
                                 {"authToken": F}, {"client_secrets": {"a": F}}, {"cookies": [{"v": F}]},
                                 {"passphrase": F}, {"bearer": F}, {"pass": F}, {"session": F},
                                 {"accessTokens": [F]}, {"sid": F}]):
            with self.subTest(case=i):
                out, _, omitted = run(rec)
                self.assertIsNone(omitted)
                self.assertFalse(leaks(out, F))
                self.assertTrue(b"[REDACTED:keyed]" in out)

    def test_nested_containers_under_a_key_are_replaced_whole(self):
        out, _, omitted = run({"credentials": {"user": "u1", "inner": [F, {"deeper": F2}]}, "other": 1})
        self.assertIsNone(omitted)
        self.assertFalse(leaks(out, F, F2))
        self.assertEqual(json.loads(out)["credentials"], "[REDACTED:keyed]")
        self.assertEqual(json.loads(out)["other"], 1)

    def test_numbers_kept_except_under_password_pin_otp_passcode(self):
        out, _, _ = run({"otp": 918273, "user_pin": 4321, "passcode": 1234, "dbPassword": 99, "pass": True,
                         "token": None, "secret": 5, "api_key": 7.5})
        obj = json.loads(out)
        for key in ("otp", "user_pin", "passcode", "dbPassword"):
            with self.subTest(key=key):
                self.assertEqual(obj[key], "[REDACTED:keyed]")
        self.assertIs(obj["pass"], True)
        self.assertIsNone(obj["token"])
        self.assertEqual(obj["secret"], 5)
        self.assertEqual(obj["api_key"], 7.5)
        for i, rec in enumerate([{"secret": 123456, "api_key": 9876.5}, {"x": {"client_secret": 44444}},
                                 {"auth_token": -1234567}]):
            with self.subTest(kept_number=i):
                out, _, omitted = run(rec)
                self.assertIsNone(omitted)
                self.assertEqual(json.loads(out), rec)
        tr_pass1 = tr._pass1
        try:
            tr._pass1 = lambda line: (line, {})
            self.assertIsNotNone(run({"password": 12345678})[2])  # pass 2 still flags a numeric password
        finally:
            tr._pass1 = tr_pass1

    def test_non_credential_keys_are_not_redacted(self):
        clean = {"pin": "1234", "passage": "a long passage", "passenger": "p", "input_tokens": 12,
                 "max_tokens": 4096, "token_count": 3, "author": "someone", "keyboard": "k",
                 "session_count": 2, "compass": "north", "tokens": 9, "bypass": "b", "authors": ["a"]}
        out, counts, omitted = run(clean)
        self.assertIsNone(omitted)
        self.assertEqual(json.loads(out), clean)
        self.assertEqual(counts, {})

    def test_name_value_pairs(self):
        cases = [
            {"cookies": None, "list": [{"name": "sessionid", "value": F}]},
            {"env": [{"name": "GITHUB_TOKEN", "value": F}, {"name": "HOME_DIR", "value": "kept"}]},
            {"item": {"key": "API_KEY", "value": F}},
            {"jar": [{"name": "_ga_x", "value": F, "domain": ".example.invalid", "path": "/"}]},
        ]
        for i, case in enumerate(cases):
            with self.subTest(case=i):
                out, _, omitted = run(case)
                self.assertIsNone(omitted)
                self.assertFalse(leaks(out, F))
                self.assertTrue(parses(out))
        out, _, _ = run(cases[1])
        self.assertTrue(b"kept" in out)

    def test_header_maps(self):
        basic = base64.b64encode(("admin:" + F).encode()).decode()
        obj = {"headers": {"Authorization": "Basic " + basic, "Cookie": "a=" + F, "Set-Cookie": "s=" + F2 + "; Path=/",
                           "X-Auth-Token": F3, "X-Custom-Key": F, "X-Api-Key": F2, "Accept": "text/html"},
               "pairs": [["Authorization", F3], ["Accept", "kept/type"]]}
        out, _, omitted = run(obj)
        self.assertIsNone(omitted)
        self.assertFalse(leaks(out, F, F2, F3, basic))
        self.assertTrue(b"text/html" in out and b"kept/type" in out)


class TextShapes(unittest.TestCase):
    def cases(self):
        basic = base64.b64encode(("admin:" + F).encode()).decode()
        return [
            ("Authorization: Basic " + basic, [basic]),
            ("Authorization: Bearer " + F, [F]),
            ("authorization: Token " + F, [F]),
            ("Cookie: sid=" + F + "; theme=" + F2, [F, F2]),
            ("Set-Cookie: sid=" + F + "; Path=/; HttpOnly", [F]),
            ("curl -u admin:" + F + " https://example.invalid/x", [F]),
            ("tool --password " + F + " --x", [F]),
            ("tool --token=" + F, [F]),
            ("tool --secret " + F, [F]),
            ("mysql -uroot -p" + F + " db1", [F]),
            ("mysqldump -u root -p " + F + " db1", [F]),
            ("MYSQL_PWD=" + F + " mysql", [F]),
            ("export DJANGO_SECRET_KEY=" + F, [F]),
            ("secretKey: " + F, [F]),
            ("PGPASSWORD=" + F + " psql -h db", [F]),
            ("https://bucket.example.invalid/o?X-Amz-Credential=" + F + "&X-Amz-Signature=" + F2
             + "&X-Amz-Security-Token=" + F3, [F, F2, F3]),
            ("https://storage.example.invalid/o?X-Goog-Signature=" + F, [F]),
            ("https://x.example.invalid/blob?sv=1&sig=" + F, [F]),
            ("https://x.example.invalid/p?a=1&signature=" + F, [F]),
            ("https://x.example.invalid/p?token=" + F, [F]),
            ('cfg {\\"password\\": \\"' + F + '\\"}', [F]),
        ]

    def test_shapes_in_plain_text_lines(self):
        for i, (text, secrets) in enumerate(self.cases()):
            with self.subTest(case=i):
                out, _, omitted = run(text)
                self.assertIsNone(omitted)
                self.assertFalse(leaks(out, *secrets))

    def test_shapes_inside_json_strings(self):
        for i, (text, secrets) in enumerate(self.cases()):
            with self.subTest(case=i):
                out, _, omitted = run({"type": "tool_result", "content": "out: " + text + " done"})
                self.assertIsNone(omitted)
                self.assertFalse(leaks(out, *secrets))
                self.assertTrue(parses(out))
                self.assertTrue(b"done" in out)

    def test_dash_p_outside_mysql_is_not_redacted(self):
        for i, text in enumerate(["mkdir -p build/out && ls", "mkdir -p build && mysql -u app",
                                  "mysql -u root; mkdir -p dir2", "grep -p pattern file"]):
            with self.subTest(case=i):
                out, counts, _ = run(text)
                self.assertEqual(out, text.encode())
                self.assertEqual(counts, {})

    def test_bearer_with_colon_or_equals(self):
        for i, text in enumerate(["bearer:" + F, "Bearer=" + F]):
            with self.subTest(case=i):
                out, _, omitted = run(text)
                self.assertIsNone(omitted)
                self.assertFalse(leaks(out, F))

    def test_secret_in_a_key_is_redacted(self):
        out, _, omitted = run({ANT: 1, "long_" * 60 + "password": F2})
        self.assertIsNone(omitted)
        self.assertFalse(leaks(out, F, F2))

    def test_superseded_named_credential_coverage(self):
        # transcript_redact skips redact.py's first named-credential shape; its own keyword rule must cover it.
        for i, text in enumerate(["DB_PASSWORD=" + F, "a_b_c_d_e_f_g_h_i_j_secret=" + F, "my-app-client-secret: " + F,
                                  "x-api-key=" + F, "refresh_token_value=" + F, "id_token: '" + F + "'",
                                  "ACCESS-KEY=" + F, "credentials=" + F, "private_key:" + F]):
            with self.subTest(case=i):
                out, _, omitted = run(text)
                self.assertIsNone(omitted)
                self.assertFalse(leaks(out, F))

    def test_aligned_assignments_are_redacted(self):
        """Delta gate on PR #316: _NAMED replaced redact.py's named-credential shape, whose separator whitespace is
        unbounded; column-aligned config (.env, TOML, YAML, INI) put 9+ spaces around = or : and leaked."""
        for i, text in enumerate(ALIGNED):
            with self.subTest(case=i):
                out, _, omitted = run(text)
                self.assertIsNone(omitted)
                self.assertFalse(leaks(out, F))

    def test_psql_port_is_not_redacted(self):
        out, _, _ = run("psql -h db -p 5432 -U app")
        self.assertTrue(b"-p 5432" in out)

    def test_email(self):
        out, counts, _ = run({"t": "mail someone@example.invalid now"})
        self.assertFalse(b"someone@example.invalid" in out)
        self.assertTrue(b"[REDACTED:email]" in out)
        self.assertEqual(counts.get("email"), 1)

    def test_phone_numbers(self):
        for i, text in enumerate(["call (555) 123-4567 now", "call 555-123-4567 now", "call +1 555.123.4567 now",
                                  "call 555 123 4567 now"]):
            with self.subTest(case=i):
                out, _, _ = run({"t": text})
                self.assertTrue(b"[REDACTED:phone]" in out)
                self.assertFalse(b"4567" in out)

    def test_phone_negatives(self):
        for i, text in enumerate(["2026-11-22T02:14:13.084941+00:00", "2026-11-22 10:15:30",
                                  "550e8400-e29b-41d4-a716-446655440000", "12345678-1234-1234-1234-123456789012",
                                  "version 1.2.3", "macOS 10.15.7", "Python 3.9.6", "file.py:123:45",
                                  "at main.go:1234:5678", "build 20261122.1"]):
            with self.subTest(case=i):
                out, counts, _ = run({"t": text})
                self.assertEqual(json.loads(out)["t"], text)
                self.assertEqual(counts, {})

    def test_base64_run_omitted(self):
        blob = base64.b64encode(bytes(range(256)) * 5)[:1500].decode()
        out, counts, _ = run({"image": {"data": blob}})
        sha12 = hashlib.sha256(blob.encode()).hexdigest()[:12]
        self.assertFalse(blob[:200].encode() in out)
        self.assertEqual(json.loads(out)["image"]["data"], "[OMITTED:base64:1500:%s]" % sha12)
        self.assertEqual(counts.get("base64"), 1)

    def test_long_run_never_swallows_a_key_word(self):
        """Triage of PR #316 at 79d55675 (CRITICAL): the base64 collapse ran before the keyword rules, so a 1000+
        character name ending in a key word lost the key word and its value reached the archive. Keyword spans and
        base64 runs are now found on the same untransformed text (raw and normalized) and applied together."""
        jwt = ("eyJhbGciOiJIUzI1NiJ9." + base64.urlsafe_b64encode(b'{"sub":"' + b"u" * 1200 + b'"}').decode()
               .rstrip("=") + "." + F)
        cases = {
            "17 long segments": "_".join(["b" * 130] * 17) + "_secret: " + F,
            "one long segment": "b" * 1200 + "_password=" + F,
            "hyphen key": "b" * 1200 + "-api-key: " + F,
            "env name": "B" * 1200 + "_TOKEN=" + F,
            # key words that only appear after normalization (the normalized scan used to run on collapsed text)
            "percent-encoded key word": "b" * 1200 + "_api%5Fkey=" + F,
            "percent-encoded letter": "b" * 1200 + "_pass%77ord=" + F,
            "zero-width space": "b" * 1200 + "_pass\u200bword=" + F,
            "escaped zero-width space": "b" * 1200 + "_pass\\u200bword=" + F,
            "escaped quote": "b" * 1200 + "_password\\\"=" + F,
            "jwt with a long payload": "bearer " + jwt,
            "bare jwt with a long payload": jwt,
        }
        for name, text in cases.items():
            for shape in ("text", "json"):
                with self.subTest(case=name, shape=shape):
                    out, _, _ = run(text if shape == "text" else {"type": "user", "content": text})
                    self.assertFalse(leaks(out, F))

    def test_long_run_before_a_pass2_only_key_word_omits_the_record(self):
        """A key word only pass 2 joins (a line break inside it) is checked before the run is collapsed."""
        out, counts, omitted = run({"type": "user", "content": "b" * 1200 + "_pass\nword=" + F})
        self.assertIsNotNone(omitted)
        self.assertFalse(leaks(out, F))

    def test_long_value_leaves_no_tail(self):
        """A value longer than its rule's limit (about 4096) inside one long run is omitted whole: the keyword span
        is extended to the end of the run, so no tail shorter than the 1000-character collapse survives."""
        value = "Q" * 2000 + F + "R" * 2600
        for text in ("password=" + value, "x password: " + value, "Bearer " + value, "PGPASSWORD=" + value):
            with self.subTest(text=text[:12]):
                out, _, _ = run({"t": text})
                self.assertFalse(leaks(out, F, "R" * 100, "Q" * 100))
        # The invariant itself (pass 2 would also catch the end-to-end shape above): a span cut at its limit inside
        # a run reaches the end of the run.
        text = "x password: " + value
        self.assertEqual([end for _, end, kind in tr._keyword_spans(text) if kind == "named-credential"], [len(text)])

    def test_long_run_before_a_key_word_is_still_omitted(self):
        """The fix keeps the omission: the run itself is never archived, whatever follows it."""
        run_text = "b" * 1200
        out, counts, omitted = run({"x": run_text + "_password=" + F})
        self.assertIsNone(omitted)
        self.assertFalse(leaks(out, run_text, F))
        self.assertTrue(counts)

    def test_short_base64_kept(self):
        blob = base64.b64encode(b"x" * 600).decode()
        out, _, _ = run({"d": blob})
        self.assertEqual(json.loads(out)["d"], blob)


class KnownBypasses(unittest.TestCase):
    def check(self, value, *secrets):
        for i, form in enumerate((value, {"content": value})):
            with self.subTest(form=i):
                out, _, omitted = run(form)
                self.assertFalse(leaks(out, *secrets))
                if omitted is None and isinstance(form, dict):
                    self.assertTrue(parses(out))

    def test_marker_abutting_value(self):
        self.check("password=[REDACTED:x]" + F, F)

    def test_token_wrapped_across_line_break(self):
        head = "sk-" + "ant-api03-" + "Z" * 12 + F
        self.check("key " + head + "\n" + F2 + " end", F, F2)

    def test_ansi_between_key_and_value(self):
        self.check("password\x1b[0m=" + F, F)

    def test_zero_width_inside_prefix(self):
        self.check("key sk-​ant-" + ANT_BODY, F)

    def test_url_encoded_bearer(self):
        self.check("GET /x?h=Authorization%3A%20Bearer%20" + F, F)
        self.check("header Bearer%20" + F, F)

    def test_unicode_escaped_prefix(self):
        self.check("key \\u0073k-ant-" + ANT_BODY, F)

    def test_json_line_with_escaped_prefix(self):
        raw = b'{"t":"key \\u0073k-ant-' + ANT_BODY.encode() + b'"}'
        out, _, _ = tr.redact_line(raw, 1)
        self.assertFalse(leaks(out, F))

    def test_decoding_never_undoes_a_raw_redaction(self):
        # A %XX or \\u escape can add a delimiter that shortens a match the raw text fully covered.
        self.check("postgres://app:" + F + "%2Ftail@db.example.invalid/x", F)
        self.check("password=abc%20" + F, F)
        self.check("password=abc\\u0020" + F, F)

    def test_token_wrapped_over_several_lines(self):
        head = "sk-" + "ant-api03-" + "Z" * 12 + F
        self.check("key " + head + "\n" + F2 + "\n" + F3 + "\nQq7Ww" + "Ee9Rr2Tt" + " end", F, F2, F3, "Qq7WwEe9Rr2Tt")

    def test_argv_arrays(self):
        for i, argv in enumerate([["tool", "--password", F], ["tool", "--api-key", F, "--verbose"],
                                  ["curl", "-u", "admin:" + F, "https://example.invalid"],
                                  ["mysql", "-u", "root", "-p" + F, "db1"]]):
            with self.subTest(case=i):
                out, _, omitted = run({"input": {"argv": argv}})
                self.assertIsNone(omitted)
                self.assertFalse(leaks(out, F))
        out, _, _ = run({"argv": ["mkdir", "-p", "build", "--verbose"]})
        self.assertEqual(json.loads(out)["argv"], ["mkdir", "-p", "build", "--verbose"])

    def test_env_style_key_names(self):
        out, _, _ = run({"env": {"APP_KEY": F, "DEPLOY_KEY": F2, "SORT_KEY_HINT": "kept"}})
        self.assertFalse(leaks(out, F, F2))
        self.assertTrue(b"kept" in out)

    def test_double_encoded_json_api_key(self):
        once = json.dumps({"api_key": F})
        twice = json.dumps(once)
        for i, form in enumerate(({"content": once}, {"content": twice}, {"a": {"b": json.dumps(twice)}})):
            with self.subTest(form=i):
                out, _, omitted = run(form)
                self.assertFalse(leaks(out, F))
                self.assertIsNone(omitted)
                self.assertTrue(parses(out))


class SerializedPassKeepsJson(unittest.TestCase):
    def test_no_cross_field_damage(self):
        for i, obj in enumerate([{"url": "https://example.invalid", "pkg": "@scope/x"},
                                 {"secret_mode": False, "note": "x"},
                                 {"a": "token=", "b": "x"},
                                 {"a": "password:", "b": {"c": "d"}},
                                 {"m": "ok", "n": "-----BEGIN RSA " + "PRIVATE KEY-----"}]):
            with self.subTest(case=i):
                out, _, omitted = run(obj)
                self.assertIsNone(omitted)
                self.assertTrue(parses(out))
                got = json.loads(out)
                self.assertEqual(sorted(got), sorted(obj))
        out, _, _ = run({"url": "https://example.invalid", "pkg": "@scope/x"})
        self.assertEqual(json.loads(out), {"url": "https://example.invalid", "pkg": "@scope/x"})


CLEAN_RECORDS = [
    {"parentUuid": None, "isSidechain": False, "userType": "external", "cwd": "/home/runner/repo",
     "version": "2.1.0", "gitBranch": "main", "type": "user", "uuid": "550e8400-e29b-41d4-a716-446655440000",
     "timestamp": "2026-11-22T02:14:13.084Z", "message": {"role": "user", "content": "please run the tests"}},
    {"type": "assistant", "message": {"model": "claude-x", "content": [
        {"type": "thinking", "thinking": "consider the passage", "signature": None},
        {"type": "text", "text": "Done. 12 tests passed in 3.21s; see file.py:123:45."},
        {"type": "tool_use", "id": "toolu_01", "name": "Bash", "input": {"command": "ls -la", "timeout": 120000}}],
        "usage": {"input_tokens": 12, "cache_creation_input_tokens": 0, "output_tokens": 345}}},
    {"timestamp": "2026-11-22T02:14:13.084Z", "type": "event_msg", "payload": {
        "type": "token_count", "info": {"total_token_usage": {"input_tokens": 1, "cached_input_tokens": 2,
                                                              "reasoning_output_tokens": 3}}}},
    {"result": {"pass": True, "fail": 0, "duration_ms": 1234, "path": "tests/test_x.py"}},
    {"type": "tool_result", "content": "a" * 50 + " total 48\ndrwxr-xr-x  5 runner  staff  160 Nov 22 10:15 ."},
    {"nested": json.dumps({"inner": {"k": "v", "n": 1.5}}), "list": [1, 2.5, "x", None, True]},
]


class Pass2AndFailClosed(unittest.TestCase):
    def tearDown(self):
        tr._pass1 = self._orig

    def setUp(self):
        self._orig = tr._pass1

    def test_pass2_catches_what_pass1_missed(self):
        tr._pass1 = lambda line: (line, {})
        out, counts, omitted = tr.redact_line(("note " + ANT).encode(), 7)
        self.assertIsNotNone(omitted)
        self.assertFalse(leaks(out, F, ANT_BODY))
        rec = json.loads(out)
        self.assertEqual(rec["_archive"], "omitted")
        self.assertEqual(rec["line"], 7)
        self.assertEqual(rec["reason"], omitted)
        self.assertEqual(rec["src_len"], len(("note " + ANT).encode()))
        self.assertEqual(sorted(rec), ["_archive", "line", "reason", "src_len"])  # no hash of the record

    def test_pass2_catches_aligned_assignments(self):
        """Delta gate on PR #316: column-aligned config (more than 4 spaces around = or :) must not slip past the
        verifier when pass 1 misses it."""
        tr._pass1 = lambda line: (line, {})
        for i, text in enumerate(ALIGNED[:-1]):  # pass 2 has no authorization-header rule (pass 1 only)
            with self.subTest(case=i):
                out, _, omitted = tr.redact_line(json.dumps({"t": text}).encode(), 3)
                self.assertIsNotNone(omitted)
                self.assertFalse(leaks(out, F))

    def test_pass2_catches_marker_abutting_value(self):
        tr._pass1 = lambda line: (line, {})
        out, _, omitted = tr.redact_line(b'{"t":"password=[REDACTED:x]' + F.encode() + b'"}', 3)
        self.assertIsNotNone(omitted)
        self.assertFalse(leaks(out, F))

    def test_exception_in_pass1_omits(self):
        def boom(line):
            raise RuntimeError("synthetic failure " + F)
        tr._pass1 = boom
        try:
            out, _, omitted = tr.redact_line(b'{"t":"x"}', 2)
        except Exception:  # never let a traceback carry the synthetic value
            self.fail("redact_line raised instead of failing closed")
        self.assertEqual(omitted, "error")
        self.assertFalse(leaks(out, F))
        self.assertEqual(json.loads(out)["line"], 2)

    def test_marker_holds_no_fragment(self):
        tr._pass1 = lambda line: (line, {})
        out, _, _ = tr.redact_line(("x " + ANT).encode(), 1)
        self.assertFalse(any(F[i:i + 6].encode() in out for i in range(len(F) - 5)))

    def test_omitted_markers_verify_clean(self):
        tr._pass1 = lambda line: (line, {})
        markers = [tr.redact_line(("x " + ANT).encode(), 1)[0],
                   tr.redact_line(b'{"t":"password=[REDACTED:x]' + F.encode() + b'"}', 2)[0]]
        tr._pass1 = self._orig
        markers.append(tr._omitted(b"src", 3, "error"))
        markers.append(tr._omitted(b"src", 4, "reserialize"))
        self.assertEqual(tr.verify_bytes(b"\n".join(markers) + b"\n"), [])

    def test_verify_bytes_reports_kind_and_line_only(self):
        data = b'{"a":1}\nclean text\nleak ' + ANT.encode() + b"\n"
        hits = tr.verify_bytes(data)
        self.assertTrue(len(hits) >= 1)
        self.assertTrue(all(line == 3 for _kind, line in hits))
        self.assertFalse(any(F in kind for kind, _ in hits))


class Properties(unittest.TestCase):
    def all_secret_inputs(self):
        items = [c[0] for c in TextShapes().cases()]
        items += [{"content": c[0]} for c in TextShapes().cases()]
        items += [{"input": {k: F}} for k in KeyedValues.KEYS]
        items += ["password=[REDACTED:x]" + F, "password\x1b[0m=" + F, "key sk-​ant-" + ANT_BODY,
                  "header Bearer%20" + F, {"content": json.dumps(json.dumps({"api_key": F}))}]
        return items

    def test_pass1_output_of_secret_corpus_verifies_clean(self):
        outputs = []
        for item in self.all_secret_inputs():
            out, _, omitted = run(item)
            self.assertIsNone(omitted)
            outputs.append(out)
        self.assertEqual(tr.verify_bytes(b"\n".join(outputs) + b"\n"), [])

    def test_clean_records_round_trip(self):
        for i, rec in enumerate(CLEAN_RECORDS):
            with self.subTest(case=i):
                out, counts, omitted = run(rec)
                self.assertIsNone(omitted)
                self.assertEqual(json.loads(out), rec)
                self.assertEqual(counts, {})

    def test_neg18_mapping_fields_survive(self):
        # NEG-18 (AC-10): a Claude-shaped record keeps its mapping fields; a session token is still redacted.
        rec = {"parentUuid": "550e8400-e29b-41d4-a716-446655440000", "sessionId": "6fa459ea-ee8a-3ca4-894e-db77e160355e",
               "uuid": "7c9e6679-7425-40de-944b-e07fc1f90ae7", "requestId": "01ARZ3NDEKTSV4RRFFQ69G5FAV",
               "type": "assistant", "message": {"model": "claude-x", "max_tokens": 4096,
                                                "usage": {"input_tokens": 12, "output_tokens": 345,
                                                          "cache_read_input_tokens": 0}},
               "token_count": 7, "sessionToken": F}
        out, counts, omitted = run(rec)
        self.assertIsNone(omitted)
        self.assertFalse(leaks(out, F))
        got = json.loads(out)
        self.assertEqual(got["sessionToken"], "[REDACTED:keyed]")
        del got["sessionToken"], rec["sessionToken"]
        self.assertEqual(got, rec)
        self.assertEqual(counts, {"keyed": 1})

    def test_codex_session_ids_survive(self):
        rec = {"type": "session_meta", "payload": {"id": "01ARZ3NDEKTSV4RRFFQ69G5FAV",
               "session_id": "550e8400-e29b-41d4-a716-446655440000",
               "parent_thread_id": "6fa459ea-ee8a-3ca4-894e-db77e160355e", "forked_from_id": None}}
        out, counts, omitted = run(rec)
        self.assertIsNone(omitted)
        self.assertEqual(json.loads(out), rec)
        self.assertEqual(counts, {})

    def test_neg18_allowlist_holds_only_for_its_value_shape(self):
        out, _, omitted = run({"tokens": ["opaque"], "sessionId": "not-a-uuid-" + F, "model": "m" * 70,
                               "type": "has spaces " + F2, "max_tokens": "str" + F3, "session": F2})
        self.assertIsNone(omitted)
        self.assertFalse(leaks(out, F, F2, F3, "opaque", "m" * 70))
        got = json.loads(out)
        for key in ("tokens", "sessionId", "model", "type", "max_tokens", "session"):
            with self.subTest(key=key):
                self.assertEqual(got[key], "[REDACTED:keyed]")

    def test_allowlist_exempts_only_the_keyed_rule(self):
        # Text shapes still apply to an allowlisted value; pass 2 still verifies it.
        out, _, omitted = run({"model": "someone@example.invalid"})
        self.assertIsNone(omitted)
        self.assertEqual(json.loads(out)["model"], "[REDACTED:email]")

    def test_session_keys_with_non_id_values_are_redacted(self):
        out, _, _ = run({"sessionId": F, "session": F2, "session_id": "not-a-uuid-" + F3})
        self.assertFalse(leaks(out, F, F2, F3))

    def test_determinism(self):
        for i, item in enumerate(self.all_secret_inputs()[:20] + CLEAN_RECORDS):
            with self.subTest(case=i):
                results = {run(item, 5)[0] for _ in range(3)}
                self.assertEqual(len(results), 1)

    def test_invalid_utf8_line(self):
        raw = b"plain \xff\xfe text " + ANT.encode() + b" tail \xc3"
        out1, _, omitted = tr.redact_line(raw, 1)
        out2, _, _ = tr.redact_line(raw, 1)
        self.assertEqual(out1, out2)
        self.assertIsNone(omitted)
        self.assertFalse(leaks(out1, F))
        self.assertTrue(out1.startswith(b"plain \xff\xfe text "))
        out3, _, _ = tr.redact_line(b'{"a":"\xff' + ANT.encode() + b'"}', 1)
        self.assertFalse(leaks(out3, F))

    def test_lone_surrogate_escape(self):
        raw = b'{"a":"x\\ud800y","b":"ok"}'
        out, _, omitted = tr.redact_line(raw, 1)
        self.assertIsNone(omitted)
        self.assertEqual(json.loads(out.decode("utf-8")), json.loads(raw.decode("utf-8")))

    def test_no_newline_is_stripped(self):
        # redact_line takes a record WITHOUT its trailing newline and strips nothing itself: a newline inside the
        # input fails closed instead of being silently removed, and output never ends with a newline.
        out, _, omitted = tr.redact_line(b'{"a":"x"}\n', 4)
        self.assertEqual(omitted, "embedded-newline")
        self.assertEqual(json.loads(out)["line"], 4)
        out, _, omitted = tr.redact_line(b"plain text with trailing spaces  ", 1)
        self.assertEqual(out, b"plain text with trailing spaces  ")
        out, _, _ = tr.redact_line(b'{"a":"x"}', 1)
        self.assertFalse(out.endswith(b"\n"))

    def test_ruleset_version(self):
        self.assertTrue(isinstance(tr.RULESET_VERSION, str) and tr.RULESET_VERSION not in ("", "0"))

    def test_five_megabyte_line_is_linear(self):
        parts = ["the quick brown fox 12 jumps over file.py:12:3 " * 20000,
                 "\n" * 400000,
                 "a-" * 300000,
                 ((("Ab3_-" * 200)[:999] + " ") * 1000),
                 "{" * 200000 + "eyJabcdefghij." * 20000]
        text = "".join(parts)
        text = (text * (5_000_000 // len(text) + 1))[:5_000_000]
        line = json.dumps({"content": text}).encode()
        start = time.process_time()
        out, _, omitted = tr.redact_line(line, 1)
        elapsed = time.process_time() - start
        self.assertLess(elapsed, 3.0)
        self.assertIsNone(omitted)

    def test_keyword_dense_input_scales_linearly(self):
        # A quadratic shape costs 16x for 4x input; allow up to 8x for timing noise on a loaded host.
        for i, unit in enumerate(["password=x ", '\\"password\\": ', "mysql -u x ", "Authorization: "]):
            with self.subTest(case=i):
                timings = []
                for size in (250_000, 1_000_000):
                    line = json.dumps({"c": (unit * (size // len(unit) + 1))[:size]}).encode()
                    best = None
                    for _ in range(2):
                        start = time.process_time()
                        tr.redact_line(line, 1)
                        took = time.process_time() - start
                        best = took if best is None else min(best, took)
                    timings.append(max(best, 0.01))
                self.assertLess(timings[1] / timings[0], 8.0)

    def test_files_pass_leak_scan_rules(self):
        spec = importlib.util.spec_from_file_location("leak_scan_mod", ROOT / "scripts" / "leak_scan.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        for path in (ROOT / "harness" / "hooks" / "transcript_redact.py", Path(__file__)):
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                with self.subTest(file=path.name, line=number):
                    self.assertEqual(mod.check_line(line, []), [])


def nested_record(depth, bottom):
    """A record whose message holds `bottom` JSON-encoded inside a string `depth` times (each layer an object)."""
    payload = bottom
    for _ in range(depth):
        payload = json.dumps({"data": payload}, separators=(",", ":"))
    return {"type": "user", "message": {"role": "user", "content": payload}}


class NestLimitFailsClosed(unittest.TestCase):
    """Gate F2 (PR #316 run 123d8933): past MAX_NEST both passes must omit, never fall back to text shapes."""
    BOTTOMS = [{"apiKeys": [F]}, {"tokenString": F2}, {"passwords": [F3]}, {"login": {"user": "x", "pw": F}}]

    def setUp(self):
        self._orig = tr._pass1

    def tearDown(self):
        tr._pass1 = self._orig

    def test_at_the_limit_key_aware_rules_still_apply(self):
        for i, bottom in enumerate(self.BOTTOMS):
            with self.subTest(case=i):
                out, counts, omitted = run(nested_record(tr.MAX_NEST, bottom))
                self.assertFalse(leaks(out, F, F2, F3))
                self.assertIsNone(omitted)  # depth 8 is decoded and redacted, not omitted
                self.assertTrue(parses(out))

    def test_past_the_limit_the_record_is_omitted(self):
        for depth in (tr.MAX_NEST + 1, 20):
            for i, bottom in enumerate(self.BOTTOMS):
                with self.subTest(depth=depth, case=i):
                    out, counts, omitted = run(nested_record(depth, bottom))
                    self.assertFalse(leaks(out, F, F2, F3))
                    self.assertEqual(omitted, "nest-limit")
                    self.assertEqual(counts, {})

    def test_pass2_alone_bails_closed_past_the_limit(self):
        tr._pass1 = lambda line: (line, {})
        for depth in (tr.MAX_NEST + 1, 20):
            with self.subTest(depth=depth):
                out, _, omitted = run(nested_record(depth, {"apiKeys": [F]}))
                self.assertFalse(leaks(out, F))
                self.assertEqual(omitted, "nest-limit")

    def test_verify_bytes_reports_the_kind(self):
        line = json.dumps(nested_record(20, {"apiKeys": [F]}), separators=(",", ":")).encode()
        self.assertEqual(tr.verify_bytes(line + b"\n"), [("nest-limit", 1)])

    def test_clean_deep_json_is_omitted_too(self):
        # fail closed: past the limit there is no key-aware judgement, so even a clean deep object is omitted
        _, _, omitted = run(nested_record(tr.MAX_NEST + 1, {"note": "nothing secret"}))
        self.assertEqual(omitted, "nest-limit")

    def test_plain_strings_at_the_limit_keep_text_rules(self):
        out, _, omitted = run(nested_record(tr.MAX_NEST, "just text " + ANT))
        self.assertFalse(leaks(out, ANT_BODY))
        self.assertIsNone(omitted)

    def test_decode_nested_contract(self):
        deep = json.dumps(json.dumps(json.dumps({"apiKeys": [F]})))  # quoted layers wrapping an object
        with self.assertRaises(tr._Omit):
            tr._decode_nested(deep, tr.MAX_NEST)
        with self.assertRaises(tr._Omit):
            tr._decode_nested('[1, 2]', tr.MAX_NEST)
        self.assertIs(tr._decode_nested('"plain"', tr.MAX_NEST), tr._MISSING)
        self.assertIs(tr._decode_nested("not json", 0), tr._MISSING)
        self.assertIs(tr._decode_nested("42", 0), tr._MISSING)
        self.assertEqual(tr._decode_nested('{"a": 1}', tr.MAX_NEST - 1), {"a": 1})

    def test_max_nest_is_read_only_by_the_one_owner(self):
        """Guard: every pass reaches the limit through _decode_nested, so no pass can fall back on its own."""
        import ast
        tree = ast.parse((ROOT / "harness" / "hooks" / "transcript_redact.py").read_text(encoding="utf-8"))
        readers = set()
        for fn in ast.walk(tree):
            if isinstance(fn, ast.FunctionDef):
                for node in ast.walk(fn):
                    if isinstance(node, ast.Name) and node.id == "MAX_NEST":
                        readers.add(fn.name)
        self.assertEqual(readers, {"_decode_nested"})


if __name__ == "__main__":
    unittest.main()
