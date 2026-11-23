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

    def test_nested_containers_under_a_key_are_replaced_whole(self):
        out, _, omitted = run({"credentials": {"user": "u1", "inner": [F, {"deeper": F2}]}, "other": 1})
        self.assertIsNone(omitted)
        self.assertFalse(leaks(out, F, F2))
        self.assertEqual(json.loads(out)["credentials"], "[REDACTED:keyed]")
        self.assertEqual(json.loads(out)["other"], 1)

    def test_numeric_secret_redacted_but_booleans_and_null_kept(self):
        out, _, _ = run({"otp": 918273, "pass": True, "token": None})
        obj = json.loads(out)
        self.assertEqual(obj["otp"], "[REDACTED:keyed]")
        self.assertIs(obj["pass"], True)
        self.assertIsNone(obj["token"])

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
        self.assertEqual(rec["src_sha256"], hashlib.sha256(("note " + ANT).encode()).hexdigest())

    def test_pass2_catches_marker_abutting_value(self):
        tr._pass1 = lambda line: (line, {})
        out, _, omitted = tr.redact_line(b'{"t":"password=[REDACTED:x]' + F.encode() + b'"}', 3)
        self.assertIsNotNone(omitted)
        self.assertFalse(leaks(out, F))

    def test_exception_in_pass1_omits(self):
        def boom(line):
            raise RuntimeError("synthetic failure " + F)
        tr._pass1 = boom
        out, _, omitted = tr.redact_line(b'{"t":"x"}', 2)
        self.assertEqual(omitted, "error")
        self.assertFalse(leaks(out, F))
        self.assertEqual(json.loads(out)["line"], 2)

    def test_marker_holds_no_fragment(self):
        tr._pass1 = lambda line: (line, {})
        out, _, _ = tr.redact_line(("x " + ANT).encode(), 1)
        self.assertFalse(any(F[i:i + 6].encode() in out for i in range(len(F) - 5)))

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

    def test_session_id_is_redacted_as_specified(self):
        out, _, _ = run({"sessionId": "550e8400-e29b-41d4-a716-446655440000", "type": "user"})
        self.assertEqual(json.loads(out)["sessionId"], "[REDACTED:keyed]")

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


if __name__ == "__main__":
    unittest.main()
