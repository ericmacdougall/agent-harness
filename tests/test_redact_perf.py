"""Linear-time guard for redact.PATTERNS (GoodQA #16680).

The rclone-token shape (`^\\s*token`) rescanned every line start on a run of newlines, and the first
named-credential shape (`(?:[a-z0-9]+[_-])*` prefix) restarted at every word boundary of a hyphenated run. On
100 KB inputs they took about 52 s and 224 s. Each adversarial 100 KB input must now finish in under 1 s of CPU.
"""
import random
import re
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "harness" / "hooks"))
import redact  # noqa: E402

SIZE = 100_000
ADVERSARIAL = {
    "newline-run": "\n" * SIZE,
    "space-newline-run": " \n" * (SIZE // 2),
    "hyphen-run": "a-" * (SIZE // 2),
    "underscore-hyphen-run": "a_b-" * (SIZE // 4),
    "token-lines": "token\n" * (SIZE // 6),
    "camel-run": "aB" * (SIZE // 2),
    "underscore-run": "a_" * (SIZE // 2),
    "underscore-keyword-run": "a_password_" * (SIZE // 11),
    "long-segment-run": ("a" * 200 + "_") * (SIZE // 201),
}

# The pre-#16680 shapes, kept only as the differential baseline: every value they redacted must still be redacted.
_OLD_KEYS = (r'(?:[a-z0-9]+[_-])*(?:password|passwd|passphrase|secret|token|api[_-]?key|access[_-]?key|'
             r'private[_-]?key|credentials?|client[_-]?secret|refresh[_-]?token|access[_-]?token|id[_-]?token)'
             r'(?:[_-]value)?')
OLD = {"rclone": re.compile(r'(?im)^\s*token\s*=\s*\{[^\n]{0,8192}'),
       "named": re.compile(r'(?i)\b' + _OLD_KEYS
                                      + r'[\x22\x27]?\s*[:=]\s*[\x22\x27]?[^\s\x22\x27,;}]{3,512}')}
ATOMS = [" ", "\t", "\n", "\r", "\x0b", "\x0c", "token", "TOKEN", "=", ":", "{", "}", '"', "'", "-", "_", "a", "my",
         "x1", "secret", "password", "api_key", "value", "Zq9Xw2Lm", ",", ";", "id", "access"]
VALUE = "Zq9X" + "w2Lm8Rt4" + "Vb7Np3Kc6"  # synthetic
EDGES = {
    "40 underscore segments": "_".join(["a"] * 40) + "_password=" + VALUE,
    "40 hyphen segments": "-".join(["a"] * 40) + "-password=" + VALUE,
    "300-char segment": "a" * 300 + "_password=" + VALUE,
    "17 long segments": "_".join(["b" * 130] * 17) + "_secret: " + VALUE,
    "100-space indent": " " * 100 + "token = {" + VALUE + "}",
    "vertical-tab indent": "\x0btoken = {" + VALUE + "}",
    "form-feed indent": "\x0ctoken = {" + VALUE + "}",
    "carriage-return indent": "\rtoken = {" + VALUE + "}",
    "100 spaces before =": "token" + " " * 100 + "= {" + VALUE + "}",
    "100 newlines before =": "token" + "\n" * 100 + "= {" + VALUE + "}",
    "100 spaces after separator": "password" + " " * 100 + "= " + VALUE,
}



def _archive(text):
    import json
    import transcript_redact
    line = json.dumps({"type": "user", "message": {"role": "user", "content": text}}).encode()
    return transcript_redact.redact_line(line, 1)[0]


def _new_cover(text):
    cover = bytearray(len(text))
    for _, pattern in redact.PATTERNS:
        for m in pattern.finditer(text):
            cover[m.start():m.end()] = b"\x01" * (m.end() - m.start())
    return cover


def _uncovered_old_values(text):
    """Old matches whose value (the text after the separator, less spaces, quotes and braces) has a character no
    current pattern covers."""
    missed = []
    cover = None
    for kind, pattern in OLD.items():
        for m in pattern.finditer(text):
            body = m.group(0)
            sep = body.find("=") if kind == "rclone" else max(body.rfind("="), body.find(":"))
            if cover is None:
                cover = _new_cover(text)
            value = range(m.start() + sep + 1, m.end())
            if not all(cover[i] for i in value if not text[i].isspace() and text[i] not in "\"'{}"):
                missed.append(kind)
    return missed


class PatternsAreLinear(unittest.TestCase):
    def test_each_pattern_on_adversarial_input(self):
        for name, text in ADVERSARIAL.items():
            for kind, pattern in redact.PATTERNS:
                with self.subTest(input=name, kind=kind):
                    start = time.process_time()
                    for _ in pattern.finditer(text):
                        pass
                    self.assertLess(time.process_time() - start, 1.0)

    def test_redact_and_find_on_adversarial_input(self):
        for name, text in ADVERSARIAL.items():
            with self.subTest(input=name):
                start = time.process_time()
                redact.redact(text)
                self.assertLess(time.process_time() - start, 2.0)

    def test_coverage_kept_for_long_and_prefixed_names(self):
        value = "Zq9X" + "w2Lm8Rt4" + "Vb7Np3Kc6"
        for i, text in enumerate(["DB_PASSWORD=" + value, "a_b_c_d_e_f_g_h_i_j_secret=" + value,
                                  "my-app-client-secret: " + value, "token = {\"access\": \"" + value + "\"}",
                                  "  token = {" + value + "}", "x-api-key=" + value, "refresh_token_value=" + value]):
            with self.subTest(case=i):
                self.assertFalse(value in redact.redact(text))


    def test_redacts_names_beyond_the_scan_window(self):
        """Delta gate on #16680: underscores are word characters, so a long underscore name has no later \\b to start
        from; the bounded scan must still reach the key word (it may also start right after _ or -)."""
        for name, text in EDGES.items():
            with self.subTest(case=name):
                self.assertNotIn(VALUE, redact.redact(text))

    def test_every_value_the_old_patterns_redacted_is_still_redacted(self):
        """Differential: on the named edges and 30 000 seeded random inputs over the shapes' alphabet, every old
        rclone-token / named-credential match has its value covered by the current PATTERNS."""
        for name, text in EDGES.items():
            with self.subTest(case=name):
                self.assertEqual(_uncovered_old_values(text), [])
        rng = random.Random(16680)
        misses = []
        for _ in range(30000):
            text = "".join(rng.choice(ATOMS) for _ in range(rng.randint(2, 14)))
            if _uncovered_old_values(text):
                misses.append(text)
        self.assertEqual(misses[:5], [])

    def test_archive_path_redacts_the_window_edges(self):
        """transcript_redact skips this shape for its own prefix-free keyword rule; the edges must still be redacted
        on the archive path. Every edge is a NEG: "17 long segments" was a pinned known gap at 79d55675 (the base64
        collapse swallowed the key word) and is now required to pass."""
        for name, text in EDGES.items():
            with self.subTest(case=name):
                self.assertNotIn(VALUE.encode(), _archive(text))

    def test_find_scales_linearly_without_chunks(self):
        """find() scans the whole text since the chunking was removed (GoodQA #16680), so the 256 KiB chunk no
        longer caps a superlinear pattern: every adversarial input at 2 MB may cost at most 3x its 1 MB CPU."""
        for name, text in ADVERSARIAL.items():
            with self.subTest(input=name):
                cost = []
                for size in (1_000_000, 2_000_000):
                    big = (text * (size // len(text) + 1))[:size]
                    start = time.process_time()
                    redact.find(big)
                    cost.append(max(time.process_time() - start, 0.05))
                self.assertLess(cost[1], 20.0)
                self.assertLess(cost[1] / cost[0], 3.0)

    def test_archive_scales_linearly_on_long_runs(self):
        """The keyword rules now see long base64 runs uncollapsed (triage of PR #316 at 79d55675), so the archive
        path must stay linear on them: 2 MB may cost at most 3x the CPU of 1 MB, and 2 MB stays under 20 s."""
        import base64
        rnd = random.Random(16650)
        blob = rnd.randbytes(1_600_000)
        shapes = {
            "base64": lambda n: base64.b64encode(blob).decode()[:n],
            "base64url": lambda n: base64.urlsafe_b64encode(blob).decode()[:n],
            "jwt-dense": lambda n: ("eyJaaaaaaaa-" * (n // 12 + 1))[:n],
            "dot-joined eyJ": lambda n: ("eyJaaaaaaaa." * (n // 12 + 1))[:n],
            "underscore-keyword": lambda n: ("bb_password_" * (n // 12 + 1))[:n],
        }
        for name, make in shapes.items():
            with self.subTest(shape=name):
                cost = []
                for size in (1_000_000, 2_000_000):
                    text = make(size)
                    start = time.process_time()
                    _archive(text)
                    cost.append(max(time.process_time() - start, 0.05))
                self.assertLess(cost[1], 20.0)
                self.assertLess(cost[1] / cost[0], 3.0)

    def test_archive_patterns_on_adversarial_input(self):
        """The archive's separator whitespace is bounded (256) and every such rule starts at a key word."""
        import transcript_redact
        inputs = dict(ADVERSARIAL, **{"aligned-run": ("password" + " " * 300) * (SIZE // 308),
                                      "aligned-colon-run": ("api_key:" + "\t" * 300) * (SIZE // 308)})
        for name, text in inputs.items():
            with self.subTest(input=name):
                start = time.process_time()
                transcript_redact._find_spans(text)
                self.assertLess(time.process_time() - start, 2.0)

    def test_no_new_named_credential_findings_on_ordinary_code(self):
        """The wider start only reaches inside long names: on this repo's own text files every match of the first
        named-credential shape ends where an old-form match ends (scanners such as ahc_scan gain no findings),
        and a bare leading underscore is still not a start."""
        new = next(p for k, p in redact.PATTERNS if k == "named-credential")
        for text in ("self._token = load_token()", "x._password = get()", "obj.__secret__: dict",
                     "_PATH_TOKEN = re.compile(r'x')"):
            with self.subTest(text=text):
                self.assertEqual([m.group(0) for m in OLD["named"].finditer(text)], [])
                self.assertEqual([m.group(0) for m in new.finditer(text)], [])
        root = Path(__file__).resolve().parents[1]
        extra = {}
        for path in sorted(root.rglob("*")):
            rel = path.relative_to(root).parts
            if (not path.is_file() or rel[0] in (".git", "node_modules") or path.suffix not in
                    (".py", ".md", ".json", ".sh", ".txt", ".toml", ".yml", ".yaml")
                    or path.stat().st_size > 1_000_000):
                continue
            text = path.read_text("utf-8", "replace")
            old_ends = {m.end() for m in OLD["named"].finditer(text)}
            added = sum(1 for m in new.finditer(text) if m.end() not in old_ends)
            if added:
                extra["/".join(rel)] = added
        self.assertEqual(extra, {})


if __name__ == "__main__":
    unittest.main()
