"""ahc_scan: the R5 report scanner (goodqa#16049 spec ahc-m1-v2g7 R5, NEG-21 scan half, harvest idea 4, and the
spec owner's tiering and corpus rulings).

Every secret here is built at run time from a seeded generator and the scanner's own split prefixes; this file
holds no token-shaped literal, and the clean-corpus test checks that (it scans this file too)."""
import base64
import binascii
import hashlib
import json
import random
import re
import subprocess
import sys
import tempfile
import unittest
import urllib.parse
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "harness" / "hooks"))
import ahc_scan as S  # noqa: E402

SEED = 16049
EXEMPT = ROOT / "tests" / "data" / "ahc_scan_corpus_exempt.json"
ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
PREFIX = dict(S.PREFIXES)


def own(findings):
    """The scanner's own-rule findings, without the redactor floor (tests of a rule's own semantics)."""
    return [f for f in findings if not f["rule"].startswith(S.FLOOR)]


def corpus_files(root=ROOT):
    """The repo's own .py and .md files and its test fixtures (tests/data, R5): the tracked ones when git is there,
    else a walk skipping dot dirs."""
    try:
        out = subprocess.run(["git", "-C", str(root), "ls-files", "-z", "*.py", "*.md", "tests/data/*"],
                             capture_output=True, check=True).stdout
        return sorted(p for p in out.decode().split("\0") if p)
    except (OSError, subprocess.CalledProcessError):
        return sorted(str(p.relative_to(root)) for p in root.rglob("*") if (p.suffix in (".py", ".md") or
                      p.relative_to(root).parts[:2] == ("tests", "data"))
                      and p.is_file() and not any(part.startswith(".") or part in ("node_modules", "__pycache__")
                                                  for part in p.relative_to(root).parts))


def corpus_counts(root=ROOT, files=None):
    """{path: {rule[:prefix]: count}} for every corpus file with at least one finding."""
    counts = {}
    for rel in files if files is not None else corpus_files(root):
        path = Path(root) / rel
        if not path.is_file():
            continue
        findings = S.scan_report(path.read_bytes(), rel)
        if findings:
            counts[rel] = dict(sorted(Counter(f["rule"] + ("" if f["exposure"] else ":prefix")
                                              for f in findings).items()))
    return counts


class Secrets:
    def __init__(self, seed=SEED):
        self.rng = random.Random(seed)

    def body(self, n):
        """n random alphanumerics with every class present (so a body is never hex-only)."""
        while True:
            s = "".join(self.rng.choice(ALNUM) for _ in range(n))
            if n < 3 or (any(c.isupper() for c in s) and any(c.islower() for c in s) and any(c.isdigit() for c in s)):
                return s

    def token(self, kind, n=36):
        return PREFIX[kind] + self.body(n)

    def jwt(self):
        enc = lambda obj: base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()  # noqa: E731
        return ".".join([enc({"alg": "HS256", "typ": "J" + "WT"}), enc({"sub": self.body(12), "n": 7}),
                         self.body(43)])


class PrefixWindowTests(unittest.TestCase):
    def setUp(self):
        self.s = Secrets()

    def only(self, text):
        findings = own(S.scan_report(text.encode()))
        self.assertEqual(len(findings), 1, findings)
        return findings[0]

    def test_byte_boundary_pairs_only_the_8_byte_one_is_an_exposure(self):
        for kind in PREFIX:
            with self.subTest(kind=kind):
                seven = self.only("see %s here" % (PREFIX[kind] + self.s.body(7)))
                eight = self.only("see %s here" % (PREFIX[kind] + self.s.body(8)))
                self.assertEqual((seven["rule"], seven["exposure"], seven["severity"]), (kind, False, "block"))
                self.assertEqual((eight["rule"], eight["exposure"], eight["severity"]), (kind, True, "block"))

    def test_a_bare_public_prefix_is_a_block_but_not_an_exposure(self):
        for kind in PREFIX:
            with self.subTest(kind=kind):
                f = self.only("the `%s` prefix" % PREFIX[kind])
                self.assertEqual((f["rule"], f["exposure"]), (kind, False))

    def test_separators_inside_a_value_are_stripped_before_the_window(self):
        b = self.s.body(12)
        split = "-".join(b[i:i + 3] for i in range(0, 12, 3))          # 3 alnum, '-', 3 alnum ...
        f = self.only("value %s%s end" % (PREFIX["github-classic"], split))
        self.assertTrue(f["exposure"], "separators do not hide the 12 alphanumerics")

    def test_the_longest_prefix_names_the_kind(self):
        self.assertEqual(self.only(self.s.token("anthropic"))["rule"], "anthropic")
        self.assertEqual(self.only(self.s.token("openai-project"))["rule"], "openai-project")

    def test_a_prefix_counts_only_at_a_word_boundary(self):
        words = "a risk" + "-based plan, the task" + "-ant-thing and a whisk" + "-proj-x; xghp" + "_y"
        self.assertEqual(S.scan_report(words.encode()), [])

    def test_line_numbers(self):
        text = "one\ntwo\n%s\nfour\n" % self.s.token("github-classic")
        self.assertEqual(self.only(text)["line"], 3)


class EncodingTests(unittest.TestCase):
    def setUp(self):
        self.s = Secrets()
        self.tok = self.s.token("github-fine-grained", 40)

    def encoded(self, encoding):
        b = self.tok.encode()
        return {"hex": binascii.hexlify(b).decode(), "base64": base64.b64encode(b).decode(),
                "base64-urlsafe": base64.urlsafe_b64encode(b).decode().rstrip("="),
                "url": "".join("%%%02X" % c for c in b)}[encoding]       # every byte percent-encoded

    def test_each_listed_encoding_is_decoded_and_scanned(self):
        for encoding in ("hex", "base64", "base64-urlsafe", "url"):
            with self.subTest(encoding=encoding):
                findings = S.scan_report(("line one\nx = %s\n" % self.encoded(encoding)).encode())
                hits = [f for f in findings if f["rule"] == "github-fine-grained"]
                self.assertTrue(hits, findings)
                self.assertTrue(hits[0]["exposure"])
                self.assertEqual(hits[0]["encoding"], encoding.split("-")[0])
                self.assertEqual(hits[0]["line"], 2)

    def test_url_encoding_of_a_whole_value_with_separators(self):
        value = PREFIX["anthropic"] + "api03-" + self.s.body(20)
        findings = S.scan_report(urllib.parse.quote("key=" + value, safe="").encode())
        self.assertTrue(any(f["rule"] == "anthropic" and f["exposure"] for f in findings), findings)

    def test_jwt_shape(self):
        f = S.scan_report(("Authorization: %s\n" % self.s.jwt()).encode())
        self.assertTrue(any(x["rule"] == "jwt" and x["exposure"] for x in f), f)


class EntropyTests(unittest.TestCase):
    def setUp(self):
        self.s = Secrets()

    def test_a_long_random_mixed_run_is_an_exposure(self):
        for n in (32, 40, 64):
            with self.subTest(n=n):
                f = S.scan_report(("value: %s\n" % self.s.body(n)).encode())
                self.assertEqual([(x["rule"], x["exposure"]) for x in f], [("high-entropy", True)])

    def test_a_base64_blob_of_random_bytes_is_an_exposure(self):
        blob = base64.b64encode(bytes(self.s.rng.randrange(256) for _ in range(48))).decode()
        if "+" not in blob:
            blob = blob[:10] + "+" + blob[11:]
        f = S.scan_report(blob.encode())
        self.assertIn(("high-entropy", True), [(x["rule"], x["exposure"]) for x in f])

    def test_an_encoded_opaque_value_is_an_exposure(self):
        """v2g9 adversarial round 3 F4: entropy applies to decoded content, so encoding cannot hide a value."""
        for n in (32, 64):
            value = self.s.body(n).encode()
            for name, blob in (("hex", binascii.hexlify(value)), ("hex-upper", binascii.hexlify(value).upper()),
                               ("base64", base64.b64encode(value)), ("base64url", base64.urlsafe_b64encode(value)),
                               ("url", urllib.parse.quote_from_bytes(b"k=" + value + b"&", safe="").encode())):
                with self.subTest(n=n, encoding=name):
                    f = S.scan_report(b"value: " + blob + b"\n")
                    self.assertEqual(S.verdict(f)["action"], S.QUARANTINE, f)

    def test_benign_encoded_data_stays_clean(self):
        import hashlib
        digest = hashlib.sha256(self.s.body(40).encode()).digest()
        prose = (b"the release notes say the queue drains in order and every owner is told when its item "
                 b"settles, which is what the reviewers asked for")
        for name, blob in (("sha256 hex", binascii.hexlify(digest)), ("sha256 HEX", binascii.hexlify(digest).upper()),
                           ("base64 prose", base64.b64encode(prose)), ("hex prose", binascii.hexlify(prose))):
            with self.subTest(case=name):
                self.assertEqual(S.scan_report(b"x " + blob + b"\n"), [])

    def test_ordinary_shapes_are_not_high_entropy(self):
        hexsha = "".join(self.s.rng.choice("0123456789abcdef") for _ in range(64))
        cases = {
            "hex digest": hexsha,
            "upper hex digest": hexsha.upper(),
            "sorted flag table": "0123456789EFGHILPRSTUVWYabchijklnopqrsuvwxyz",
            "alphabet listing": ALNUM,
            "reverse alphabet": ALNUM[::-1],
            "distinct-character flag set": "".join(self.s.rng.sample(ALNUM, 45)),
            "a path": "/Users/someone/Work/Project-2026/src/Module_v2/TestCase9/file.py",
            "NAME=value": "HARNESS_WORKTREE_GATE=off-for-Tests-2026",
            "an identifier": "test_explicit_base_equal_to_head_is_omitted_and_refused_with_base",
            "short random": self.s.body(31),
        }
        for name, text in cases.items():
            with self.subTest(name):
                self.assertEqual(S.scan_report(text.encode()), [])


class RedactShapeTests(unittest.TestCase):
    """The spec owner's follow-up: redact.py's specific shapes the first slice left clean. Values are built here."""

    def setUp(self):
        self.s = Secrets(SEED + 1)

    def rules(self, text):
        return [(f["rule"], f["exposure"]) for f in own(S.scan_report(("x " + text + "\n").encode()))]

    def test_the_floor_never_lets_a_tier_fall_below_the_redactor(self):
        """Where the redactor's own minimum is shorter than the 8-byte window (Slack: 6), its detection wins."""
        import redact
        value = "xo" + "xb-" + self.s.body(7)
        self.assertTrue(redact.find(value))
        self.assertEqual(self.rules(value), [("slack", False)])                  # own rule: prefix only
        self.assertEqual(S.verdict(S.scan_report(("x " + value + "\n").encode()))["action"], S.QUARANTINE)

    def test_every_new_prefix_quarantines_with_a_value_and_restricts_alone(self):
        new = {"aws-key-id", "slack", "stripe", "gitlab"}
        prefixes = [(k, p) for k, p in S.PREFIXES if k in new]
        self.assertEqual({k for k, _ in prefixes}, new)
        self.assertEqual(len(prefixes), 2 + 6 + 4 + 1)
        for kind, prefix in prefixes:
            with self.subTest(prefix=kind + ":" + prefix[:2]):
                self.assertEqual(self.rules(prefix + self.body_for(kind, 16)), [(kind, True)])
                self.assertEqual(self.rules(prefix + self.body_for(kind, 7)), [(kind, False)])
                self.assertEqual(self.rules(prefix), [(kind, False)])

    def body_for(self, kind, n):
        if kind == "aws-key-id":                       # upper case and digits only, as the real shape is
            return "".join(self.s.rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(n))
        return self.s.body(n)

    def test_bearer_needs_8_token_characters_and_not_a_plain_word(self):
        word = "Be" + "arer "
        self.assertEqual(self.rules("Authorization: " + word + self.s.body(24)), [("bearer", True)])
        self.assertEqual(self.rules(word.lower() + self.s.body(8)), [("bearer", True)])
        self.assertEqual(self.rules(word + self.s.body(7)), [("bearer", False)])

    def test_bearer_own_rule_accepts_every_whitespace_separator(self):
        """BLOCK F1: the scanner's own rule matches the redactor's \\s+, not just spaces and tabs."""
        for name, sep in SEPARATORS.items():
            with self.subTest(sep=name):
                self.assertEqual(self.rules("Be" + "arer" + sep + self.s.body(12)), [("bearer", True)])

    def test_bearer_letters_only_values_quarantine_whatever_their_case(self):
        """v2g9 F4: letters-only values are valid token shapes; no plain-word exception, prose fails closed."""
        letters = "abcdefghijklmnopqrstuvwxyz"
        word = "Be" + "arer "
        for n in (8, 20, 32, 40, 64):
            lower = "".join(self.s.rng.choice(letters) for _ in range(n))
            cases = {"lower": lower, "title": lower[0].upper() + lower[1:],
                     "mixed": "".join(c.upper() if self.s.rng.random() < 0.5 else c for c in lower)}
            for name, value in cases.items():
                with self.subTest(n=n, case=name):
                    self.assertEqual(self.rules(word + value), [("bearer", True)])
                    self.assertEqual(S.verdict(S.scan_report((word + value + "\n").encode()))["action"],
                                     S.QUARANTINE)
        self.assertEqual(self.rules(word + "authorization"), [("bearer", True)])   # prose fails closed
        self.assertEqual(self.rules(word + "abcdefg"), [("bearer", False)])        # 7 characters: prefix only

    def test_url_userinfo_and_named_credentials_restrict_only(self):
        floor = lambda text: [(f["rule"], f["exposure"]) for f in S.scan_report(("x " + text + "\n").encode())]  # noqa
        self.assertEqual(floor("https://bob:" + self.s.body(12) + "@example.invalid/x"),
                         [(S.FLOOR + "url-userinfo", False)])
        self.assertEqual(floor("pass" + "word = " + self.s.body(12)), [(S.FLOOR + "named-credential", False)])
        self.assertEqual(S.verdict(S.scan_report(("pass" + "word = " + self.s.body(12)).encode()))["action"],
                         S.RESTRICT)

    def test_the_restrict_kinds_are_redactor_kinds(self):
        import redact
        self.assertEqual(S.REDACT_RESTRICT_KINDS, {"url-userinfo", "named-credential"})
        self.assertTrue(S.REDACT_RESTRICT_KINDS <= {k for k, _ in redact.PATTERNS})


def _redact_samples(s, low=False):
    """{kind: [(label, value)]}: one or more synthetic instances of every shape redact.py knows, built at run time
    from split literals (this file holds no token-shaped literal). The text scanned is label + SEP + value, so the
    separator forms below exercise each shape's own whitespace handling where the label is part of the shape."""
    rng = s.rng
    up = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    b64 = ALNUM + "/+"

    def r(n, alphabet=ALNUM):
        if low:     # repeated characters: entropy rules never fire, so only a shape rule (or the floor) catches it
            return ((alphabet[0] * 3 + alphabet[-1]) * n)[:n]
        return "".join(rng.choice(alphabet) for _ in range(n))

    begin, end = "-----BEG" + "IN RSA PRIVATE KEY-----", "-----EN" + "D RSA PRIVATE KEY-----"
    return {
        "rclone-token": [("to" + "ken =", "{\"access" + "_token\":\"" + r(30) + "\"}")],
        "oauth-json": [("{\"refresh" + "_token\":", "\"" + r(30) + "\"}")],
        "anthropic": [("key:", "sk" + "-ant-" + r(32))],
        "openai": [("key:", "sk" + "-proj-" + r(32))],
        "github": [("key:", "gh" + "p_" + r(36))],
        "aws-key-pair": [("AK" + "IA" + r(16, up), r(40, b64))],
        "aws-key": [("id:", "AK" + "IA" + r(16, up))],
        "aws-secret": [("aws_sec" + "ret_access_key =", r(40, b64))],
        "stripe": [("key:", "sk" + "_live_" + r(24))],
        "stripe-webhook": [("key:", "wh" + "sec_" + r(32))],
        "huggingface": [("key:", "h" + "f_" + r(34))],
        "gitlab": [("key:", "gl" + "pat-" + r(24))],
        "sendgrid": [("key:", "S" + "G." + r(22) + "." + r(43))],
        "google-oauth": [("key:", "ya" + "29." + r(40))],
        "google-api": [("key:", "AI" + "za" + r(35))],
        "google-refresh": [("key:", "1/" + "/" + r(40))],
        "dropbox": [("key:", "s" + "l." + r(60))],
        "slack": [("key:", "xo" + "xb-" + r(10, "0123456789") + "-" + r(24))],
        "npm": [("key:", "np" + "m_" + r(36))],
        "jwt": [("key:", s.jwt())],
        "bearer": [("Authorization: Be" + "arer", r(24)), ("Authorization: Be" + "arer", r(24, ALNUM[:52]))],
        "url-userinfo": [("url:", "https://bob:" + r(12) + "@example.invalid/x")],
        "named-credential": [("pass" + "word =", r(14)), ("dbPass" + "word =", r(14))],
        "pem": [(begin, "MIIE" + r(60, b64) + "\n" + r(60, b64) + "\n" + end)],
    }


SEPARATORS = {"space": " ", "tab": "\t", "lf": "\n", "crlf": "\r\n"}


def _wrapped(text, width=16):
    """The text hard-wrapped at spaces to `width` columns, as a pager or a mail client would wrap a report."""
    out, line = [], ""
    for word in text.split(" "):
        if line and len(line) + 1 + len(word) > width:
            out.append(line)
            line = word
        else:
            line = (line + " " + word) if line else word
    return "\n".join(out + [line])


class RedactParityTests(unittest.TestCase):
    """Main's direction after code-inspection BLOCK F1/F2: anything redact.py detects can never scan clean, in any
    whitespace or wrapping form or one encoding level deep. Generated from redact's own pattern table, so a new
    redactor kind without a sample here fails."""

    def setUp(self):
        import redact
        self.redact = redact
        random_ones, low_ones = _redact_samples(Secrets(SEED + 2)), _redact_samples(Secrets(SEED + 3), low=True)
        self.samples = {k: random_ones[k] + low_ones[k] for k in random_ones}

    def test_every_redactor_kind_has_a_sample(self):
        kinds = {kind for kind, _ in self.redact.PATTERNS} | {"pem"}
        self.assertEqual(sorted(kinds - set(self.samples)), [], "redactor kinds with no scanner parity sample")
        self.assertEqual(sorted(set(self.samples) - kinds), [], "samples for kinds the redactor no longer has")

    def forms(self, label, value):
        for name, sep in SEPARATORS.items():
            yield name, "x " + label + sep + value + " y\n"
        yield "wrapped", _wrapped("context words before " + label + " " + value + " and after") + "\n"

    def test_every_redactor_kind_is_never_clean_in_any_whitespace_form(self):
        for kind, instances in sorted(self.samples.items()):
            for i, (label, value) in enumerate(instances):
                self.assertTrue(self.redact.find(label + " " + value), "the %s sample is not a %s shape" % (kind, kind))
                for form, text in self.forms(label, value):
                    with self.subTest(kind=kind, instance=i, form=form):
                        findings = S.scan_report(text.encode())
                        self.assertNotEqual(S.verdict(findings)["action"], S.CLEAN)
                        self.assertNotEqual(S.outward(findings, text), text, "the excerpt never leaves")

    def test_every_redactor_kind_is_never_clean_one_encoding_deep(self):
        for kind, instances in sorted(self.samples.items()):
            for i, (label, value) in enumerate(instances):
                text = (label + " " + value).encode()
                for name, blob in (("base64", base64.b64encode(text)), ("base64url", base64.urlsafe_b64encode(text)),
                                   ("hex", binascii.hexlify(text)), ("hex-upper", binascii.hexlify(text).upper()),
                                   ("url", urllib.parse.quote_from_bytes(text, safe="").encode())):
                    with self.subTest(kind=kind, instance=i, encoding=name):
                        self.assertNotEqual(S.verdict(S.scan_report(b"x " + blob + b"\n"))["action"], S.CLEAN)

    def test_low_entropy_samples_get_no_help_from_the_entropy_rule(self):
        """Round 4 F4: segmented values whose every segment is below the entropy threshold (SendGrid's three
        segments among them) must still never be clean, so the floor, not entropy, is what catches them."""
        low = _redact_samples(Secrets(SEED + 3), low=True)
        for kind, instances in sorted(low.items()):
            if kind == "jwt":
                continue                                   # the JWT sample is random by construction
            for label, value in instances:
                with self.subTest(kind=kind):
                    for seg in re.split(r"[^A-Za-z0-9+/]", value):
                        self.assertLess(S._entropy(seg.encode()) if seg else 0, S.SEGMENT_BITS, seg[:4])
                    findings = S.scan_report(("x " + label + " " + value + "\n").encode())
                    self.assertNotIn("high-entropy", [f["rule"] for f in findings])
                    self.assertNotEqual(S.verdict(S.scan_report(("x " + label + " " + value + "\n").encode()))
                                        ["action"], S.CLEAN)

    def test_restrict_only_kinds_stay_restrict(self):
        for kind in ("url-userinfo", "named-credential"):
            label, value = self.samples[kind][0]
            with self.subTest(kind=kind):
                self.assertEqual(S.verdict(S.scan_report(("x " + label + " " + value + "\n").encode()))["action"],
                                 S.RESTRICT)


# ---------------------------------------------------------------- generated invariant tests (ahc_scan's I1-I3)

ALL_WHITESPACE = [chr(c) for c in range(0x110000) if re.match(r"\s", chr(c))]   # every character \s matches
RANK = {S.CLEAN: 0, S.RESTRICT: 1, S.QUARANTINE: 2}


def tier(data):
    return RANK[S.verdict(S.scan_report(data))["action"]]


def redactor_tier(text):
    """The tier the redactor alone implies for `text`: quarantine for any exposure kind, restrict when it finds
    only restrict-tier kinds, clean when it finds nothing."""
    kinds = {kind for kind, _s, _e in __import__("redact").find(text)}
    if not kinds:
        return 0
    return 1 if kinds <= S.REDACT_RESTRICT_KINDS else 2


def encodings(raw):
    """Every encoding the scanner decodes, applied once to the bytes `raw`."""
    return {"base64": base64.b64encode(raw), "base64url": base64.urlsafe_b64encode(raw),
            "hex": binascii.hexlify(raw), "hex-upper": binascii.hexlify(raw).upper(),
            "url": urllib.parse.quote_from_bytes(raw, safe="").encode()}


def fragment_pool(s):
    """Fragments of every tier, built at run time: key words with no value (they make overlapping assignments when
    joined by '=' or ':'), restrict-tier shapes, exposures of every rule family, and clean text."""
    rng = s.rng

    def r(n, alphabet=ALNUM):
        return "".join(rng.choice(alphabet) for _ in range(n))
    return {
        "key:tok": "to" + "ken", "key:pwd": "pass" + "word", "key:apik": "api" + "_key",
        "restrict:named": "pass" + "word=" + r(10), "restrict:url": "https://bob:" + r(8) + "@example.invalid/x",
        "restrict:bare-prefix": "gh" + "p_", "restrict:short-prefix": "gh" + "p_" + r(5),
        "restrict:short-bearer": "Be" + "arer " + r(5),
        "exposure:entropy": s.body(64), "exposure:prefix": "gh" + "p_" + r(36),
        "exposure:floor-low-entropy": "wh" + "sec_" + "aaab" * 8, "exposure:bearer": "Be" + "arer " + r(24),
        "exposure:jwt": s.jwt(), "exposure:aws": "AK" + "IA" + r(16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"),
        "clean:word": "hello", "clean:path": "src/app/main.py",
    }


PAIR_SEPARATORS = [" ", "=", ":", "\n", "\t", " ", " ", "\r\n"]


class InvariantTests(unittest.TestCase):
    """Generated tests for the three scanner invariants (module docstring). No hand-picked expected outcomes: each
    asserts an ordering against the redactor or against the fragments' own tiers, over every combination."""

    def setUp(self):
        self.samples = {k: v for k, v in _redact_samples(Secrets(SEED + 2)).items()}
        low = _redact_samples(Secrets(SEED + 3), low=True)
        for k in self.samples:
            self.samples[k] = self.samples[k] + low[k]
        self.pool = fragment_pool(Secrets(SEED + 4))

    def test_i1_floor_is_never_weaker_than_the_redactor_for_every_unicode_whitespace(self):
        self.assertGreaterEqual(len(ALL_WHITESPACE), 25)
        for kind, instances in sorted(self.samples.items()):
            for i, (label, value) in enumerate(instances):
                for ws in ALL_WHITESPACE:
                    text = "x " + label + ws + value + " y\n"
                    want = redactor_tier(text)
                    with self.subTest(kind=kind, instance=i, ws="U+%04X" % ord(ws)):
                        self.assertGreaterEqual(tier(text.encode("utf-8")), want)
                        for name, blob in encodings(text.encode("utf-8")).items():
                            self.assertGreaterEqual(tier(b"x " + blob + b"\n"), want, name)

    def test_i1_floor_holds_on_mixed_valid_and_invalid_utf8(self):
        bad = (b"\xff", b"\xc3", b"\xed\xa0\x80", b"\x80\x80", b"\xa0", b"\x85")   # \xa0, \x85: Latin-1 whitespace
        for kind, instances in sorted(self.samples.items()):
            label, value = instances[0]
            for junk in bad:
                for where in ("before", "separator", "between", "after"):
                    plain = {"before": junk + b" " + label.encode() + b" " + value.encode(),
                             "separator": label.encode() + junk + value.encode(),
                             "between": label.encode() + b" " + value.encode() + b" " + junk + b" tail",
                             "after": label.encode() + b" " + value.encode() + junk}[where]
                    want = max(redactor_tier(plain.decode("utf-8", "surrogateescape")),
                               redactor_tier(plain.decode("latin-1")))
                    with self.subTest(kind=kind, junk=junk.hex(), where=where):
                        self.assertGreaterEqual(tier(b"x " + plain + b"\n"), want)

    def test_i2_the_strongest_tier_wins_for_every_overlapping_pair_in_both_orders(self):
        names = sorted(self.pool)
        for a in names:
            for b in names:
                for sep in PAIR_SEPARATORS:
                    text = self.pool[a] + sep + self.pool[b]
                    want = max(tier(("x " + self.pool[a] + "\n").encode()), tier(("x " + self.pool[b] + "\n").encode()),
                               redactor_tier(text))
                    with self.subTest(first=a, second=b, sep="U+%04X" % ord(sep[0])):
                        self.assertGreaterEqual(tier(("x " + text + "\n").encode("utf-8")), want)

    def test_findings_map_back_to_byte_lines_past_multibyte_text(self):
        """Character offsets on the decoded text map back to byte offsets, so line numbers stay right."""
        for prefix_char in ("\u00e9", "\u20ac", "\U0001F600", "\u00a0"):
            text = (prefix_char * 5 + "\n") * 3 + "Be" + "arer\u2003" + Secrets(SEED + 5).body(16) + "\n"
            with self.subTest(char="U+%04X" % ord(prefix_char)):
                lines = {f["line"] for f in S.scan_report(text.encode("utf-8"))}
                self.assertEqual(lines, {4})

    def test_i3_decode_minimums_admit_every_value_of_the_minimum_length(self):
        """DECODE_MIN_BYTES of content encode to at least B64_MIN base64 data characters and HEX_MIN hex digits."""
        n = S.DECODE_MIN_BYTES
        self.assertGreaterEqual(len(base64.b64encode(b"x" * n).rstrip(b"=")), S.B64_MIN)
        self.assertGreaterEqual(2 * n, S.HEX_MIN)
        self.assertLess(n, 11, "below the shortest exposure: a 3-byte prefix plus the 8-byte window")

    def test_i3_decoded_content_gets_every_rule(self):
        cases = {name: frag for name, frag in self.pool.items()}
        for a in sorted(self.pool):                         # overlapping assignments, compact and spaced
            if a.startswith("key:"):
                for b in sorted(self.pool):
                    for sep in ("=", " = ", ":"):
                        cases["%s%s%s" % (a, sep.strip(), b)] = self.pool[a] + sep + self.pool[b]
        for kind, instances in self.samples.items():
            for i, (label, value) in enumerate(instances):
                cases["sample:%s:%d" % (kind, i)] = label + " " + value
        for name, text in sorted(cases.items()):
            raw = text.encode("utf-8")
            want = max(tier(b"x " + raw + b"\n"), redactor_tier(text))
            if want < 2 and len(raw) < S.DECODE_MIN_BYTES:
                # below the decode minimum only a public prefix or field name fits, never a value: exposures are
                # held to I3 at every length (the shortest is 11 bytes, above the minimum)
                continue
            for enc, blob in encodings(raw).items():
                with self.subTest(case=name, encoding=enc):
                    self.assertGreaterEqual(tier(b"x " + blob + b"\n"), want)


class TierTests(unittest.TestCase):
    """The spec owner's tiering ruling: prefix-only restricts the outward text; an exposure quarantines."""

    def setUp(self):
        self.s = Secrets()

    def test_clean_report_passes_its_excerpt(self):
        findings = S.scan_report(b"PASS: no findings in harness/hooks/merge_gate.py\n")
        self.assertEqual(S.verdict(findings), {"action": "clean", "incident": False, "exposures": 0, "blocks": 0})
        self.assertEqual(S.outward(findings, "the excerpt"), "the excerpt")

    def test_prefix_only_restricts_to_structured_fields_with_no_incident(self):
        report = "F1 at redact.py:12 the pattern for `%s` misses a case\n" % PREFIX["github-classic"]
        findings = S.scan_report(report.encode(), "reports/r1.md")
        v = S.verdict(findings)
        self.assertEqual((v["action"], v["incident"], v["exposures"], v["blocks"]), ("restrict", False, 0, 1))
        out = S.outward(findings, report)
        self.assertEqual(out, "SCAN-1 reports/r1.md:1 block")
        self.assertNotIn("misses", out, "no excerpt leaves on a prefix-only hit")
        self.assertNotIn(PREFIX["github-classic"], out)

    def test_an_exposure_quarantines_writes_nothing_outward_and_raises_an_incident(self):
        for secret in (self.s.token("anthropic"), self.s.jwt(), self.s.body(40)):
            with self.subTest(kind=secret[:3].isalpha()):
                report = "F1 the reviewer pasted %s by mistake\n" % secret
                findings = S.scan_report(report.encode())
                v = S.verdict(findings)
                self.assertEqual((v["action"], v["incident"]), ("quarantine", True))
                self.assertIsNone(S.outward(findings, report))

    def test_a_prefix_hit_and_an_exposure_together_quarantine(self):
        report = "`%s` and %s\n" % (PREFIX["openai"], self.s.token("github-classic"))
        self.assertEqual(S.verdict(S.scan_report(report.encode()))["action"], "quarantine")

    def test_no_finding_or_rendering_carries_secret_text(self):
        secrets = [self.s.token(k) for k in PREFIX] + [self.s.jwt(), self.s.body(48)]
        report = "\n".join("x %s" % s for s in secrets).encode()
        findings = S.scan_report(report, "r.md")
        dumped = json.dumps(findings) + S.render_structured(findings)
        for secret in secrets:
            body = secret[-8:]
            self.assertNotIn(body, dumped)
        self.assertEqual(set().union(*(f.keys() for f in findings)),
                         {"id", "path", "line", "rule", "encoding", "severity", "exposure"})

    def test_only_bytes_are_scanned(self):
        with self.assertRaises(TypeError):
            S.scan_report("text")


class CleanCorpusTests(unittest.TestCase):
    """The repo's own .py and .md files (spec owner's corpus ruling A): every file not on the exemption list
    yields zero findings, and every listed file yields exactly its listed per-rule counts. A stale entry or a
    changed count fails, so a new credential-shaped literal anywhere in the repo is caught."""

    def test_the_corpus_matches_the_exemption_list_exactly(self):
        exempt = json.loads(EXEMPT.read_text())
        # an entry that pins the file's sha256 covers exactly those bytes: any edit drops the exemption
        listed = {path: entry["counts"] for path, entry in exempt.items()
                  if "sha256" not in entry or hashlib.sha256((ROOT / path).read_bytes()).hexdigest() == entry["sha256"]}
        for path, entry in exempt.items():
            self.assertTrue(entry.get("reason"), "every exemption names its reason: %s" % path)
        # the data-fixture exemptions added by slice 1 (b) R5 pin the fixture's bytes; the exemption list's own entry
        # cannot (a file holding its own sha256 is a fixed point), so it is bound by its exact per-rule counts only
        for fixture in ("tests/data/review_diagnostics_hostile.json", "tests/data/merge_gate_corpus.json"):
            self.assertRegex(exempt[fixture].get("sha256", ""), "^[0-9a-f]{64}$",
                             "the fixture exemption pins the fixture's bytes: %s" % fixture)
        self.assertNotIn("sha256", exempt["tests/data/ahc_scan_corpus_exempt.json"])
        actual = corpus_counts()
        unlisted = {p: c for p, c in actual.items() if p not in listed}
        self.assertEqual(unlisted, {}, "files with credential shapes that are not exempted")
        stale = sorted(p for p in listed if p not in actual)
        self.assertEqual(stale, [], "exemptions for files that no longer have findings")
        changed = {p: (listed[p], actual[p]) for p in listed if p in actual and listed[p] != actual[p]}
        self.assertEqual(changed, {}, "per-rule counts changed (listed, actual)")

    def test_the_scanner_and_this_test_are_clean(self):
        for rel in ("harness/hooks/ahc_scan.py", "tests/test_ahc_scan.py"):
            with self.subTest(rel):
                self.assertEqual(S.scan_report((ROOT / rel).read_bytes(), rel), [])

    def test_a_pinned_exemption_drops_on_any_edit(self):
        exempt = json.loads(EXEMPT.read_text())
        rel = "tests/data/merge_gate_corpus.json"
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / rel
            target.parent.mkdir(parents=True)
            target.write_bytes((ROOT / rel).read_bytes() + b"\n")
            self.assertNotEqual(hashlib.sha256(target.read_bytes()).hexdigest(), exempt[rel]["sha256"],
                                "one appended byte no longer matches the pin, so the exemption no longer applies")
            self.assertEqual(hashlib.sha256((ROOT / rel).read_bytes()).hexdigest(), exempt[rel]["sha256"])

    def test_a_planted_secret_in_an_exempt_file_changes_its_count(self):
        exempt = json.loads(EXEMPT.read_text())
        rel = sorted(exempt)[0]
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / rel
            target.parent.mkdir(parents=True)
            target.write_bytes((ROOT / rel).read_bytes() + ("\n# %s\n" % Secrets(7).token("openai", 40)).encode())
            self.assertNotEqual(corpus_counts(tmp, [rel]).get(rel), exempt[rel]["counts"])


if __name__ == "__main__":
    unittest.main()
