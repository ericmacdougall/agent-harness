#!/usr/bin/env python3
"""R5 report scanner (goodqa#16049 spec ahc-m1-v2g7, R5, NEG-21 scan half, harvest idea 4).

Before any notice or comment leaves the host, the reviewer's report bytes are scanned for credential shapes:
known token prefixes, JWT shapes and long high-entropy runs. `scan_report(data, path=...)` returns the findings;
no finding ever holds matched text. `verdict(findings)` gives the tier (clean, restrict, quarantine) and
`outward(findings, excerpt)` is the only text about the report that may leave the host.

Rules (spec harvest idea 4):
- Encodings: each value is scanned raw, and again after decoding the hex, base64 (standard and URL-safe) and
  URL-encoded (percent) runs it contains, one level deep, with every rule (entropy included) on the decoded bytes.
  A base64 run that decodes to printable prose is judged by its decoded content, not by the run's own entropy.
- Window: after a known prefix, the following token characters are stripped to alphanumerics; 8 or more
  alphanumerics is an exposure (the value is there). Separators inside a value do not hide it.
- A public prefix alone (fewer than 8 alphanumerics after it) is a block finding but not an exposure: the
  prefix is public knowledge, the value is not present (see verdict for the tiers).
- A prefix counts only at a word boundary (not preceded by a letter or digit), so ordinary words that contain a
  prefix's letters do not match.
- `Bearer` (any case) followed by 8 or more token characters is an exposure, whatever their case: letters-only
  values are valid token shapes (spec owner, v2g9 F4). Fewer is a block finding. Prose that names the scheme
  and a long word after it fails closed; repo files with such prose carry exact counts on the exemption list.
- Floor: every span redact.find() detects (raw, and in each decoded run) is a finding, so nothing the redactor
  knows can scan clean in any whitespace or wrapping form. Credential-bearing URLs (user:pass@) and NAME=value
  credential assignments restrict (no excerpt outward); every other redactor kind quarantines. The scanner's
  own rules only add to the floor (bare prefixes, separators inside values, JWTs, high-entropy runs).

Invariants (each has a generated test in tests/test_ahc_scan.py InvariantTests, not an example test):
- I1 floor >= redactor on the same text: the tier is never weaker than redact.find() implies for the text as
  the redactor would see it (UTF-8, every Unicode whitespace; and for bytes that are not valid UTF-8, also a
  lossless fallback), raw and in every encoding the scanner decodes.
- I2 strongest tier wins: a weaker finding never suppresses a stronger one, so the tier of joined or
  overlapping content is never below the strongest tier any part of it has alone.
- I3 decoded content gets every rule: every hex, base64 (standard and URL-safe) and percent-encoded run of at
  least the decode minimum is decoded and its content goes through every rule (the floor and entropy
  included). The minimums sit below the shortest exposure (11 bytes), so an encoded exposure never escapes.

Text: the floor and the text-shaped own rules (Bearer, PEM header) run on the report decoded as UTF-8 with
surrogateescape (lossless; invalid bytes become lone surrogates, which are neither whitespace nor token
characters), and, when the bytes are not valid UTF-8, also on a Latin-1 decoding (lossless, one character per
byte). Never on a lossy reinterpretation of valid UTF-8. Character offsets map back to byte offsets.

Pure: it reads its argument and writes nothing. Stdlib plus redact.py from the same tree; every pattern has
bounded repetition.
"""

from __future__ import annotations

import base64
import binascii
import math
import re
import urllib.parse

import redact

WINDOW = 8                 # alphanumerics after a prefix that make an exposure
TOKEN_RUN = 256            # how far a value after a prefix is read
ENTROPY_MIN_LEN = 32       # a high-entropy run is at least this long
ENTROPY_BITS = 4.3         # Shannon bits per character at or above which a run is high-entropy
SEGMENT_MIN = 32           # a separator-free alphanumeric segment at least this long may be a credential
SEGMENT_BITS = 4.2         # ... when its entropy per character reaches this (random base62 at 32 chars is ~4.5)
MONOTONIC = 0.75           # a run whose adjacent pairs mostly step one way is a sorted list, not a secret
HEX_MIN = 16               # hex runs at least this long are decoded (8 bytes)
DECODE_MIN_BYTES = 9       # content this long or longer is decoded from every supported encoding (I3)
B64_MIN = 12               # base64 runs with at least this many data characters are decoded (9 bytes); the
#                            shortest exposure (a 3-byte prefix plus the 8-byte window, 11 bytes) is 15 or more

# The prefixes are assembled from parts so this file never holds a contiguous token-shaped literal.
_P = lambda *parts: "".join(parts)          # noqa: E731
PREFIXES = (
    ("github-fine-grained", _P("github", "_pat_")),
    ("github-classic", _P("gh", "p_")),
    ("github-oauth", _P("gh", "o_")),
    ("github-user-server", _P("gh", "u_")),
    ("github-server", _P("gh", "s_")),
    ("github-refresh", _P("gh", "r_")),
    ("anthropic", _P("sk", "-ant-")),
    ("openai-project", _P("sk", "-proj-")),
    ("openai-service", _P("sk", "-svcacct-")),
    ("openai-admin", _P("sk", "-admin-")),
    ("openai", _P("sk", "-")),
    ("aws-key-id", _P("AK", "IA")),
    ("aws-key-id", _P("AS", "IA")),
    ("gitlab", _P("gl", "pat-")),
) + tuple(("slack", _P("xo", "x", c, "-")) for c in "abposr") + tuple(
    ("stripe", _P(k, "_", env, "_")) for k in ("sk", "rk") for env in ("live", "test"))
_PREFIX_RE = re.compile(rb"(?<![A-Za-z0-9])(" + b"|".join(
    re.escape(p.encode()) for _, p in sorted(PREFIXES, key=lambda kp: -len(kp[1]))) + rb")")
_PREFIX_KIND = {p.encode(): k for k, p in PREFIXES}
_VALUE_RE = re.compile(rb"[A-Za-z0-9_\-./+=]{0,%d}" % TOKEN_RUN)
_JWT_RE = re.compile(rb"(?<![A-Za-z0-9])" + _P("ey", "J").encode() + rb"[A-Za-z0-9_-]{8,1024}\."
                     + _P("ey", "J").encode() + rb"[A-Za-z0-9_-]{8,4096}\.[A-Za-z0-9_-]{0,1024}")
_RUN_RE = re.compile(rb"[A-Za-z0-9+/=_-]{%d,4096}" % ENTROPY_MIN_LEN)
_HEX_RE = re.compile(rb"(?<![0-9A-Fa-f])[0-9A-Fa-f]{%d,8192}(?![0-9A-Fa-f])" % HEX_MIN)
_B64_RE = re.compile(rb"[A-Za-z0-9+/_-]{%d,8192}={0,2}" % B64_MIN)
_ALNUM = re.compile(rb"[A-Za-z0-9]")
_BEARER_RE = re.compile(r"(?i)(?<![A-Za-z0-9])bearer\s{1,64}([A-Za-z0-9._~+/=-]{0,%d})" % TOKEN_RUN)


# A private-key header with any whitespace inside it, including a line break (a wrapped report): the redactor's
# own PEM shape allows spaces only. Built from parts so this file holds no header literal.
_PEM_RE = re.compile(_P("-----BE", "GIN") + r"[A-Z0-9\s]{0,60}?(?:" + _P("PRIV", "ATE")
                     + r"\s+KEY|PGP\s+" + _P("PRIV", "ATE") + r"\s+KEY\s+BLOCK)-----")

# The redactor floor (code-inspection BLOCK F1/F2): every span redact.find() detects is a finding, so nothing the
# redactor knows can scan clean. These kinds name a credential's place without proving a value is a secret (spec
# owner's ruling), so they restrict; every other redactor kind is an exposure and quarantines.
FLOOR = "redact:"           # rule-name prefix of a floor finding, so own rules and the floor stay distinguishable
REDACT_RESTRICT_KINDS = frozenset(("url-userinfo", "named-credential"))
_REDACT_KINDS = frozenset(k for k, _ in redact.PATTERNS) | {"pem"}
if not REDACT_RESTRICT_KINDS <= _REDACT_KINDS:
    raise ImportError("redact.py no longer has the restrict-tier kinds %s" % sorted(REDACT_RESTRICT_KINDS))


def _texts(data):
    """The texts the floor and the text rules run on, each with its encoding for mapping offsets back to bytes:
    UTF-8 with surrogateescape (exactly the UTF-8 text when the bytes are valid), plus Latin-1 when they are not.
    Both are lossless; neither reinterprets valid UTF-8."""
    out = [(data.decode("utf-8", "surrogateescape"), "utf-8")]
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        out.append((data.decode("latin-1"), "latin-1"))
    return out


def _byte_offsets(text, encoding, char_offsets):
    """{char offset: byte offset} for the given offsets, walking the text once."""
    if encoding == "latin-1" or text.isascii():
        return {c: c for c in char_offsets}
    out, last_c, last_b = {}, 0, 0
    for c in sorted(set(char_offsets)):
        last_b += len(text[last_c:c].encode("utf-8", "surrogateescape"))
        last_c = c
        out[c] = last_b
    return out


def _text_hits(data):
    """(byte offset, rule, exposure) for the floor (every redact.find() span) and the text-shaped own rules
    (Bearer, PEM header), on every text from _texts(data)."""
    hits = []
    for text, encoding in _texts(data):
        found = [(start, FLOOR + kind, kind not in REDACT_RESTRICT_KINDS) for kind, start, _end in redact.find(text)]
        found += [(m.start(), "bearer", len(m.group(1)) >= WINDOW) for m in _BEARER_RE.finditer(text)]
        found += [(m.start(), "pem", True) for m in _PEM_RE.finditer(text)]
        to_byte = _byte_offsets(text, encoding, [o for o, _, _ in found])
        hits += [(to_byte[o], rule, exposure) for o, rule, exposure in found]
    return sorted(set(hits))


def _entropy(run):
    counts = {}
    for b in run:
        counts[b] = counts.get(b, 0) + 1
    n = len(run)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _mixed(run):
    return bool(re.search(rb"[A-Z]", run) and re.search(rb"[a-z]", run) and re.search(rb"[0-9]", run))


def _alphabet_like(seg):
    """A sorted or reverse-sorted run (an alphabet listing such as a flag table), or one with no repeated
    character at all: 32 random draws from about 62 symbols repeat one with probability above 0.999, so a long
    all-distinct run is a character set someone wrote, not a secret."""
    ups = sum(1 for a, b in zip(seg, seg[1:]) if b > a)
    downs = sum(1 for a, b in zip(seg, seg[1:]) if b < a)
    pairs = max(len(seg) - 1, 1)
    return ups / pairs >= MONOTONIC or downs / pairs >= MONOTONIC or len(set(seg)) == len(seg)


def _candidate(seg, bits):
    return _mixed(seg) and _entropy(seg) >= bits and not _alphabet_like(seg)


def _high_entropy(run):
    """A credential-like run: either one separator-free alphanumeric segment of SEGMENT_MIN or more characters with
    upper, lower and digits at SEGMENT_BITS or more per character, or a base64-looking run (it holds a '+') with
    mixed classes at ENTROPY_BITS or more; in both cases not an alphabet listing (_alphabet_like). Paths,
    NAME=value pairs and identifiers split into word segments, and hex digests (one case plus digits) are not
    mixed, so neither counts."""
    if b"+" in run and _candidate(run, ENTROPY_BITS):
        return True
    return any(len(seg) >= SEGMENT_MIN and _candidate(seg, SEGMENT_BITS) for seg in re.split(rb"[/=_.\-]", run))


def _raw_hits(data, *, entropy=True):
    """(offset, rule, exposure) for each credential shape in `data`, no matched text."""
    hits = []
    for m in _PREFIX_RE.finditer(data):
        value = _VALUE_RE.match(data, m.end()).group(0)
        exposure = len(_ALNUM.findall(value)) >= WINDOW
        hits.append((m.start(), _PREFIX_KIND[m.group(1)], exposure))
    for m in _JWT_RE.finditer(data):
        hits.append((m.start(), "jwt", True))
    hits.extend(_text_hits(data))        # raw and every decoded blob alike: _raw_hits runs on both
    if entropy:
        # I2: only an exposure may stand in for the entropy finding it overlaps; a restrict-tier finding inside
        # (or around) a high-entropy run must never lower its tier
        covered = {o for o, _, exposure in hits if exposure}
        for m in _RUN_RE.finditer(data):
            if _high_entropy(m.group(0)) and not any(m.start() <= o < m.end() for o in covered) \
                    and not _encoded_prose(m.group(0)):
                hits.append((m.start(), "high-entropy", True))
    return hits


_PRINTABLE = frozenset(range(0x20, 0x7f)) | {0x09, 0x0a, 0x0d}


def _encoded_prose(run):
    """True when `run` is base64 of printable text with word spaces in it. Such a run is judged by its decoded
    content instead (scan_report applies every rule, entropy included, to decoded runs), so encoded prose is not
    an incident while a token inside it still is. Random bytes, and a token with no spaces, keep the raw rule."""
    bare = run.rstrip(b"=")
    for alt in (b"+/", b"-_"):
        try:
            text = base64.b64decode(bare + b"=" * (-len(bare) % 4), altchars=alt, validate=True)
        except (binascii.Error, ValueError):
            continue
        return text.count(b" ") >= 2 and all(b in _PRINTABLE for b in text)
    return False


def _decoded(data):
    """(offset, encoding, bytes) for each decodable encoded run in `data`, one level deep."""
    out = []
    for m in _HEX_RE.finditer(data):
        run = m.group(0)
        if len(run) % 2 == 0:
            out.append((m.start(), "hex", binascii.unhexlify(run)))
    for m in _B64_RE.finditer(data):
        run = m.group(0).rstrip(b"=")       # re-pad from the bare run: padding already present must not double
        for alt in (b"+/", b"-_"):
            try:
                out.append((m.start(), "base64", base64.b64decode(run + b"=" * (-len(run) % 4),
                                                                   altchars=alt, validate=True)))
                break
            except (binascii.Error, ValueError):
                continue
    start = 0
    for line in data.split(b"\n"):
        if b"%" in line:
            unq = urllib.parse.unquote_to_bytes(line)
            if unq != line:
                out.append((start, "url", unq))
        start += len(line) + 1
    return out


def _line_of(data, offset):
    return data.count(b"\n", 0, offset) + 1


def scan_report(data, path="report"):
    """The findings for one report: a list of dicts {id, path, line, rule, encoding, severity, exposure}. Every
    finding blocks the report (quarantine, NEG-21); `exposure` says whether a value, not just a public prefix, is
    present. Raises TypeError for anything but bytes: a report is scanned as the bytes that would leave."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("scan_report takes the report bytes")
    data = bytes(data)
    found = []
    for offset, rule, exposure in _raw_hits(data):
        found.append((offset, rule, "raw", exposure))
    for offset, encoding, blob in _decoded(data):
        for _, rule, exposure in _raw_hits(blob):     # every rule, the bounded entropy rule included
            found.append((offset, rule, encoding, exposure))    # reported at the encoded run's (or line's) start
    # one finding per (line, rule, exposure); the raw form wins over a decoded copy of the same hit
    best = {}
    for offset, rule, encoding, exposure in found:
        key = (_line_of(data, offset), rule, bool(exposure))
        if key not in best or (best[key] != "raw" and encoding == "raw"):
            best[key] = encoding
    findings = []
    for (line, rule, exposure), encoding in sorted(best.items(), key=lambda kv: (kv[0][0], kv[0][1], kv[0][2])):
        findings.append({"id": "SCAN-%d" % (len(findings) + 1), "path": str(path), "line": line, "rule": rule,
                         "encoding": encoding, "severity": "block", "exposure": exposure})
    return findings


def exposures(findings):
    return sum(1 for f in findings if f["exposure"])


CLEAN, RESTRICT, QUARANTINE = "clean", "restrict", "quarantine"


def verdict(findings):
    """The R5 tier (spec owner's ruling on v2g7, to be folded into the next revision):
    - clean: no finding; the report's excerpt may be quoted outward.
    - restrict: only prefix-only findings (a public prefix with fewer than 8 secret bytes after it). Every one is
      a block finding: the outward text is restricted to structured fields (ids, paths, lines, severity), no
      excerpt. No incident and no quarantine: a prefix alone is not secret material.
    - quarantine: any exposure (8 or more secret bytes after a prefix, a JWT shape, a high-entropy run). Nothing
      is written outward, and an incident is raised (NEG-21).
    Returns {"action", "incident", "exposures", "blocks"}."""
    n = exposures(findings)
    action = QUARANTINE if n else (RESTRICT if findings else CLEAN)
    return {"action": action, "incident": action == QUARANTINE, "exposures": n, "blocks": len(findings)}


def render_structured(findings):
    """Structured fields only: id, path, line and severity per finding."""
    return "\n".join("%s %s:%d %s" % (f["id"], f["path"], f["line"], f["severity"]) for f in findings)


def outward(findings, excerpt):
    """The text about this report that may leave the host: the excerpt when clean, the structured fields only
    when restricted, and None (nothing at all) when quarantined."""
    action = verdict(findings)["action"]
    if action == CLEAN:
        return excerpt
    if action == RESTRICT:
        return render_structured(findings)
    return None
