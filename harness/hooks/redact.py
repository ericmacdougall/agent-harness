#!/usr/bin/env python3
"""Shared secret redaction: one high-recall shape list for WAL notes, scans and (later) every other redactor.

Stdlib only, linear-time patterns with bounded repetition, so hostile input cannot trigger catastrophic
backtracking. `redact(text)` replaces each secret with `[REDACTED:<kind>]`; `find(text)` returns the kinds and
offsets WITHOUT the values, which is what scanners must print.

Recall over precision: a false positive costs a placeholder in a note, a false negative leaks a credential into
a transcript that is never deleted. Shapes cover Dropbox/rclone OAuth blobs, Anthropic, OpenAI, GitHub, AWS,
Google, Slack and npm tokens, JWTs, PEM blocks, Bearer headers, URL userinfo and generic NAME=value credentials.
"""

from __future__ import annotations

import re

_KEY_WORDS = (r'(?:password|passwd|passphrase|secret|token|api[_-]?key|access[_-]?key|'
              r'private[_-]?key|credentials?|client[_-]?secret|refresh[_-]?token|access[_-]?token|id[_-]?token)'
              r'(?:[_-]value)?')
# For anchored use (ah_export fullmatches whole key names with it): any number of name segments.
_KEYS = r'(?:[a-z0-9]+[_-])*' + _KEY_WORDS
# For searching: the same name shape with a bounded prefix (at most 16 segments of at most 128 characters). The
# unbounded prefix restarted at every word boundary of a hyphenated run and scanned to its end, which is
# quadratic (GoodQA #16680); bounded, each start does constant work. A match starts at a word boundary, as before.
# Underscores are word characters, so a name longer than that window has no later \b to start from; two more starts
# cover it, and each fires only once the window is used up, so short names match exactly as before:
#   - inside a name, after a letter or digit and _ or -, with exactly 16 full segments to the key word (17+ segments);
#   - inside a segment, after a letter or digit, with 128 more before its _ or - (a segment over 128 characters).
# Every value the unbounded form redacted is still redacted; tests/test_redact_perf.py pins this against it, and
# pins that the repo's own code gains no findings. Past the window the match is a slight superset (the extra starts
# cannot see whether the whole name began with _), which only over-redacts.
_KEY_SEG = r'[a-z0-9]{1,128}[_-]'
_KEYS_SCAN_ANY = (r'(?:\b(?:' + _KEY_SEG + r'){0,16}'
                  r'|(?<=[a-z0-9][_-])(?:' + _KEY_SEG + r'){16}'
                  r'|(?<=[a-z0-9])[a-z0-9]{128}[_-](?:' + _KEY_SEG + r'){0,15})' + _KEY_WORDS)

# PEM bodies are unbounded: scan them separately so chunk boundaries and regex body caps cannot expose a tail.
PEM_BEGIN = re.compile(r'-----BEGIN [A-Z0-9 ]{0,40}(?:PRIVATE KEY|ENCRYPTED PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----')
PEM_END = re.compile(r'-----END [A-Z0-9 ]{0,40}-----')

# (kind, compiled pattern). Order matters: specific shapes first so the kind label is the most useful one.
PATTERNS = [
    # bounded whitespace: an unbounded `^\s*` rescanned every line start of a newline run (GoodQA #16680)
    ('rclone-token', re.compile(r'(?im)^[ \t]{0,64}token\s{0,64}=\s{0,64}\{[^\n]{0,8192}')),
    ('oauth-json', re.compile(r'(?is)\{[^{}]{0,2048}?[\x22\x27](?:access_token|refresh_token|id_token)[\x22\x27]'
                              r'\s*:[^{}]{0,4096}\}')),
    ('anthropic', re.compile(r'\bsk-ant-[A-Za-z0-9_-]{8,}')),
    ('openai', re.compile(r'\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}')),
    ('github', re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})')),
    # an access key id followed by its 40-character secret (CSV exports, `aws configure` echoes)
    ('aws-key-pair', re.compile(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b[\s,:;=\x22\x27]{1,20}[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+=])')),
    ('aws-key', re.compile(r'\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[A-Z0-9]{16}\b')),
    ('aws-secret', re.compile(r'(?i)\baws[_-]?secret[_-]?(?:access[_-]?)?key[\x22\x27]?\s*[:=]\s*[\x22\x27]?'
                              r'[A-Za-z0-9/+]{40}')),
    # Stripe secret/restricted keys and webhook secrets, Hugging Face, GitLab and SendGrid (GoodQA #15585)
    ('stripe', re.compile(r'\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}')),
    ('stripe-webhook', re.compile(r'\bwhsec_[A-Za-z0-9]{16,}')),
    ('huggingface', re.compile(r'\bhf_[A-Za-z0-9]{20,}')),
    ('gitlab', re.compile(r'\bglpat-[A-Za-z0-9_-]{20,}')),
    ('sendgrid', re.compile(r'\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}')),
    ('google-oauth', re.compile(r'\bya29\.[A-Za-z0-9_-]{20,}')),
    ('google-api', re.compile(r'\bAIza[A-Za-z0-9_-]{30,}')),
    ('google-refresh', re.compile(r'\b1//[A-Za-z0-9_-]{30,}')),
    ('dropbox', re.compile(r'\bsl\.[A-Za-z0-9_-]{40,}')),
    ('slack', re.compile(r'\bxox[abposr]-[A-Za-z0-9-]{6,}')),
    ('npm', re.compile(r'\bnpm_[A-Za-z0-9]{30,}')),
    ('jwt', re.compile(r'\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{0,512}')),
    ('bearer', re.compile(r'(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}')),
    ('url-userinfo', re.compile(r'(?i)\b[a-z][a-z0-9+.-]{0,30}://[^\s/?#@]{1,256}@[^\s/?#]{1,256}')),
    ('named-credential', re.compile(r'(?i)' + _KEYS_SCAN_ANY + r'[\x22\x27]?\s*[:=]\s*[\x22\x27]?[^\s\x22\x27,;}]{3,512}')),
    ('named-credential', re.compile(r'\b[a-z][a-z0-9]*(?:Secret|Token|Password|ApiKey|AccessKey|PrivateKey|Credentials?)'
                                    r'[\x22\x27]?\s*[:=]\s*[\x22\x27]?[^\s\x22\x27,;}]{3,512}')),
]


def _find_pem(text):
    hits = []
    cursor = 0
    while True:
        begin = PEM_BEGIN.search(text, cursor)
        if begin is None:
            return hits
        end = PEM_END.search(text, begin.end())
        stop = end.end() if end is not None else len(text)
        hits.append(('pem', begin.start(), stop))
        cursor = stop


def find(text):
    """[(kind, start, end)] for every secret-shaped span. Values are never returned."""
    text = str(text)
    hits = _find_pem(text)
    seen = {(start, end) for _kind, start, end in hits}
    # The whole text is scanned in one pass: every pattern is linear (tests/test_redact_perf.py guards that at
    # 1-2 MB), and slicing it into chunks cut any match longer than the overlap at a boundary (GoodQA #16680).
    for kind, pattern in PATTERNS:
        for match in pattern.finditer(text):
            if '[REDACTED:' in match.group(0):
                continue
            span = match.span()
            if span in seen:
                continue
            seen.add(span)
            hits.append((kind, span[0], span[1]))
    return sorted(hits, key=lambda hit: (hit[1], hit[2]))


def redact(text):
    """Return text with every secret-shaped span replaced by [REDACTED:<kind>]. Idempotent."""
    text = str(text)
    spans = []
    for kind, start, end in find(text):
        spans.append((start, end, kind))
    if not spans:
        return text
    spans.sort(key=lambda item: (item[0], -(item[1] - item[0])))
    out = []
    cursor = 0
    for start, end, kind in spans:
        if start < cursor:  # overlaps a span already replaced (nested shapes): the outer one wins
            if end > cursor:
                cursor = max(cursor, end)  # swallow the tail so no secret fragment survives
            continue
        out.append(text[cursor:start])
        out.append('[REDACTED:' + kind + ']')
        cursor = end
    out.append(text[cursor:])
    return ''.join(out)


def redact_obj(value, depth=0):
    """redact() applied to every string (keys included) inside dicts, lists and tuples, for data that is about
    to be serialized. A private-key block without its END line is redacted to the end of its string; run over
    serialized JSON that would also swallow the closing quote and braces, so redact the values, then dump."""
    if depth > 32:
        return '[REDACTED:depth]'
    if isinstance(value, dict):
        return {redact(k) if isinstance(k, str) else k: redact_obj(v, depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact_obj(v, depth + 1) for v in value]
    if isinstance(value, str):
        return redact(value)
    return value


def has_secret(text):
    return bool(find(text))
