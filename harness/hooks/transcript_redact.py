#!/usr/bin/env python3
"""Transcript archive redaction gate (GoodQA #16650, spec "Redaction gate"; red-team spec-review-redteam.md).

One JSONL record in, one record out. Fail closed: if the independent verifier (pass 2) still sees a secret in
pass 1's output, or anything raises, the record is replaced by an omitted marker that names only a kind, the
line number and the byte length of the source line (no hash: a hash of a short record could be brute-forced). No matched value ever reaches a return value other than the
redacted output itself, an exception message, a log or stdout.

Pass 1 (redaction):
  * JSON records are walked key-aware. A value under a credential-like key is replaced whole by
    "[REDACTED:keyed]" (containers included). Booleans and null are always kept; numbers are kept except under
    password, pin, otp and passcode keys (spec r3).
  * Allowlist, never redacted (spec r3, NEG-18: session mapping depends on it): session and record id keys
    (sessionId, session_id, session, parentUuid, uuid, requestId, and the Codex session_meta fields id,
    session_id, parent_thread_id, forked_from_id) when the value is a UUID or ULID; numeric *_tokens,
    max_tokens, *_token_count and tokens; scalar model and type. A credential-like key whose value is not
    UUID/ULID-shaped is still redacted. Pass 2 still verifies allowlisted values, so a secret planted there
    omits the record instead of leaking.
    {"name"|"key": <credential-like>, "value": X} pairs, cookie objects and [header, value] pairs redact X.
  * Every string (keys included) is redacted with redact.PATTERNS, redact.PEM_BEGIN/PEM_END and the extra shapes
    below. Unlike redact.find(), a candidate is never skipped because it contains a "[REDACTED:" marker; only a
    match that IS exactly one placeholder is left alone.
  * A string that parses as JSON is walked recursively (up to 8 levels) and re-encoded only if something in it
    was redacted, so clean nested JSON keeps its original bytes.
  * A string holding ANSI escapes, zero-width/bidi characters, %XX or \\uXXXX escapes is also scanned in a
    normalized form; if that form has a hit, the normalized form is redacted and kept instead.
  * The record is re-serialized with json.dumps(ensure_ascii=False, separators=(",", ":")) and the text shapes
    run again inside each JSON string literal of the serialized line. A replacement never crosses a literal
    boundary or splits a backslash escape, and the result must still parse, or the record is omitted.
  * A non-JSON line, or a line that is not valid UTF-8, is redacted as text. Invalid UTF-8 is decoded with the
    "surrogateescape" handler, so the undecodable bytes come back out unchanged and the output is deterministic.
    Lone surrogates from \\ud800-style JSON escapes are written back as \\uXXXX escapes.

Pass 2 (verifier) is written separately on purpose: its own shapes, keyword rules and JSON key walk, run over
normalized scan copies (ANSI and zero-width/bidi stripped, URL-decoded once, \\u escapes and escaped quotes
decoded, nested JSON decoded up to 8 levels, and a copy with line breaks removed so wrapped tokens join).

Linear time: every pattern has bounded repetition or a left anchor. redact.py's rclone-token shape (quadratic
on runs of newlines) and its first named-credential shape (quadratic on hyphenated runs) are replaced here by
bounded equivalents; every other redact.PATTERNS entry is used as is. Patterns run only when a cheap literal
anchor is present.

Deliberate gaps (reported to the owner, see the hand-off): raw high-entropy strings with no keyword or vendor
prefix (64-hex keys look like sha256 digests), free-text passwords, base64 wrapped across lines, a token split
across two JSONL records, and third-party PII other than emails and North American phone numbers.

Stdlib only, Python 3.9 compatible.
"""
from __future__ import annotations

import bisect
import hashlib
import json
import re
from urllib.parse import unquote

import redact

RULESET_VERSION = "2026.11.22-2"  # bump on any rule change: staged chunks with an older version are re-redacted

MAX_NEST = 8  # JSON-in-a-string decoding depth, pass 1 and pass 2
_MISSING = object()


class _Omit(Exception):
    """Fail closed with a fixed kind. Never carries a value."""

    def __init__(self, kind):
        super().__init__(kind)
        self.kind = kind


# ----------------------------------------------------------------------------------------------------------
# Pass 1 shapes
# ----------------------------------------------------------------------------------------------------------

MARKER = re.compile(r'\[(?:REDACTED|OMITTED):[A-Za-z0-9:_.-]{1,80}\]')
_Q = r'(?:\\{0,8}[\x22\x27])?'  # an optional quote, possibly backslash-escaped (\"password\": \"x\")
_VAL = r'(?:[^\s\x22\x27,;}\\]|\\(?![\x22\x27\\]))'  # a value char; a backslash only when it does not escape a quote

_KW = (r'(?:password|passwd|passphrase|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credentials?|'
       r'client[_-]?secret)')

# Bounded replacements for the two quadratic redact.PATTERNS entries.
_RCLONE = re.compile(r'(?im)^[ \t]{0,64}token[ \t]{0,64}=[ \t]{0,64}\{[^\n]{0,8192}')
_NAMED = re.compile(r'(?i)' + _KW + r'(?:[_-]value)?' + _Q + r'\s{0,8}[:=]\s{0,8}' + _Q + r'(?P<v>' + _VAL + r'{3,4096})')

_REPLACED_KINDS = {('rclone-token', 0), ('named-credential', 0)}  # (kind, occurrence) in redact.PATTERNS


def _imported_patterns():
    seen = {}
    out = []
    for kind, pattern in redact.PATTERNS:
        index = seen.get(kind, 0)
        seen[kind] = index + 1
        if (kind, index) in _REPLACED_KINDS:
            continue
        out.append((kind, pattern))
    return out


# Literal anchors (lowercase): a pattern runs only when one is present. A kind without an entry always runs.
_ANCHORS = {
    'rclone-token': ('token',),
    'oauth-json': ('access_token', 'refresh_token', 'id_token'),
    'anthropic': ('sk-ant-',),
    'openai': ('sk-',),
    'github': ('ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_', 'github_pat_'),
    'aws-key-pair': ('akia', 'asia'),
    'aws-key': ('akia', 'asia', 'agpa', 'aida', 'aroa'),
    'aws-secret': ('aws',),
    'stripe': ('_live_', '_test_'),
    'stripe-webhook': ('whsec_',),
    'huggingface': ('hf_',),
    'gitlab': ('glpat-',),
    'sendgrid': ('sg.',),
    'google-oauth': ('ya29.',),
    'google-api': ('aiza',),
    'google-refresh': ('1//',),
    'dropbox': ('sl.',),
    'slack': ('xox',),
    'npm': ('npm_',),
    'jwt': ('eyj',),
    'bearer': ('bearer',),
    'url-userinfo': ('://',),
    'named-credential': ('pass', 'secret', 'token', 'key', 'credential'),
    'auth-header': ('authorization',),
    'cookie-header': ('cookie',),
    'userpass-flag': ('-u',),
    'secret-flag': ('--',),
    'mysql-password': ('mysql', 'mariadb'),
    'psql-password': ('psql',),
    'env-secret': ('pwd', 'pass', 'secret'),
    'url-secret': ('=',),
    'email': ('@',),
}

_EXTRA = [
    ('named-credential', _NAMED),
    # redact.py's bearer needs whitespace; pass 2 also accepts "bearer:" and "bearer=", so pass 1 must too.
    ('bearer', re.compile(r'(?i)bearer[ \t:=]{1,4}(?P<v>[A-Za-z0-9._~+/=-]{8,4096})')),
    ('auth-header', re.compile(
        r'(?i)\b(?:proxy-)?authorization\b' + _Q + r'[ \t]{0,8}[:=][ \t]{0,8}' + _Q +
        r'(?:(?:basic|bearer|token|digest|negotiate|ntlm|apikey)[ \t]{1,8})?(?P<v>[^\s\x22\x27\\,;]{1,4096})')),
    ('cookie-header', re.compile(r'(?i)\b(?:set-)?cookie' + _Q + r'[ \t]{0,8}:[ \t]{0,8}(?P<v>[^\s;\x22\\]{1,4096}(?:;[ \t]{0,4}[^\s;\x22\\]{1,4096}){0,64};?)')),
    ('userpass-flag', re.compile(
        r'(?<![^\s\x22\x27])(?:-u|--user)(?:[ \t]{1,8}|=)' + _Q + r'[^\s:\x22\x27\\]{1,256}:(?P<v>[^\s\x22\x27\\]{1,512})')),
    ('secret-flag', re.compile(
        r'(?i)(?<![^\s\x22\x27])--(?:[a-z0-9]{1,32}-){0,4}(?:password|passwd|pass|token|secret|api-?key|access-?key|'
        r'auth-token)(?:[ \t]{1,8}|=)' + _Q + r'(?P<v>(?!--)[^\s\x22\x27\\]{1,512})')),
    # mysql: -pSECRET attached, or -p SECRET (that is a database name to mysql, redacted anyway: recall first).
    # Gated by _CMD_GATES: the command must appear at most 256 characters earlier with no \n | ; & in between.
    ('mysql-password', re.compile(
        r'(?<=\s)-p(?:(?P<v>[^\s\x22\x27\\]{1,256})|[ \t]{1,8}(?P<v2>(?!-)[^\s\x22\x27\\]{1,256}))')),
    # psql: -p is the port; only a non-numeric value (never a port) is redacted.
    ('psql-password', re.compile(
        r'(?<=\s)-p[ \t]{0,8}(?P<v>(?![0-9]{1,5}(?![^\s\x22\x27]))(?!-)[^\s\x22\x27\\]{1,256})')),
    ('env-secret', re.compile(
        r'(?i)(?:_PWD|\bPWD|PGPASSWORD|SECRET[_-]?KEY)[A-Za-z0-9_]{0,64}' + _Q + r'[ \t]{0,8}[:=][ \t]{0,8}' + _Q +
        r'(?P<v>' + _VAL + r'{1,4096})')),
    ('url-secret', re.compile(
        r'(?i)[?&;](?:x-amz-signature|x-amz-credential|x-amz-security-token|x-goog-signature|x-goog-credential|'
        r'x-goog-security-token|sig|signature|token|access_token|refresh_token|id_token|api_key|apikey|key|code|'
        r'password|client_secret)=(?P<v>[^&#\s\x22\x27\\]{1,4096})')),
    ('email', re.compile(
        r'(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9][A-Za-z0-9-]{0,62}(?:\.[A-Za-z0-9-]{1,63}){0,8}'
        r'\.[A-Za-z]{2,24}(?![A-Za-z0-9-])')),
    ('phone', re.compile(
        r'(?<![\w.:/+-])(?:\+?1[ .-])?(?:\([0-9]{3}\)[ ]?|[0-9]{3}[ .-])[0-9]{3}[ .-][0-9]{4}(?![\w.:/-])')),
]

_CMD_GATES = {
    'mysql-password': re.compile(r'\b(?:mysql|mysqldump|mysqladmin|mysqlimport|mysqlshow|mariadb|mariadb-dump)\b'),
    'psql-password': re.compile(r'\bpsql\b'),
}
# The phone shape has no literal or charset prefix, so it is only tried in a short window that ends at a
# digit-first core match (same results, a fraction of the per-character cost).
_PHONE_CORE = re.compile(r'[0-9]{3}[ .-][0-9]{4}(?![\w.:/-])')
_PHONE_WINDOW = 12


def _phone_matches(text, pattern):
    for core in _PHONE_CORE.finditer(text):
        start, end = core.span()
        match = pattern.search(text, max(0, start - _PHONE_WINDOW), end)
        while match is not None and match.end() != end:
            match = pattern.search(text, match.start() + 1, end)
        if match is not None:
            yield match


_CMD_SEPARATORS = re.compile(r'[\n|;&]')
_CMD_WINDOW = 256


def _command_gate(text, gate):
    """A predicate: does a gate command precede position `at` within the window, in the same command?
    Bisect over precomputed positions keeps this linear on hostile input (no per-hit rescans)."""
    ends = [m.end() for m in gate.finditer(text)]
    seps = None

    def ok(at):
        nonlocal seps
        i = bisect.bisect_right(ends, at) - 1
        if i < 0 or at - ends[i] > _CMD_WINDOW:
            return False
        if seps is None:
            seps = [m.start() for m in _CMD_SEPARATORS.finditer(text)]
        j = bisect.bisect_left(seps, ends[i])
        return j >= len(seps) or seps[j] >= at
    return ok


# A token-shaped hit that ends at a line break continues on the next line (tmux and terminal wraps).
_WRAP = re.compile(r'(?:\r?\n|(?:\\r)?\\n)[A-Za-z0-9_+/=.~-]{1,1024}')
_WRAP_LINES = 32  # continuation lines followed per hit
_NO_WRAP = {'email', 'phone', 'pem', 'cookie-header', 'url-userinfo', 'oauth-json', 'rclone-token', 'base64'}

_BASE64 = re.compile(r'(?<![A-Za-z0-9+/_=-])[A-Za-z0-9+/_-]{1000,}={0,2}')

_ANSI = re.compile(r'\x1b(?:\[[0-?]{0,64}[ -/]{0,16}[@-~]|\][^\x07\x1b]{0,4096}(?:\x07|\x1b\\)?|[@-Z\\-_])')
_INVISIBLE = re.compile('[\u00ad\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]')
_UESC = re.compile(r'\\u([0-9a-fA-F]{4})')
_NORM_TRIGGER = re.compile('[\x1b\u00ad\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]|'
                           r'%[0-9A-Fa-f]{2}|\\u[0-9A-Fa-f]{4}')
_JSON_ESC = re.compile(r'\\(?:u[0-9a-fA-F]{4}|.)', re.S)
_LITERAL = re.compile(r'"([^"\\]*(?:\\.[^"\\]*)*)"', re.S)
_SURROGATE = re.compile('[\ud800-\udfff]')
_SURROGATE_NOT_ESCAPE = re.compile('[\ud800-\udc7f\udd00-\udfff]')

_PATTERNS = None


def _patterns():
    global _PATTERNS
    if _PATTERNS is None:
        merged = [('rclone-token', _RCLONE)] + _imported_patterns() + _EXTRA
        _PATTERNS = [(kind, pattern, _ANCHORS.get(kind)) for kind, pattern in merged]
    return _PATTERNS


def _pem_spans(text):
    spans = []
    cursor = 0
    while True:
        begin = redact.PEM_BEGIN.search(text, cursor)
        if begin is None:
            return spans
        end = redact.PEM_END.search(text, begin.end())
        stop = end.end() if end is not None else len(text)
        spans.append((begin.start(), stop, 'pem'))
        cursor = stop


def _find_spans(text):
    """[(start, end, kind)] over text. Values are never returned to callers outside this module."""
    lower = text.lower()
    present = {}

    def has(anchor):  # each distinct anchor is searched once per text
        found = present.get(anchor)
        if found is None:
            found = present[anchor] = anchor in lower
        return found
    spans = _pem_spans(text) if '-----begin' in lower else []
    for kind, pattern, anchors in _patterns():
        if anchors is not None and not any(has(a) for a in anchors):
            continue
        gate = _command_gate(text, _CMD_GATES[kind]) if kind in _CMD_GATES else None
        for match in (_phone_matches(text, pattern) if kind == 'phone' else pattern.finditer(text)):
            if gate is not None and not gate(match.start()):
                continue
            if 'v' in pattern.groupindex:
                group = 'v' if match.group('v') is not None else 'v2'
                start, end = match.span(group)
            else:
                start, end = match.span()
            if start < 0 or end <= start:
                continue
            if MARKER.fullmatch(text, start, end):
                continue  # exactly one placeholder: already redacted
            if kind not in _NO_WRAP:
                for _ in range(_WRAP_LINES):
                    wrap = _WRAP.match(text, end)
                    if wrap is None:
                        break
                    end = wrap.end()
            spans.append((start, end, kind))
    return spans


def _adjust_for_escapes(content, spans):
    """Widen spans so none starts or ends inside a JSON backslash escape of a serialized string literal."""
    if '\\' not in content or not spans:
        return spans
    escapes = [m.span() for m in _JSON_ESC.finditer(content)]
    starts = [s for s, _ in escapes]
    out = []
    for start, end, kind in spans:
        i = bisect.bisect_right(starts, start) - 1
        if i >= 0 and escapes[i][0] < start < escapes[i][1]:
            start = escapes[i][0]
        j = bisect.bisect_right(starts, end - 1) - 1
        if j >= 0 and escapes[j][0] < end < escapes[j][1]:
            end = escapes[j][1]
        out.append((start, end, kind))
    return out


def _apply(text, spans, counts):
    if not spans:
        return text
    spans = sorted(spans, key=lambda s: (s[0], -s[1]))
    merged = []
    for start, end, kind in spans:
        if merged and start < merged[-1][1]:  # overlap: the outer (first) span wins and swallows the tail
            if end > merged[-1][1]:
                merged[-1][1] = end
            continue
        merged.append([start, end, kind])
    out = []
    cursor = 0
    for start, end, kind in merged:
        out.append(text[cursor:start])
        out.append('[REDACTED:' + kind + ']')
        counts[kind] = counts.get(kind, 0) + 1
        cursor = end
    out.append(text[cursor:])
    return ''.join(out)


def _collapse_base64(text, counts):
    if len(text) < 1000:
        return text

    def repl(match):
        run = match.group(0)
        counts['base64'] = counts.get('base64', 0) + 1
        return '[OMITTED:base64:%d:%s]' % (len(run), hashlib.sha256(run.encode('utf-8', 'surrogatepass')).hexdigest()[:12])
    return _BASE64.sub(repl, text)


def _normalize1(text):
    text = _ANSI.sub('', text)
    text = _INVISIBLE.sub('', text)
    if '%' in text:
        text = unquote(text, errors='surrogateescape')
    if '\\u' in text:
        text = _UESC.sub(lambda m: chr(int(m.group(1), 16)), text)
        text = _INVISIBLE.sub('', _ANSI.sub('', text))
    return text


def _redact_text(text, counts):
    # Raw spans are applied first. Decoding can add a delimiter (%2F, \u0020) that would shorten a match the raw
    # text fully covered, so the normalized form is only ever a second scan over already-redacted text.
    text = _collapse_base64(text, counts)
    text = _apply(text, _find_spans(text), counts)
    if _NORM_TRIGGER.search(text):
        norm = _normalize1(text)
        if norm != text:
            local = {}
            norm = _collapse_base64(norm, local)
            norm_spans = _find_spans(norm)
            if norm_spans or local:
                for kind, n in local.items():
                    counts[kind] = counts.get(kind, 0) + n
                return _apply(norm, norm_spans, counts)
    return text


# ----------------------------------------------------------------------------------------------------------
# Pass 1 key-aware walk
# ----------------------------------------------------------------------------------------------------------
# Key choice: a key is split on `_`, `-`, spaces and camelCase into lowercase tokens.
#  * _STRONG anywhere in the key: words that only name secrets (password_hint and secret_count are redacted too;
#    a false positive costs a placeholder, a miss costs a credential).
#  * _LAST only as the final token: words that are also ordinary nouns or prefixes (token_count, auth_method,
#    session_meta and signature_version stay; GITHUB_TOKEN, basic_auth, user_session are redacted).
#  * _PAIRS anywhere as adjacent tokens (api key, session id, ...), and fused forms by suffix (userpassword).
#  * "x-...-key|token|secret" header names.
# Not included: bare "key" (React keys, dict entries), "pin" (pinned, pin numbers in configs are rare in
# transcripts), "tokens" (usage counters such as input_tokens and max_tokens).
_STRONG = {'password', 'passwd', 'passphrase', 'secret', 'secrets', 'credential', 'credentials', 'apikey',
           'privatekey', 'clientsecret', 'sessiontoken', 'sessionid', 'accesskey', 'secretkey', 'authtoken',
           'accesstoken', 'refreshtoken'}
_LAST = {'pwd', 'pass', 'passcode', 'token', 'auth', 'authorization', 'cookie', 'cookies', 'session', 'sig',
         'signature', 'bearer', 'otp'}
_PAIRS = {('api', 'key'), ('access', 'key'), ('private', 'key'), ('secret', 'key'), ('signing', 'key'),
          ('encryption', 'key'), ('master', 'key'), ('session', 'id'), ('session', 'token'), ('auth', 'token'),
          ('access', 'token'), ('refresh', 'token'), ('id', 'token'), ('client', 'secret')}
_FUSED_SUFFIX = ('password', 'passwd', 'passphrase', 'secret', 'secrets', 'apikey', 'accesskey', 'privatekey',
                 'clientsecret', 'accesstoken', 'refreshtoken', 'authtoken', 'sessiontoken', 'sessionid',
                 'secretkey', 'credential', 'credentials', 'authorization', 'cookie', 'cookies', 'token')
_X_HEADER_LAST = {'key', 'token', 'secret', 'signature', 'sig', 'auth'}
_CAMEL1 = re.compile(r'([a-z0-9])([A-Z])')
_CAMEL2 = re.compile(r'([A-Z]+)([A-Z][a-z])')
_SPLIT = re.compile(r'[^a-z0-9]+')
_KEY_CACHE = {}


def _key_is_credential(key):
    if not isinstance(key, str) or not key:
        return False
    cached = _KEY_CACHE.get(key)
    if cached is not None:
        return cached
    tokens = _key_tokens(key)
    result = False
    if tokens:
        joined = ''.join(tokens)
        result = (any(t in _STRONG for t in tokens) or tokens[-1] in _LAST
                  or any((a, b) in _PAIRS for a, b in zip(tokens, tokens[1:]))
                  or joined.endswith(_FUSED_SUFFIX)
                  or (len(tokens) >= 2 and tokens[0] == 'x' and tokens[-1] in _X_HEADER_LAST)
                  or (len(tokens) >= 2 and tokens[-1] == 'key' and key.isupper()))  # APP_KEY, DEPLOY_KEY
    if len(_KEY_CACHE) < 4096 and len(key) <= 256:
        _KEY_CACHE[key] = result
    return result


_COOKIE_FIELDS = ('domain', 'path', 'httpOnly', 'httponly', 'expires', 'secure', 'sameSite', 'samesite')


def _pair_is_credential(d):
    """(is a credential pair, its value is a numeric secret)"""
    if 'value' not in d:
        return False, False
    for field in ('name', 'key'):
        name = d.get(field)
        if isinstance(name, str) and _key_is_credential(name):
            return True, _numeric_secret_key(name)
    return isinstance(d.get('name'), str) and any(f in d for f in _COOKIE_FIELDS), False


_NUMERIC_SECRET_ANY = {'password', 'passwd', 'passcode'}
_NUMERIC_SECRET_LAST = {'pwd', 'pin', 'otp'}
_ID_KEYS = {'sessionid', 'session', 'parentuuid', 'uuid', 'requestid', 'id', 'threadid', 'parentthreadid',
            'forkedfromid', 'conversationid', 'parentsessionid'}
_UUID = re.compile(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}')
_ULID = re.compile(r'[0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{26}')


def _key_tokens(key):
    spaced = _CAMEL2.sub(r'\1 \2', _CAMEL1.sub(r'\1 \2', key))
    return [t for t in _SPLIT.split(spaced.lower()) if t]


def _numeric_secret_key(key):
    if not isinstance(key, str) or not key:
        return False
    tokens = _key_tokens(key)
    return bool(tokens) and (any(t in _NUMERIC_SECRET_ANY for t in tokens) or tokens[-1] in _NUMERIC_SECRET_LAST
                             or ''.join(tokens).endswith(('password', 'passwd', 'passcode')))


def _allowlisted(key, value):
    """Mapping and counter fields that are never redacted (spec r3)."""
    if not isinstance(key, str) or not key or isinstance(value, (dict, list)):
        return False
    tokens = _key_tokens(key)
    if not tokens:
        return False
    joined = ''.join(tokens)
    if joined in _ID_KEYS:
        return isinstance(value, str) and bool(_UUID.fullmatch(value) or _ULID.fullmatch(value))
    if joined in ('model', 'type'):
        return True
    if tokens[-1] == 'tokens' or tokens[-2:] == ['token', 'count']:
        return value is None or (isinstance(value, (int, float)) and not isinstance(value, bool))
    return False


def _keyed(value, counts, numeric_secret=False):
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and not numeric_secret:
        return value
    if isinstance(value, str) and MARKER.fullmatch(value):
        return value
    counts['keyed'] = counts.get('keyed', 0) + 1
    return '[REDACTED:keyed]'


def _walk(value, counts, nest):
    if isinstance(value, dict):
        pair, pair_numeric = _pair_is_credential(value)
        out = {}
        for key, item in value.items():
            new_key = _redact_string(key, counts, nest) if isinstance(key, str) else key
            if _allowlisted(key, item):
                out[new_key] = item
            elif pair and key == 'value':
                out[new_key] = _keyed(item, counts, pair_numeric)
            elif _key_is_credential(key):
                out[new_key] = _keyed(item, counts, _numeric_secret_key(key))
            elif isinstance(item, (int, float)) and not isinstance(item, bool) and _numeric_secret_key(key):
                out[new_key] = _keyed(item, counts, True)
            else:
                out[new_key] = _walk(item, counts, nest)
        return out
    if isinstance(value, list):
        if len(value) == 2 and isinstance(value[0], str) and _key_is_credential(value[0]):
            return [_redact_string(value[0], counts, nest), _keyed(value[1], counts, _numeric_secret_key(value[0]))]
        out = [_walk(item, counts, nest) for item in value]
        _redact_argv(value, out, counts)
        return out
    if isinstance(value, str):
        return _redact_string(value, counts, nest)
    return value


_ARGV_SECRET_FLAG = re.compile(
    r'(?i)--(?:[a-z0-9]{1,32}-){0,4}(?:password|passwd|pass|token|secret|api-?key|access-?key|auth-token)|-u|--user')
_ARGV_MYSQL = re.compile(r'(?:^|/)(?:mysql|mysqldump|mysqladmin|mysqlimport|mysqlshow|mariadb|mariadb-dump)$')


def _redact_argv(raw, out, counts):
    """argv lists are scanned element by element, so a flag and its value never share a string:
    ["tool", "--password", X], ["curl", "-u", "user:X"], ["mysql", "-pX"] or ["mysql", "-p", X]."""
    mysql = any(isinstance(item, str) and _ARGV_MYSQL.search(item) for item in raw[:4])
    for i, item in enumerate(raw):
        if not isinstance(item, str):
            continue
        nxt = raw[i + 1] if i + 1 < len(raw) else None
        if _ARGV_SECRET_FLAG.fullmatch(item) and isinstance(nxt, str) and not nxt.startswith('--'):
            if item in ('-u', '--user') and ':' not in nxt:
                continue  # a bare user name is not a secret
            out[i + 1] = _keyed(nxt, counts)
        elif mysql and item.startswith('-p') and len(item) > 2 and not item.startswith('--'):
            out[i] = _keyed(item, counts)
        elif mysql and item == '-p' and isinstance(nxt, str) and not nxt.startswith('-'):
            out[i + 1] = _keyed(nxt, counts)


def _redact_string(text, counts, nest):
    if nest < MAX_NEST:
        head = text.lstrip()[:1]
        if head in ('{', '[', '"'):
            try:
                inner = json.loads(text)
            except ValueError:
                inner = _MISSING
            if inner is not _MISSING and isinstance(inner, (dict, list, str)):
                local = {}
                red = _walk(inner, local, nest + 1)
                if not local:
                    return text  # clean nested JSON keeps its original bytes
                for kind, n in local.items():
                    counts[kind] = counts.get(kind, 0) + n
                return json.dumps(red, ensure_ascii=False)
    return _redact_text(text, counts)


def _dumps(obj):
    out = json.dumps(obj, ensure_ascii=False, separators=(',', ':'))
    return _SURROGATE.sub(lambda m: '\\u%04x' % ord(m.group(0)), out)


def _serialized_pass(serialized, counts):
    """Text shapes again inside each JSON string literal of the serialized record, escape-safe."""
    def literal(match):
        content = match.group(1)
        if '\\' not in content:
            # No escape: the literal is byte-for-byte the decoded string the walk already redacted with the same
            # shapes. The serialized pass exists for what only the escaped form shows (\"password\": \"x\").
            return match.group(0)
        spans = _find_spans(content)
        if not spans:
            return match.group(0)
        spans = _adjust_for_escapes(content, spans)
        return '"' + _apply(content, spans, counts) + '"'
    return _LITERAL.sub(literal, serialized)


def _pass1(line):
    """bytes -> (redacted bytes, counts). Monkeypatched to identity by the pass 2 test."""
    if b'\n' in line:
        raise _Omit('embedded-newline')
    counts = {}
    try:
        text = line.decode('utf-8')
        valid = True
    except UnicodeDecodeError:
        text = line.decode('utf-8', 'surrogateescape')
        valid = False
    obj = _MISSING
    if valid:
        try:
            obj = json.loads(text)
        except ValueError:
            obj = _MISSING
    if obj is _MISSING:
        out = _redact_text(text, counts).replace('\n', '\\n')
        if valid:
            out = _SURROGATE.sub(lambda m: '\\u%04x' % ord(m.group(0)), out)
        else:
            out = _SURROGATE_NOT_ESCAPE.sub(lambda m: '\\u%04x' % ord(m.group(0)), out)
        return out.encode('utf-8', 'surrogateescape'), counts
    serialized = _serialized_pass(_dumps(_walk(obj, counts, 0)), counts)
    try:
        json.loads(serialized)
    except ValueError:
        raise _Omit('reserialize') from None
    return serialized.encode('utf-8'), counts


# ----------------------------------------------------------------------------------------------------------
# Pass 2: independent verifier (separately written shapes; keep it narrower than pass 1 on clean data)
# ----------------------------------------------------------------------------------------------------------

_V2_MARK = r'(?:\[(?:REDACTED|OMITTED):[A-Za-z0-9:_.\-]{1,80}\])'
_V2 = [
    ('v2-anthropic', ('sk-ant-',), re.compile(r'sk-ant-[A-Za-z0-9_\-]{12,}')),
    ('v2-openai', ('sk-',), re.compile(r'(?<![A-Za-z0-9])sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{24,}')),
    ('v2-github', ('ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_', 'github_pat_'),
     re.compile(r'(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})')),
    ('v2-aws', ('akia', 'asia'), re.compile(r'(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])')),
    ('v2-google', ('aiza', 'ya29.'), re.compile(r'AIza[0-9A-Za-z_\-]{35}|ya29\.[0-9A-Za-z_\-]{30,}')),
    ('v2-slack', ('xox',), re.compile(r'xox[abposr]-[0-9A-Za-z\-]{10,}')),
    ('v2-stripe', ('_live_', '_test_', 'whsec_'), re.compile(r'(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{20,}|whsec_[0-9A-Za-z]{20,}')),
    ('v2-huggingface', ('hf_',), re.compile(r'(?<![A-Za-z0-9])hf_[A-Za-z0-9]{30,}')),
    ('v2-gitlab', ('glpat-',), re.compile(r'glpat-[0-9A-Za-z_\-]{20,}')),
    ('v2-npm', ('npm_',), re.compile(r'(?<![A-Za-z0-9])npm_[A-Za-z0-9]{36,}')),
    ('v2-jwt', ('eyj',), re.compile(r'eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}')),
    ('v2-pem', ('-----begin',), re.compile(r'-----BEGIN[A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----')),
    ('v2-bearer', ('bearer',), re.compile(r'(?i)bearer[ \t:=]{1,4}(?=[A-Za-z0-9._~+/\-]{0,200}[0-9])[A-Za-z0-9._~+/\-]{16,}')),
    ('v2-keyword', ('passw', 'secret', 'api', 'access', 'auth', 'private'), re.compile(
        r'(?i)(?:passw(?:or)?d|secret|api[_\-]?key|access[_\-]?token|auth[_\-]?token|client[_\-]?secret|'
        r'private[_\-]?key)["\']?[ \t]{0,4}[:=][ \t]{0,4}["\']?' + _V2_MARK + r'{0,4}'
        r'(?!(?:true|false|null)(?![A-Za-z0-9]))(?!-?[0-9][0-9.eE+\-]{0,64}(?![^\s"\'\[\],;{}]))'
        r'[^\s"\'\[\],;{}]{4,}')),  # a bare number is a kept JSON number; numbers under password keys are keyed
    ('v2-presigned', ('sig', 'x-amz-'), re.compile(
        r'(?i)[?&](?:x-amz-signature|x-amz-credential|x-amz-security-token|x-goog-signature|sig|signature)='
        r'(?!\[)[^&\s"]{8,}')),
    ('v2-userpass', ('-u',), re.compile(r'(?<![^\s"\'])(?:-u|--user)[ \t=]{1,4}[^\s:"\']{1,64}:(?!\[)[^\s"\']{4,}')),
    ('v2-envpass', ('pgpassword', '_pwd', 'secret_key'), re.compile(
        r'(?i)(?:pgpassword|_pwd|secret_key)[ \t]{0,4}=[ \t]{0,4}(?!\[)[^\s"\']{4,}')),
    ('v2-cookie', ('cookie',), re.compile(r'(?i)cookie:[ \t]{0,4}(?!\[)[^=\s;"]{1,64}=[^;\s"]{8,}')),
]
_V2_KEY_SUFFIX = ('password', 'passwd', 'secret', 'apikey', 'accesstoken', 'refreshtoken', 'authtoken',
                  'clientsecret', 'privatekey', 'sessiontoken', 'authorization', 'cookie')
_V2_ANSI = re.compile(r'\x1b(?:\[[\x30-\x3f]{0,64}[\x20-\x2f]{0,16}[\x40-\x7e]|\][^\x07\x1b]{0,4096}(?:\x07|\x1b\\)?|[\x40-\x5f])')
_V2_INVISIBLE = re.compile('[\u00ad\u061c\u180e\u200b\u200c\u200d\u200e\u200f\u202a\u202b\u202c\u202d\u202e'
                           '\u2060\u2061\u2062\u2063\u2064\u2066\u2067\u2068\u2069\ufeff]')
_V2_UESC = re.compile(r'\\u([0-9a-fA-F]{4})')
_V2_QUOTE = re.compile(r'\\+(["\'/])')
_V2_BREAKS = re.compile(r'\r|\n|\\r|\\n')
_V2_ALNUM = re.compile(r'[^a-z0-9]')


def _v2_key_hit(key):
    return isinstance(key, str) and _V2_ALNUM.sub('', key.lower()).endswith(_V2_KEY_SUFFIX)


def _v2_value_hit(value, key=''):
    if value is None or isinstance(value, bool):
        return False
    if isinstance(value, (int, float)):
        return _V2_ALNUM.sub('', str(key).lower()).endswith(('password', 'passwd'))
    if isinstance(value, str):
        return bool(value) and not re.fullmatch(_V2_MARK, value)
    if isinstance(value, (dict, list)):
        return len(value) > 0
    return True


def _v2_copies(text):
    norm = _V2_ANSI.sub('', text)
    norm = _V2_INVISIBLE.sub('', norm)
    if '%' in norm:
        norm = unquote(norm, errors='surrogateescape')
    if '\\u' in norm:
        norm = _V2_UESC.sub(lambda m: chr(int(m.group(1), 16)), norm)
        norm = _V2_INVISIBLE.sub('', _V2_ANSI.sub('', norm))
    if '\\' in norm:
        norm = _V2_QUOTE.sub(r'\1', norm)
    copies = [text]  # the raw copy: decoding can shorten a hit below a minimum length
    for copy in (norm, _V2_BREAKS.sub('', norm)):
        if copy not in copies:
            copies.append(copy)
    return copies


def _v2_scan(text, kinds, depth):
    for copy in _v2_copies(text):
        lower = copy.lower()
        present = {}
        for kind, anchors, pattern in _V2:
            if kind in kinds:
                continue
            hit = False
            for anchor in anchors:
                found = present.get(anchor)
                if found is None:
                    found = present[anchor] = anchor in lower
                if found:
                    hit = True
                    break
            if not hit:
                continue
            if pattern.search(copy):
                kinds.append(kind)
        if depth < MAX_NEST and copy.lstrip()[:1] in ('{', '[', '"'):
            try:
                inner = json.loads(copy)
            except ValueError:
                continue
            if isinstance(inner, (dict, list, str)) and inner != text:
                _v2_walk(inner, kinds, depth + 1)


def _v2_walk(value, kinds, depth):
    if isinstance(value, dict):
        name = value.get('name', value.get('key'))
        if 'value' in value and _v2_key_hit(name) and _v2_value_hit(value['value'], name):
            kinds.append('v2-keyed-pair')
        for key, item in value.items():
            if _v2_key_hit(key) and _v2_value_hit(item, key):
                kinds.append('v2-keyed')
            if isinstance(key, str):
                _v2_scan(key, kinds, depth)
            _v2_walk(item, kinds, depth)
    elif isinstance(value, list):
        for item in value:
            _v2_walk(item, kinds, depth)
    elif isinstance(value, str):
        _v2_scan(value, kinds, depth)


def _pass2(data):
    """Kinds pass 2 finds in one redacted line (bytes, no newline). Never values."""
    text = data.decode('utf-8', 'surrogateescape')
    kinds = []
    obj = _MISSING
    if text.lstrip()[:1] in ('{', '[', '"'):
        try:
            obj = json.loads(text)
        except ValueError:
            obj = _MISSING
    if obj is not _MISSING:
        _v2_walk(obj, kinds, 0)
    _v2_scan(text, kinds, 0 if obj is _MISSING else MAX_NEST)  # the serialized copy (its JSON was walked above)
    seen = []
    for kind in kinds:
        if kind not in seen:
            seen.append(kind)
    return seen


# ----------------------------------------------------------------------------------------------------------
# Public interface
# ----------------------------------------------------------------------------------------------------------

def _omitted(line, line_no, kind):
    record = {'_archive': 'omitted', 'reason': kind, 'line': int(line_no), 'src_len': len(line)}
    return json.dumps(record, separators=(',', ':')).encode('ascii')


def redact_line(line: bytes, line_no: int) -> tuple[bytes, dict, str | None]:
    """One record without its trailing newline -> (output without newline, counts by kind, omitted kind or None).

    On a pass 2 hit or any exception the output is the omitted marker and counts is empty."""
    try:
        out, counts = _pass1(line)
        hits = _pass2(out)
        if hits:
            kind = hits[0]
        else:
            return out, counts, None
    except _Omit as failure:
        kind = failure.kind
    except Exception:  # noqa: BLE001 - fail closed; the exception text may hold a value, so it is dropped
        kind = 'error'
    return _omitted(line, line_no, kind), {}, kind


def verify_bytes(data: bytes) -> list[tuple[str, int]]:
    """Pass 2 over a whole decompressed chunk. Returns (kind, 1-based line) pairs, never values."""
    found = []
    lines = data.split(b'\n')
    if lines and lines[-1] == b'':
        lines.pop()
    for number, line in enumerate(lines, 1):
        try:
            kinds = _pass2(line)
        except Exception:  # noqa: BLE001
            kinds = ['error']
        found.extend((kind, number) for kind in kinds)
    return found
