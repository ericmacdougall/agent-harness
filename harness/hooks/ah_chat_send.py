"""ah chat send: one short direct message to one person, sent by the main agent as the user's bot (goodqa#16399).

  ah chat send (--conversation ID | --with USER_ID_OR_NAME) [--org ID] --text-file /abs/path [--approval-id ID] [--dry-run]

Why this is shaped the way it is. GoodQA's send_direct_message (MCP; POST /v1/orgs/:org/dm/:user) stores the message with
clientMsgId null, so the server has no dedupe for a DM. A retry after a lost answer can deliver the same message twice. So:

- ONE request per invocation and NO automatic retry, ever. A refusal, a timeout or an unclear answer is reported, never resent.
- The same text (by SHA-256) to the same person is refused for SAME_TEXT_WINDOW seconds after ANY earlier attempt, whatever
  its outcome (sent, uncertain, or a crash that left only the pending row). The one exception: every earlier attempt was
  refused by the user-token approval gate (NOT_STORED: approval required, pending, expired, denied or for other text). That
  gate runs before the route handler stores anything (bugtracker apps/api/src/modules/user-tokens/auth-gate.ts:639-697 at
  a70289c7). When it asks for approval the result prints the approval id; once the user approves it in the web app, the
  same command with --approval-id sends that exact body (the server binds the permit to it) and consumes the permit.
- At most RATE_LIMIT attempts per person per RATE_WINDOW seconds, counting every attempt.
- The ledger (~/.agent-harness/state/ah/store/chat-send.jsonl) gets a pending row, written completely and fsynced, BEFORE the
  request; the outcome row after it. A ledger with a malformed or unterminated record refuses every send until a person has
  looked at it: a lost pending row would let the same text go out twice.

Who may send: the main agent only. The proof is a one-shot stamp written by mission_gate's PreToolUse hook only for a payload
caller_identity.is_main accepts, bound to that tool call and to the exact target, org, text-file path and the SHA-256 of the
file's bytes. A sub-agent, a replay, a script and a text file edited after the hook saw it all find no stamp. Without the
installed hook nothing has a stamp, so send fails closed for everyone.

What is sent: PREFIX + the file's text. PREFIX is the one constant "Claude (Eric's bot). ". The text file is an absolute path
to a regular file (no symlink, one link) of at most MAX_CHARS characters of UTF-8 with no control characters other than a line
break. Text holding any secret shape or a piece of either GoodQA token is refused, never sent. No attachments, no channels.

Tokens: the user token sends (and answers whoami); --conversation also reads the DM list with the dedicated dm-read token.
Each request carries exactly one of them, read in-process by gq_browser, sent only to the pinned base. --dry-run reads no token
and makes no request: it prints exactly the body that would be sent.

Records: each attempt appends to the main session's WAL a `chat_send` row with the person, conversation, org, the text's
SHA-256, its length and the outcome. The text itself is never written anywhere but the request.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import time
import uuid

import ah_chat as chat
from ah_chat import ChatError

PREFIX = "Claude (Eric's bot). "
MAX_CHARS = 600
MAX_FILE_BYTES = 4 * MAX_CHARS + 16
RATE_LIMIT = 6
RATE_WINDOW = 3600
SAME_TEXT_WINDOW = 86400
STAMP = "chat-send"
LEDGER = "chat-send.jsonl"
MAX_LEDGER = 8 << 20
MAX_DM_PAGES = 5
# Refusals of the user-token approval gate, which runs before the route handler and so before anything is stored
# (bugtracker apps/api/src/modules/user-tokens/auth-gate.ts:639-697 and service.ts:1364-1412 at a70289c7). An attempt
# answered with one of these did not deliver, so it does not hold the text back. Every other answer does.
NOT_STORED = {"human_approval_required": "approval_required", "human_approval_pending": "approval_pending",
              "approval_expired": "approval_refused", "approval_denied": "approval_refused",
              "approval_mismatch": "approval_refused"}
FREE_STATUSES = frozenset(NOT_STORED.values())
CONTROL = re.compile(r"[\x00-\x09\x0b-\x1f\x7f  ]")


# ------------------------------------------------------------------ the text file

def read_text(path):
    """(text, sha256 of the file's bytes). The file is an absolute path to a regular, singly linked, small UTF-8 file; the
    text is its content with trailing line breaks removed. Every refusal is a fixed message that repeats nothing."""
    if not isinstance(path, str) or not os.path.isabs(path) or "\x00" in path:
        raise ChatError("bad_request", "--text-file is an absolute path to the message text", fixed=True)
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError:
        raise ChatError("bad_request", "--text-file cannot be opened (missing, unreadable or a symlink)", fixed=True) from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ChatError("bad_request", "--text-file must be a regular file with one link", fixed=True)
        if info.st_size > MAX_FILE_BYTES:
            raise ChatError("too_long", "the message is longer than %d characters; send a shorter one" % MAX_CHARS, fixed=True)
        raw = os.read(fd, MAX_FILE_BYTES + 1)
    finally:
        os.close(fd)
    if len(raw) > MAX_FILE_BYTES:
        raise ChatError("too_long", "the message is longer than %d characters; send a shorter one" % MAX_CHARS, fixed=True)
    try:
        text = raw.decode("utf-8").rstrip("\r\n")
    except UnicodeDecodeError:
        raise ChatError("bad_request", "--text-file must be UTF-8 text", fixed=True) from None
    if not text.strip():
        raise ChatError("bad_request", "--text-file is empty", fixed=True)
    if len(text) > MAX_CHARS:
        raise ChatError("too_long", "the message is %d characters; the limit is %d. Send a shorter one (nothing was sent)"
                        % (len(text), MAX_CHARS), fixed=True)
    if CONTROL.search(text.replace("\r\n", "\n")):
        raise ChatError("bad_request", "the message holds control characters; only plain text and line breaks are sent",
                        fixed=True)
    if chat._secret_spans(text):
        raise ChatError("secret_refused", "the message holds a secret-shaped value; nothing was sent or recorded", fixed=True)
    return text, hashlib.sha256(raw).hexdigest()


def _syntax(conversation, with_, org):
    if bool(conversation) == bool(with_):
        raise ChatError("bad_request", "give exactly one of --conversation or --with", fixed=True)
    if conversation is not None and not chat._is_uuid(conversation):
        raise ChatError("bad_request", "--conversation is a conversation id (a UUID)", fixed=True)
    if with_:
        chat._with_syntax(with_)
    chat._org_syntax(org)


def _approval_syntax(approval):
    if approval is not None and not chat._is_uuid(approval):
        raise ChatError("bad_request", "--approval-id is the approval id a previous send printed (a UUID)", fixed=True)


def _parts(conversation, with_, org, text_file, digest, approval):
    target = ("conversation:" + conversation) if conversation else ("with:" + with_.strip().casefold())
    return ["send", target, org or "", os.path.realpath(text_file), digest, approval or ""]


def stamp_parts(conversation, with_, org, text_file, approval=None):
    """The parts a main-agent stamp is bound to: target, org, the text file's real path, the SHA-256 of its bytes and the
    approval id. The hook (mission_gate) computes them here; the sender computes them with _parts from the ONE read of the
    file whose text it sends, so a file swapped between two reads cannot pair one text's stamp with another text's body.
    None when the arguments would be refused anyway."""
    try:
        _syntax(conversation, with_, org)
        _approval_syntax(approval)
        _text, digest = read_text(text_file)
    except ChatError:
        return None
    return _parts(conversation, with_, org, text_file, digest, approval)


# ------------------------------------------------------------------ the ledger

def _ledger_path(home):
    import ah  # noqa: PLC0415
    return ah.store_dir(home) / LEDGER


def _rows(path):
    """Every record, or a ChatError when the ledger is damaged: a record that is not a JSON object, or a last record with no
    line break (a write that did not finish). Fail closed: a lost pending row would let the same text go out twice."""
    try:
        fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return []
    except OSError:
        raise ChatError("ledger_damaged", "the chat-send ledger cannot be read; nothing was sent", 3, fixed=True) from None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode) or os.fstat(fd).st_size > MAX_LEDGER:
            raise ChatError("ledger_damaged", "the chat-send ledger is not a regular file or is too large; nothing was sent",
                            3, fixed=True)
        chunks = []
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        os.close(fd)
    data = b"".join(chunks)
    if data and not data.endswith(b"\n"):
        raise ChatError("ledger_damaged", "the chat-send ledger ends in an unfinished record; a person must check whether "
                                          "that message went out before anything else is sent. Nothing was sent", 3, fixed=True)
    rows = []
    for line in data.splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            row = None
        if not isinstance(row, dict) or not isinstance(row.get("id"), str):
            raise ChatError("ledger_damaged", "the chat-send ledger holds a malformed record; nothing was sent", 3, fixed=True)
        rows.append(row)
    return rows


def _append(path, row):
    """One complete, fsynced line, or a ChatError. A short write is an error, never silently dropped."""
    data = (json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n").encode()
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        done = 0
        while done < len(data):
            wrote = os.write(fd, data[done:])
            if wrote <= 0:
                raise OSError("short write")
            done += wrote
        os.fsync(fd)
    finally:
        os.close(fd)


def _attempts(rows):
    """{attempt id: {"peer", "sha", "at", "status"}} from pending rows and their outcome rows."""
    out = {}
    for row in rows:
        if row.get("kind") == "pending":
            out[row["id"]] = {"peer": row.get("peer"), "sha": row.get("sha"), "at": row.get("at") or 0, "status": "pending"}
        elif row.get("kind") == "outcome" and row.get("ref") in out:
            out[row["ref"]]["status"] = row.get("status")
    return out


def check_ledger(rows, peer, digest, now):
    """Refuse a duplicate or a send over the rate. Every attempt counts, whatever its outcome."""
    mine = [a for a in _attempts(rows).values() if a["peer"] == peer and isinstance(a["at"], (int, float))]
    same = [a for a in mine if a["sha"] == digest and now - a["at"] < SAME_TEXT_WINDOW]
    if same and any(a["status"] not in FREE_STATUSES for a in same):
        raise ChatError("duplicate", "this exact text already went to this person in the last 24 hours (or its outcome is "
                                     "unknown). It is never resent automatically: check `ah chat history` and, if it really "
                                     "did not arrive, send a reworded message. Nothing was sent", fixed=True)
    recent = [a for a in mine if now - a["at"] < RATE_WINDOW]
    if len(recent) >= RATE_LIMIT:
        raise ChatError("rate_limited", "at most %d messages per person per hour; nothing was sent" % RATE_LIMIT, fixed=True)


class _Lock:
    def __init__(self, path):
        self.path = str(path) + ".lock"

    def __enter__(self):
        import fcntl  # noqa: PLC0415
        self.fd = os.open(self.path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        deadline = time.time() + 30
        while True:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except BlockingIOError:
                if time.time() > deadline:
                    os.close(self.fd)
                    raise ChatError("busy", "another chat send is running; nothing was sent", 3, fixed=True) from None
                time.sleep(0.2)

    def __exit__(self, *exc):
        os.close(self.fd)


# ------------------------------------------------------------------ the WAL row

def _wal(home, session, row):
    """The main session's WAL gets a chat_send row: ids, the text's SHA-256 and the outcome, never the text."""
    import ah  # noqa: PLC0415
    record = dict(row, id="w" + uuid.uuid4().hex[:11], event="chat_send", at=ah.iso(time.time()), actor="main")
    ah._wal_append(home, ah._wal_path(home, session, "main"), record)
    return record["id"]


# ------------------------------------------------------------------ resolving the person

def _whoami(client):
    data = client.tool("whoami", {})
    user = data.get("user") if isinstance(data, dict) and isinstance(data.get("user"), dict) else data
    uid = user.get("id") if isinstance(user, dict) else None
    if not chat._is_uuid(uid):
        raise ChatError("unexpected_response", "GoodQA whoami returned no user id", 3)
    return uid


def _peer_of_conversation(home, base, org, conversation, me):
    """The one other person of a 1:1 DM, read from the DM list with the dm-read token (bounded pages, never a group DM)."""
    reader = chat.Client(base, source="dm")
    chat._need(reader, "list_direct_conversations")
    cursor = None
    for _ in range(MAX_DM_PAGES):
        arguments = {"orgId": org, "limit": chat.MAX_LIMIT}
        if cursor:
            arguments["cursor"] = cursor
        data = reader.tool("list_direct_conversations", arguments)
        for row in chat._messages(data):
            if not isinstance(row, dict) or row.get("id") != conversation:
                continue
            if row.get("kind") != "dm":
                raise ChatError("refused", "that conversation is not a one-to-one DM; send goes to one person only", 3)
            ids = [p.get("id") for p in row.get("participants") or [] if isinstance(p, dict)]
            others = [i for i in ids if i != me]
            if len(ids) != 2 or me not in ids or len(others) != 1 or not chat._is_uuid(others[0]):
                raise ChatError("refused", "that DM does not have exactly you and one other person in it", 3)
            chat._refuse_credential_ids(others[0])
            return others[0]
        cursor = data.get("nextCursor") if isinstance(data, dict) and data.get("hasMore") else None
        if not (isinstance(cursor, str) and chat.CURSOR_RE.fullmatch(cursor)):
            break
    raise ChatError("not_found", "that conversation is not among your DMs in this org", 3)


# ------------------------------------------------------------------ the command

def send(home, conversation=None, with_=None, org=None, text_file=None, dry_run=False, base=None, now=None, approval=None):
    chat._pinned_base(base)  # first: a refused base reads nothing
    _syntax(conversation, with_, org)
    _approval_syntax(approval)
    text, digest = read_text(text_file)  # the one read: the stamp below is matched against this text's digest
    body = PREFIX + text
    target = {"conversation": conversation} if conversation else {"with": with_}
    if dry_run:  # no token, no request, no ledger row, no stamp
        return {"ok": True, "dry_run": True, "tool": "send_direct_message", **target, "org": org,
                "body": body, "chars": len(body), "text_sha256": digest,
                "note": "nothing was sent; without --dry-run this exact body goes to the person once, never retried"}
    import caller_identity  # noqa: PLC0415
    stamp = caller_identity.take_stamp(STAMP, _parts(conversation, with_, org, text_file, digest, approval), home=home,
                                       bound=True)
    if stamp is None:
        raise ChatError("main_only", "only the main agent sends chat messages: its own hook stamps this exact command (target, "
                                     "org, text file and its content). None was found: a sub-agent, a script, a replay, a "
                                     "text file changed after the command started, or a host where the mission_gate hook "
                                     "with chat-send support is not installed. Nothing was read or sent", fixed=True)
    session = stamp.get("session") if isinstance(stamp.get("session"), str) else ""
    import ah  # noqa: PLC0415
    if not ah.SESSION_RE.match(session):
        raise ChatError("main_only", "the stamp names no main session to record the send in; nothing was sent", fixed=True)
    now = time.time() if now is None else now
    path = _ledger_path(home)
    with _Lock(path):
        rows = _rows(path)
        client = chat.Client(base, source="user")
        org = chat._org(client, org)
        if conversation:
            me = _whoami(client)
            peer, shown = _peer_of_conversation(home, base, org, conversation, me), None
        else:
            peer, shown, _hit = chat._user(client, org, with_)
        if chat._holds_token(body):  # now both tokens are loaded: a piece of either is never sent
            raise ChatError("secret_refused", "the message holds a piece of a GoodQA token; nothing was sent", fixed=True)
        check_ledger(rows, peer, digest, now)
        attempt = uuid.uuid4().hex
        record = {"peer": peer, "org": org, "conversation": conversation, "text_sha256": digest, "chars": len(body)}
        try:
            _append(path, {"id": attempt, "kind": "pending", "peer": peer, "org": org, "conversation": conversation,
                           "sha": digest, "at": now})
        except OSError:
            raise ChatError("ledger_damaged", "the pending record could not be written completely; nothing was sent. Check "
                                              "the chat-send ledger before sending again", 3, fixed=True) from None
        status, message_id, sent_conv, code, approval_id = "uncertain", None, None, None, None
        arguments = {"orgId": org, "userId": peer, "body": body}
        if approval:
            arguments["approvalId"] = approval
        try:  # exactly one request: whatever happens below, nothing here sends again
            data = client.tool("send_direct_message", arguments)
            message = data.get("message") if isinstance(data, dict) and isinstance(data.get("message"), dict) else {}
            message_id = message.get("id") if chat._is_uuid(message.get("id")) else None
            sent_conv = data.get("conversationId") if isinstance(data, dict) and chat._is_uuid(data.get("conversationId")) else None
            status = "sent" if message_id else "uncertain"
        except ChatError as error:
            code = getattr(error, "server_code", None)
            status = NOT_STORED.get(code, "uncertain")
            approval_id = getattr(error, "approval_id", None) if status in FREE_STATUSES else None
        outcome = {"id": uuid.uuid4().hex, "kind": "outcome", "ref": attempt, "status": status, "message": message_id,
                   "at": time.time()}
        try:
            _append(path, outcome)
        except OSError:
            pass  # the pending row already counts as an attempt: the same text stays refused
        try:
            wal_id = _wal(home, session, dict(record, status=status, message=message_id, attempt=attempt))
        except Exception:  # noqa: BLE001 - the request already happened: report it, never let a traceback hide it
            wal_id = None
    result = {"ok": status == "sent", "status": status, **target, "peer": peer, "org": org, "chars": len(body),
              "text_sha256": digest, "wal": wal_id, "retry": "never automatic"}
    if wal_id is None:
        result["wal_warning"] = "the WAL row could not be written; the chat-send ledger still records this attempt"
    if shown:
        result["with_name"] = shown
    if message_id:
        result["message"] = message_id
    if sent_conv:
        result["sent_conversation"] = sent_conv
        if conversation and sent_conv != conversation:
            result["warning"] = "GoodQA delivered into a different conversation than the one named"
    if status in FREE_STATUSES:
        result["server_code"] = code
        if approval_id:
            result["approval_id"] = approval_id
    if status in ("approval_required", "approval_pending"):
        result["next"] = ("GoodQA holds this send for the user's approval (his user token's approval setting). Nothing was "
                          "stored. He approves it in the GoodQA web app under Account > User tokens; then run the same "
                          "command with the same text file and --approval-id %s" % (approval_id or approval or "<id>"))
    elif status == "approval_refused":
        result["next"] = ("GoodQA refused the approval (%s): it expired, was denied, or was given for different text. Nothing "
                          "was stored. Run the command without --approval-id to ask for a new approval" % code)
    elif status == "uncertain":
        result["next"] = ("the outcome is unknown. Do NOT resend: read `ah chat history` to see whether it arrived. The same "
                          "text stays refused for 24 hours")
    return chat._checked(result)
