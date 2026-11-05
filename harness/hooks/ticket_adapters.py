"""Pluggable ticket-system adapters for the commit policy.

Each adapter answers three questions for a referenced ticket: does it exist,
what discussion happened after a time, and (at delivery) post a comment.
Adapters fail closed: any transport or shape surprise raises
TicketSystemUnavailable, which callers report as "could not verify".
Credentials are read from a private file and never printed or logged.
"""

from __future__ import annotations

import json
import os
import re
import socket
import stat
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


class TicketSystemUnavailable(Exception):
    """The ticket system could not be reached or answered unexpectedly."""


class TicketOutOfScope(Exception):
    """The ticket system answered, but this credential cannot see the ticket's project.

    Distinct from "ticket missing": a project in another organisation (for example the
    another org while the member key reaches ExampleOrg only) cannot be verified at all.
    """


class Ticket:
    def __init__(self, system, project, number, ticket_id, title, status, url=None):
        self.system, self.project, self.number = system, project, number
        self.id, self.title, self.status, self.url = ticket_id, title, status, url

    @property
    def label(self):
        return f"{self.system} {self.project}#{self.number}"


class Comment:
    def __init__(self, created_at: datetime, body: str):
        self.created_at, self.body = created_at, body


def parse_time(value) -> datetime:
    if not isinstance(value, str):
        raise TicketSystemUnavailable("ticket system returned a comment without a timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise TicketSystemUnavailable("ticket system returned an unparseable timestamp") from None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def read_key(path: str) -> str:
    key_path = Path(os.path.expanduser(path))
    try:
        fd = os.open(key_path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        raise TicketSystemUnavailable(f"ticket credential file is missing or unreadable: {path}") from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > 4096:
            raise TicketSystemUnavailable(f"ticket credential file is not a small regular file: {path}")
        if info.st_mode & 0o077:
            raise TicketSystemUnavailable(f"ticket credential file must be private (chmod 600): {path}")
        key = os.read(fd, 4097).decode("utf-8", "replace").strip()
    finally:
        os.close(fd)
    if not key or any(ch.isspace() for ch in key):
        raise TicketSystemUnavailable(f"ticket credential file is empty or malformed: {path}")
    return key


# Tools a Secret Manager credential may call: the policy only verifies tickets with it.
READ_ONLY_TOOLS = frozenset({"list_orgs", "list_projects", "get_issue_by_number", "get_issue_comments"})


def read_secret(spec: dict, timeout: float = 30.0) -> str:
    """Read a Secret Manager value in-process from gcloud's stdout.

    The value never appears in argv, the environment or a file, and is never cached on disk.
    """
    import subprocess
    name, project = (spec or {}).get("name"), (spec or {}).get("project")
    if not (isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,255}", name)
            and isinstance(project, str) and re.fullmatch(r"[a-z][a-z0-9-]{4,61}[a-z0-9]", project)):
        raise TicketSystemUnavailable("key_secret needs a valid Secret Manager name and project")
    try:
        result = subprocess.run(["gcloud", "secrets", "versions", "access", "latest", "--secret=" + name,
                                 "--project=" + project], capture_output=True, timeout=max(1.0, min(30.0, timeout)),
                                stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        raise TicketSystemUnavailable(f"Secret Manager credential {name} could not be read (gcloud)") from None
    if result.returncode != 0:
        # gcloud's stderr is never echoed (it may quote the value); the exit code is enough to triage auth/IAM.
        raise TicketSystemUnavailable(f"Secret Manager credential {name} could not be read (gcloud exit "
                                      f"{result.returncode}; check gcloud auth and secretAccessor on {project})")
    key = result.stdout.decode("utf-8", "replace").strip()
    if not key or len(key) > 4096 or any(ch.isspace() for ch in key):
        raise TicketSystemUnavailable(f"Secret Manager credential {name} is empty or malformed")
    return key


class GoodQAAdapter:
    """GoodQA through its MCP JSON-RPC endpoint (tools/call)."""

    name = "goodqa"

    def __init__(self, config: dict, *, deadline: float | None = None):
        self.config = config
        self.endpoint = config.get("endpoint") or ""
        if not self.endpoint.startswith(("https://", "http://127.0.0.1", "http://localhost")):
            raise TicketSystemUnavailable("GoodQA endpoint must be https (or loopback for tests)")
        self.timeout = float(config.get("timeout_seconds", 15))
        self.attempts = max(1, min(int(config.get("attempts", 2)), 3))
        total = float(config.get("total_deadline_seconds", 90))
        self.deadline = deadline if deadline is not None else time.monotonic() + total
        self._key = None
        self._read_only = False
        self._org = config.get("org_id")

    def _load_key(self):
        """The private key file wins; without it, a configured Secret Manager key is read-only."""
        path = self.config.get("key_file") or ""
        secret = self.config.get("key_secret")
        if secret and not Path(os.path.expanduser(path)).exists():
            self._key, self._read_only = read_secret(secret, self._remaining()), True
        else:
            self._key = read_key(path)

    def _remaining(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TicketSystemUnavailable("GoodQA verification exceeded its total deadline")
        return min(self.timeout, remaining)

    def call(self, tool: str, arguments: dict):
        if self._key is None:
            self._load_key()
        if self._read_only and tool not in READ_ONLY_TOOLS:
            raise TicketSystemUnavailable(
                f"GoodQA {tool} refused: the Secret Manager credential is read-only for the commit policy; "
                "post ticket comments from a host with the member key file (the Mac)")
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                           "params": {"name": tool, "arguments": arguments}}).encode()
        last = "no attempt"
        for attempt in range(self.attempts):
            request = urllib.request.Request(self.endpoint, data=body, method="POST", headers={
                "authorization": "Bearer " + self._key, "content-type": "application/json",
                "accept": "application/json, text/event-stream"})
            try:
                with urllib.request.urlopen(request, timeout=self._remaining()) as response:
                    raw = response.read(8_000_001)
                break
            except urllib.error.HTTPError as error:
                # Authentication and policy refusals are not retried.
                raise TicketSystemUnavailable(f"GoodQA HTTP {error.code} for {tool}") from None
            except (urllib.error.URLError, socket.timeout, ConnectionError, OSError) as error:
                last = type(getattr(error, "reason", error)).__name__
                if attempt + 1 < self.attempts:
                    time.sleep(min(1.0 * (attempt + 1), max(0.0, self.deadline - time.monotonic())))
        else:
            raise TicketSystemUnavailable(f"GoodQA unreachable for {tool} ({last})")
        if len(raw) > 8_000_000:
            raise TicketSystemUnavailable("GoodQA response exceeded size budget")
        text = raw.decode("utf-8", "replace")
        frames = re.findall(r"^data: (.*)$", text, re.M)
        try:
            envelope = json.loads(frames[-1] if frames else text)
            result = envelope["result"]
            content = result["content"][0]["text"]
            data = json.loads(content)
        except (ValueError, KeyError, IndexError, TypeError):
            raise TicketSystemUnavailable(f"GoodQA returned an unexpected shape for {tool}") from None
        if result.get("isError"):
            # GoodQA wraps payloads as {"dataTrust": ..., "data": {...}}; errors sit under data.error.
            inner = data.get("data") if isinstance(data, dict) and isinstance(data.get("data"), dict) else data
            error = inner.get("error") if isinstance(inner, dict) else None
            code = error.get("code") if isinstance(error, dict) else "error"
            details = error.get("details") if isinstance(error, dict) else None
            reason = details.get("reason") if isinstance(details, dict) else None
            # Only machine codes are kept: messages can echo untrusted filenames or content.
            code = str(code)
            found = {"__error__": code if re.fullmatch(r"[a-z_]{1,40}", code) else "error"}
            if isinstance(reason, str) and re.fullmatch(r"[a-z_]{1,40}", reason):
                found["__reason__"] = reason
            return found
        return data

    def org_id(self):
        if self._org:
            return self._org
        data = self.call("list_orgs", {})
        orgs = data.get("orgs") if isinstance(data, dict) else None
        if not isinstance(orgs, list) or len(orgs) != 1 or not isinstance(orgs[0], dict):
            raise TicketSystemUnavailable("GoodQA credential reaches zero or several orgs; set org_id in commit_policy.json")
        self._org = orgs[0].get("id")
        return self._org

    def lookup(self, project: str, number: int):
        data = self.call("get_issue_by_number", {"projectSlug": project, "orgId": self.org_id(),
                                                 "number": int(number)})
        if data.get("__error__") == "not_found":
            return None
        if data.get("__error__") == "project_not_found":
            raise TicketOutOfScope(f"GoodQA project {project!r} is not visible to this credential "
                                   f"(org {self.org_id()})")
        if "__error__" in data:
            raise TicketSystemUnavailable(f"GoodQA lookup failed ({data['__error__']})")
        issue = data.get("issue", data)
        if not isinstance(issue, dict) or not isinstance(issue.get("id"), str) or issue.get("number") != int(number):
            raise TicketSystemUnavailable("GoodQA lookup returned an unexpected issue")
        ticket = Ticket("GoodQA", project, int(number), issue["id"], str(issue.get("title") or ""),
                        str(issue.get("status") or ""))
        ticket.project_id = issue.get("projectId")
        ticket.description = str(issue.get("description") or "")
        ticket.closed = bool(issue.get("closedAt")) or ticket.status in ("done", "wont_fix", "duplicate")
        return ticket

    def comments_since(self, ticket: Ticket, since: datetime):
        """Newest-first pages until a page starts before `since` or the page budget ends."""
        found, cursor = [], None
        for _ in range(max(1, int(self.config.get("max_comment_pages", 5)))):
            arguments = {"issueId": ticket.id, "order": "desc", "limit": 100}
            if cursor:
                arguments["cursor"] = cursor
            data = self.call("get_issue_comments", arguments)
            if "__error__" in data or not isinstance(data.get("comments"), list):
                raise TicketSystemUnavailable("GoodQA comments could not be read")
            oldest = None
            for item in data["comments"]:
                if not isinstance(item, dict):
                    raise TicketSystemUnavailable("GoodQA returned a malformed comment")
                created = parse_time(item.get("createdAt"))
                oldest = created if oldest is None or created < oldest else oldest
                if created >= since and not item.get("archivedAt"):
                    found.append(Comment(created, str(item.get("body") or "")))
            cursor = data.get("nextCursor")
            if not data.get("hasMore") or not cursor or (oldest is not None and oldest < since):
                return found
        raise TicketSystemUnavailable("GoodQA comment history exceeded the page budget; raise max_comment_pages")

    def comment(self, ticket: Ticket, body: str, operation_id: str):
        data = self.call("comment_on_issue", {"issueId": ticket.id, "body": body, "operationId": operation_id})
        if "__error__" in data:
            raise TicketSystemUnavailable(f"GoodQA comment failed ({data['__error__']})")
        return data

    def set_status(self, ticket: Ticket, status: str):
        data = self.call("update_issue", {"issueId": ticket.id, "patch": {"status": status}})
        if "__error__" in data:
            raise TicketSystemUnavailable(f"GoodQA status update failed ({data['__error__']})")
        return data

    # ---- spec flow (spec_flow.py): issue reads, attachments, uploads and the done transition

    def issue(self, issue_id: str):
        """Return the issue dict, or None when this credential cannot see it."""
        return self.issue_access(issue_id)[0]

    def issue_access(self, issue_id: str):
        """(issue, None) when readable, or (None, "not_found" | "forbidden") when this credential cannot see it."""
        data = self.call("get_issue", {"issueId": issue_id})
        if data.get("__error__") in ("not_found", "forbidden"):
            return None, data["__error__"]
        if "__error__" in data:
            raise TicketSystemUnavailable(f"GoodQA issue read failed ({data['__error__']})")
        issue = data.get("issue", data)
        if not isinstance(issue, dict) or issue.get("id") != issue_id:
            raise TicketSystemUnavailable("GoodQA returned an unexpected issue")
        return issue, None

    def all_comments(self, issue_id: str, *, max_pages: int | None = None):
        """Every active comment, oldest first. Running out of pages fails closed."""
        pages = max(1, int(max_pages or self.config.get("max_comment_pages", 5)))
        found, cursor = [], None
        for _ in range(pages):
            arguments = {"issueId": issue_id, "order": "asc", "limit": 200}
            if cursor:
                arguments["cursor"] = cursor
            data = self.call("get_issue_comments", arguments)
            if "__error__" in data or not isinstance(data.get("comments"), list):
                raise TicketSystemUnavailable("GoodQA comments could not be read")
            for item in data["comments"]:
                if not isinstance(item, dict) or not isinstance(item.get("id"), str):
                    raise TicketSystemUnavailable("GoodQA returned a malformed comment")
                if not item.get("archivedAt"):
                    found.append(item)
            cursor = data.get("nextCursor")
            if not data.get("hasMore") or not cursor:
                return found
        raise TicketSystemUnavailable("too many records on this ticket for the comment page budget; "
                                      "raise max_comment_pages")

    def attachments(self, issue_id: str):
        data = self.call("issue_attachments_list", {"issueId": issue_id})
        if "__error__" in data or not isinstance(data.get("attachments"), list):
            raise TicketSystemUnavailable("GoodQA attachments could not be listed")
        return [item for item in data["attachments"] if isinstance(item, dict)]

    def upload(self, project_id: str, filename: str, mime: str, payload: bytes, sha256: str) -> str:
        """Project-surface upload: start, PUT to the presigned URL, complete with the sha256."""
        started = self.call("file_upload_start", {"surface": "project", "id": project_id, "filename": filename,
                                                  "mime": mime, "sizeBytes": len(payload)})
        started = started.get("data", started) if isinstance(started, dict) else {}
        if "__error__" in started:
            raise TicketSystemUnavailable(f"GoodQA upload start failed ({started['__error__']})")
        attachment, target = started.get("attachment") or {}, started.get("upload") or {}
        url, headers = target.get("url"), target.get("headers") or {}
        if not isinstance(attachment.get("id"), str) or not isinstance(url, str) or not isinstance(headers, dict):
            raise TicketSystemUnavailable("GoodQA upload start returned an unexpected shape")
        self._check_upload_url(url)
        request = urllib.request.Request(url, data=payload, method=str(target.get("method") or "PUT"),
                                         headers={str(k): str(v) for k, v in headers.items()})
        try:
            with urllib.request.urlopen(request, timeout=max(self._remaining(), 30.0)) as response:
                response.read(65536)
        except urllib.error.HTTPError as error:
            raise TicketSystemUnavailable(f"upload storage refused the file (HTTP {error.code})") from None
        except (urllib.error.URLError, socket.timeout, ConnectionError, OSError) as error:
            raise TicketSystemUnavailable(f"upload storage unreachable ({type(error).__name__})") from None
        done = self.call("file_upload_complete", {"id": attachment["id"], "expectedSha256": sha256})
        done = done.get("data", done) if isinstance(done, dict) else {}
        if "__error__" in done:
            raise TicketSystemUnavailable(f"GoodQA upload verification failed ({done['__error__']}"
                                          f"{', ' + done['__reason__'] if '__reason__' in done else ''})")
        row = done.get("attachment") or {}
        if row.get("completionState") != "completed" or row.get("sha256") != sha256:
            raise TicketSystemUnavailable("GoodQA did not verify the uploaded bytes")
        return attachment["id"]

    def _check_upload_url(self, url: str):
        parsed = urllib.parse.urlsplit(url)
        host = (parsed.hostname or "").lower()
        loopback = host in ("127.0.0.1", "localhost") and self.endpoint.startswith(("http://127.0.0.1",
                                                                                    "http://localhost"))
        suffixes = self.config.get("upload_host_suffixes") or [".digitaloceanspaces.com"]
        if loopback:
            return
        if parsed.scheme != "https" or not any(host.endswith(s) for s in suffixes):
            raise TicketSystemUnavailable("GoodQA returned an upload URL outside the allowed storage hosts")

    def comment_with_files(self, issue_id: str, body: str, operation_id: str, attachment_ids=()):
        arguments = {"issueId": issue_id, "body": body, "operationId": operation_id}
        if attachment_ids:
            arguments["attachmentIds"] = list(attachment_ids)
        data = self.call("comment_on_issue", arguments)
        if "__error__" in data:
            raise TicketSystemUnavailable(f"GoodQA comment failed ({data['__error__']})")
        comment = data.get("comment", data)
        if not isinstance(comment, dict) or not isinstance(comment.get("id"), str):
            raise TicketSystemUnavailable("GoodQA comment returned an unexpected shape")
        return comment

    def close_done(self, issue_id: str, note: str):
        """Request status done. Returns (ok, detail); a refusal is not retried."""
        data = self.call("close_issue_done", {"issueId": issue_id, "status": "done", "note": note})
        if "__error__" in data:
            return False, data["__error__"]
        return True, "done"

    def update_instructions(self, ticket: Ticket, names: str) -> str:
        return (f"Comment on {ticket.label} naming {names}, for example with the GoodQA MCP tool "
                f"comment_on_issue (issueId {ticket.id}) or the GoodQA UI.")


LEDGER_TICKET_ID = re.compile(r"tk_[0-9A-HJKMNP-TV-Z]{26}")
LEDGER_VERSION = re.compile(r"(\d{1,6})\.(\d{1,6})\.(\d{1,6})")


class LedgerAdapter:
    """Resolve `Ledger <slug>#<hex>` handles through the local `harness tickets` binary.

    A temporary Python <-> Go seam until commit-policy is ported (P4): one call with a hard
    deadline whose process group is killed on timeout. Anything other than a well-formed
    answer from a new-enough binary raises TicketSystemUnavailable ("could not verify");
    "not found" and "ambiguous" are reported only when the binary says so in JSON.
    Only tickets from this machine's own (self) and explicitly trusted writers are visible,
    because the binary folds nothing else. The ledger has no comments API for delivery.
    """

    def __init__(self, config: dict, runner=None, which=None):
        self.config = config
        self.binary = str(config.get("binary") or "harness")
        self.min_version = str(config.get("min_version") or "0.1.0")
        if not LEDGER_VERSION.fullmatch(self.min_version):
            raise TicketSystemUnavailable("ledger min_version must be MAJOR.MINOR.PATCH")
        self.timeout = min(float(config.get("timeout_seconds", 5)), 5.0)
        if runner is None:
            from process import run as runner
        self.runner = runner
        if which is None:
            import shutil
            which = shutil.which
        self.which = which

    def _executable(self) -> str:
        path = self.binary if os.path.isabs(self.binary) else self.which(self.binary)
        if not path or not os.path.isabs(path) or not os.access(path, os.X_OK):
            raise TicketSystemUnavailable(f"ledger binary {self.binary!r} not found on PATH")
        return path

    def resolve(self, slug: str, handle: str, *, cwd: str, as_of_ms: int):
        """Return ("ok", Ticket), ("not_found", None) or ("ambiguous", None)."""
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", slug) or not re.fullmatch(r"[0-9a-f]{8,64}", handle):
            return "not_found", None
        command = [self._executable(), "tickets", "show", handle, "--json", "--min-version", self.min_version,
                   "--as-of", str(int(as_of_ms)), "--slug", slug]
        # No GIT_* (the repository is chosen by cwd) and no HARNESS_LEDGER_* test variables, which a
        # test build would honour (fake clock or machine id could defeat the --as-of bound).
        env = {k: v for k, v in os.environ.items() if not k.startswith(("GIT_", "HARNESS_LEDGER_"))}
        env["GIT_TERMINAL_PROMPT"] = "0"
        try:
            result = self.runner(command, cwd=cwd, env=env, timeout=self.timeout, input="")
        except subprocess.TimeoutExpired as error:
            raise TicketSystemUnavailable(f"ledger binary did not answer within {self.timeout:g}s") from error
        except OSError as error:
            raise TicketSystemUnavailable(f"ledger binary could not run ({type(error).__name__})") from error
        try:
            data = json.loads(result.stdout or "")
        except ValueError:
            raise TicketSystemUnavailable("ledger binary printed non-JSON output") from None
        if not isinstance(data, dict):
            raise TicketSystemUnavailable("ledger binary printed an unexpected JSON shape")
        if result.returncode == 3 and data.get("error") in ("not_found", "ambiguous"):
            return data["error"], None
        if result.returncode != 0:
            # Exit 2 covers "older than --min-version" and an unknown --as-of flag; both fail closed.
            raise TicketSystemUnavailable(f"ledger binary failed (exit {result.returncode}, "
                                          f"{str(data.get('error') or 'unknown')[:40]})")
        version = LEDGER_VERSION.fullmatch(str(data.get("ledger_version") or ""))
        if not version or tuple(map(int, version.groups())) < tuple(
                map(int, LEDGER_VERSION.fullmatch(self.min_version).groups())):
            raise TicketSystemUnavailable("ledger binary is older than the required version")
        ticket = data.get("ticket")
        if (data.get("slug") != slug or not isinstance(ticket, dict)
                or not LEDGER_TICKET_ID.fullmatch(str(ticket.get("id") or ""))
                or not isinstance(ticket.get("title"), str) or not isinstance(ticket.get("status"), str)):
            raise TicketSystemUnavailable("ledger binary answered for a different ledger or ticket shape")
        shown = str(ticket.get("handle") or "")
        if not re.fullmatch(r"[0-9a-f]{8,64}", shown) or not (shown.startswith(handle) or handle.startswith(shown)):
            raise TicketSystemUnavailable("ledger binary answered for a different handle")
        created = ticket.get("created_ms")
        if not isinstance(created, int) or created >= int(as_of_ms):
            raise TicketSystemUnavailable("ledger binary ignored --as-of")
        return "ok", Ticket("ledger", slug, handle, ticket["id"], ticket["title"], ticket["status"])

    # The generic verification/notification paths never route ledger refs here (ticket_refs
    # excludes them by default); if one ever does, it fails closed instead of guessing.
    def lookup(self, project, number):
        raise TicketSystemUnavailable("ledger tickets are verified only through resolve()")

    def comments_since(self, ticket, since):
        raise TicketSystemUnavailable("the local ledger has no comment feed for delivery checks")

    def comment(self, ticket, body, op):
        raise TicketSystemUnavailable("the local ledger does not accept delivery comments")

    def update_instructions(self, ticket, names: str) -> str:
        return f"Ledger {ticket.project}#{ticket.number} is local; reference a GoodQA ticket for delivery."


ADAPTERS = {"goodqa": GoodQAAdapter, "ledger": LedgerAdapter}


def project_config(config: dict, project: str | None, routes: dict | None = None) -> dict:
    """Route a project slug to its own org and key (a GoodQA key is bound to one org).

    `routes` maps slug -> {"org_id": ..., "key_file": ...}; it defaults to config["projects"].
    Unlisted projects keep the system's default org and key.
    """
    routes = routes if routes is not None else (config.get("projects") or {})
    route = routes.get((project or "").lower()) if isinstance(routes, dict) else None
    if not isinstance(route, dict):
        return config
    merged = dict(config)
    for key in ("org_id", "key_file", "endpoint"):
        if route.get(key):
            merged[key] = route[key]
    return merged


def adapter_for(config: dict, **kwargs):
    kind = config.get("adapter")
    if kind not in ADAPTERS:
        raise TicketSystemUnavailable(f"no ticket adapter named {kind!r}")
    return ADAPTERS[kind](config, **kwargs)
