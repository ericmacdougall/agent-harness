#!/usr/bin/python3 -I
"""Create ONE Cloudflare DNS record and nothing else:

    A  timbar-staging.transition2.ai -> 159.203.13.118   (DNS only, TTL 300)

Run as `/usr/bin/python3 -I <this file>` with no arguments. Every value is a constant in this file. The API token is read
from GCP Secret Manager into memory, sent only to api.cloudflare.com in the Authorization header, and never printed,
logged, written to disk, placed in argv or exported. All output is built from fixed text, numbers and the constants below.

Idempotent: when the record already exists exactly as wanted it reports that and exits 0. When any other record holds
the name it changes nothing and exits 4. Python 3.9, standard library only.

Exit codes: 0 created or already present; 2 arguments given; 3 secret unreadable or malformed; 4 zone not visible or a
conflicting record; 5 the create call failed or its result could not be confirmed; 70 unexpected error.
"""
import json
import os
import pwd
import re
import subprocess
import sys
import urllib.error
import urllib.request

PROJECT = "goodqa-28dd3"
SECRET = "GOODQA_CLOUDFLARE_API_TOKEN"
ZONE = "transition2.ai"
NAME = "timbar-staging.transition2.ai"
IPV4 = "159.203.13.118"
TTL = 300
COMMENT = "TIMBAR staging (IP-restricted at nginx)"
GCLOUD = "/opt/homebrew/bin/gcloud"
GCLOUD_PATH = "/opt/homebrew/bin:/usr/bin:/bin"  # gcloud needs a Python newer than the system one to start
API = "https://api.cloudflare.com/client/v4"
MAX_BODY = 1 << 20
TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{20,200}")
ZONE_ID_RE = re.compile(r"[0-9a-f]{32}")


class Stop(Exception):
    """A planned exit: an exit code and a line of fixed text."""

    def __init__(self, code, text):
        super().__init__(text)
        self.code, self.text = code, text


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # the Authorization header never follows a redirect
        return None


# No proxy from the environment (-I does not stop urllib reading *_proxy variables), and no redirects.
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())


def read_token():
    env = {"HOME": pwd.getpwuid(os.getuid()).pw_dir, "PATH": GCLOUD_PATH, "CLOUDSDK_CORE_DISABLE_PROMPTS": "1"}
    try:
        done = subprocess.run(
            [GCLOUD, "secrets", "versions", "access", "latest", "--secret", SECRET, "--project", PROJECT],
            env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=60)
    except (OSError, subprocess.SubprocessError):
        raise Stop(3, "FAILED secret: the secret tool did not run or timed out") from None
    if done.returncode != 0:
        raise Stop(3, "FAILED secret: the secret tool exited %d" % done.returncode)
    try:
        token = done.stdout.decode("ascii").strip()
    except UnicodeDecodeError:
        token = ""
    if not TOKEN_RE.fullmatch(token):
        raise Stop(3, "FAILED secret: the value does not look like an API token")
    return token


def send(request):
    """(status, body bytes) for one request. Tests replace this function."""
    try:
        with _OPENER.open(request, timeout=30) as response:
            return response.status, response.read(MAX_BODY + 1)
    except urllib.error.HTTPError as error:
        try:
            return error.code, error.read(MAX_BODY + 1)
        finally:
            error.close()


def call(token, method, path, body=None):
    """(status, parsed object or {}) and never an exception that carries the request."""
    request = urllib.request.Request(
        API + path, method=method, data=(json.dumps(body).encode() if body is not None else None),
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json", "Accept": "application/json"})
    try:
        status, raw = send(request)
    except Exception:  # noqa: BLE001 - network, TLS or timeout; the reason is not needed and is not echoed
        return 0, {}
    if len(raw) > MAX_BODY:
        return int(status), {}
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError):
        parsed = {}
    return int(status), parsed if isinstance(parsed, dict) else {}


def results(parsed):
    rows = parsed.get("result")
    return [r for r in rows if isinstance(r, dict)] if isinstance(rows, list) else []


def error_codes(parsed):
    rows = parsed.get("errors")
    codes = [r.get("code") for r in rows if isinstance(r, dict)] if isinstance(rows, list) else []
    return sorted(c for c in codes if isinstance(c, int) and not isinstance(c, bool))[:10]


def wanted(record):
    return (record.get("type") == "A" and record.get("name") == NAME and record.get("content") == IPV4
            and record.get("proxied") is False)


def run():
    token = read_token()
    status, parsed = call(token, "GET", "/zones?name=" + ZONE)
    zones = [z for z in results(parsed) if z.get("name") == ZONE]
    if status != 200 or parsed.get("success") is not True or len(zones) != 1 or zones[0].get("status") != "active":
        raise Stop(4, "FAILED zone: %s is not visible and active for this credential (HTTP %d, codes %s)"
                   % (ZONE, status, error_codes(parsed)))
    zone_id = zones[0].get("id")
    if not isinstance(zone_id, str) or not ZONE_ID_RE.fullmatch(zone_id):
        raise Stop(4, "FAILED zone: the zone id has an unexpected form")
    records_path = "/zones/%s/dns_records" % zone_id
    status, parsed = call(token, "GET", records_path + "?name=" + NAME)
    if status != 200 or parsed.get("success") is not True or not isinstance(parsed.get("result"), list):
        raise Stop(4, "FAILED lookup: could not list records for %s (HTTP %d, codes %s); nothing was changed"
                   % (NAME, status, error_codes(parsed)))
    existing = results(parsed)
    if len(existing) != len(parsed["result"]):
        raise Stop(4, "FAILED lookup: the record list has an unexpected form; nothing was changed")
    if len(existing) == 1 and wanted(existing[0]):
        return "OK already present: A %s -> %s, DNS only" % (NAME, IPV4)
    if existing:
        raise Stop(4, "CONFLICT: %d other record(s) already hold %s; nothing was changed" % (len(existing), NAME))
    status, parsed = call(token, "POST", records_path,
                          {"type": "A", "name": NAME, "content": IPV4, "ttl": TTL, "proxied": False, "comment": COMMENT})
    created = parsed.get("result")
    if status == 200 and parsed.get("success") is True and isinstance(created, dict) and wanted(created):
        return "OK created: A %s -> %s, DNS only, TTL %d" % (NAME, IPV4, TTL)
    raise Stop(5, "FAILED create: HTTP %d, codes %s; run again to see whether the record exists"
               % (status, error_codes(parsed)))


def main(argv):
    if len(argv) != 1:
        print("usage: this script takes no arguments", file=sys.stderr)
        return 2
    try:
        text, code = run(), 0
    except Stop as stop:
        text, code = stop.text, stop.code
    except Exception as error:  # noqa: BLE001 - only the class name is reported, never the message or a traceback
        text, code = "FAILED unexpected: " + re.sub(r"[^A-Za-z0-9_]", "?", type(error).__name__)[:60], 70
    except BaseException:  # noqa: BLE001 - an interrupt gets a fixed line and no traceback
        text, code = "FAILED interrupted", 70
    print(text, file=sys.stdout if code == 0 else sys.stderr)
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv))
