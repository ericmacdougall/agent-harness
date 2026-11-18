#!/usr/bin/python3 -I
"""Create ONE Cloudflare DNS record and nothing else:

    A  timbar-staging.transition2.ai -> 159.203.13.118   (DNS only, TTL 300)

Run as `/usr/bin/python3 -I <this file>` with no arguments. Every value is a constant in this file. The API token is read
from GCP Secret Manager into memory, sent only to api.cloudflare.com in the Authorization header, and never printed,
logged, written to disk, placed in argv or exported. All output is built from fixed text, numbers and the constants below.

Idempotent: when the record already exists exactly as wanted it reports that and exits 0. When any other record holds
the name it changes nothing and exits 4. Cloudflare has no conditional create, so after creating it lists the name
again: if another record appeared in between, it removes the one record this run created (by the id the create call
returned, and nothing else) and exits 4. Python 3.9, standard library only.

Exit codes: 0 created or already present; 2 arguments given; 3 secret unreadable or malformed; 4 zone not visible or a
conflicting record; 5 the create call failed, or its result could not be confirmed or undone; 70 unexpected error.
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
    # The two logging overrides beat any persisted gcloud setting, so the answer cannot reach a gcloud log file.
    env = {"HOME": pwd.getpwuid(os.getuid()).pw_dir, "PATH": GCLOUD_PATH, "CLOUDSDK_CORE_DISABLE_PROMPTS": "1",
           "CLOUDSDK_CORE_LOG_HTTP": "false", "CLOUDSDK_CORE_DISABLE_FILE_LOGGING": "true"}
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


def listed(token, records_path):
    """The records that hold NAME, or None when the list could not be read."""
    status, parsed = call(token, "GET", records_path + "?name=" + NAME)
    rows = parsed.get("result")
    if status != 200 or parsed.get("success") is not True or not isinstance(rows, list) or len(results(parsed)) != len(rows):
        return None, status, error_codes(parsed)
    return rows, status, []


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
    existing, status, codes = listed(token, records_path)
    if existing is None:
        raise Stop(4, "FAILED lookup: could not list records for %s (HTTP %d, codes %s); nothing was changed"
                   % (NAME, status, codes))
    if len(existing) == 1 and wanted(existing[0]):
        return "OK already present: A %s -> %s, DNS only" % (NAME, IPV4)
    if existing:
        raise Stop(4, "CONFLICT: %d record(s) hold %s and they are not exactly the one wanted; nothing was changed"
                   % (len(existing), NAME))
    status, parsed = call(token, "POST", records_path,
                          {"type": "A", "name": NAME, "content": IPV4, "ttl": TTL, "proxied": False, "comment": COMMENT})
    created = parsed.get("result")
    created_id = created.get("id") if isinstance(created, dict) else None
    if not (status == 200 and parsed.get("success") is True and isinstance(created, dict) and wanted(created)
            and isinstance(created_id, str) and ZONE_ID_RE.fullmatch(created_id)):
        raise Stop(5, "FAILED create: HTTP %d, codes %s; run again to see whether the record exists"
                   % (status, error_codes(parsed)))
    # Nothing binds the create to the empty list seen above, so look again and undo this run's record on a conflict.
    now, status, codes = listed(token, records_path)
    if now is None:
        raise Stop(5, "FAILED confirm: the record was created but the name could not be listed again (HTTP %d, codes %s); "
                      "run again to check it" % (status, codes))
    if all(row.get("id") == created_id for row in now):  # no other record holds the name
        if len(now) == 1 and wanted(now[0]):
            return "OK created: A %s -> %s, DNS only, TTL %d" % (NAME, IPV4, TTL)
        raise Stop(5, "FAILED confirm: the record was created but the list of the name does not show it as wanted; "
                      "run again to check it")
    status, parsed = call(token, "DELETE", records_path + "/" + created_id)
    if status == 200 and parsed.get("success") is True:
        raise Stop(4, "CONFLICT: another record took %s while this one was being created; the record this run created "
                      "was removed" % NAME)
    raise Stop(5, "FAILED undo: another record took %s during the create and the record this run created could not be "
                  "removed (HTTP %d, codes %s); remove A %s -> %s by hand" % (NAME, status, error_codes(parsed), NAME, IPV4))


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
