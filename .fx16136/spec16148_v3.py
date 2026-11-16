"""goodqa#16148 PEM spec v2 -> v3: Sonnet v2 BLOCK item (real-engine round trip), Opus v2 M1, M2, N1 to N4, Sonnet's smaller items."""
import os, re
D = os.path.dirname(os.path.abspath(__file__))
p = os.path.join(D, 'spec-16148-pem.md'); t = open(p).read()
W = 'wal:/Users/eric/.claude/wals/baab765b-d85c-46b4-b7b9-588eb912c770/agent-af3f19d243286a8a7.jsonl#w42a317db57c'
REV = ('inferred: from ticket:GoodQA goodqa#16148 ; wal:/Users/eric/.claude/wals/baab765b-d85c-46b4-b7b9-588eb912c770/'
       'agent-af3f19d243286a8a7.jsonl#we0ef60cda06 -- ')


def rep(o, n, cnt=1):
    global t
    assert t.count(o) == cnt, (t.count(o), o[:80]); t = t.replace(o, n)


def line(prefix, new):
    global t
    i = t.index('\n' + prefix) + 1; j = t.index('\n', i); t = t[:i] + new + t[j:]


def insert_after(prefix, new):
    global t
    i = t.index('\n' + prefix) + 1; j = t.index('\n', i); t = t[:j] + '\n' + new + t[j:]


i = t.index('Revision: v2.'); j = t.index('\n', i)
t = t[:j] + (' v3 (delta on v2 core 89556e47; Sonnet v2 BLOCK report 8e93dbbd, Opus v2 ACCEPT with two must-dos): a real-engine '
             '--env-file round trip with the real guard and a post-deploy argv scan (AC-6); docker failure text reduced to a fixed '
             'category and byte count with one allow-listed, redacted first line (AC-7, Opus M1, also for goodqa#16185); a gate (c) '
             'failure re-applies the intelligence hold before any rollback, and the release\'s dispatcher boot is proven against a '
             'fake JOB_ENVFILE before an unholding switch (AC-8, Opus M2 and N4); NSS-aware group checks (N1), per-launch 0700 env '
             'dirs with a boot sweep and key validation (N2), ASCII-only key values (N3), and Sonnet\'s smaller items. The lead\'s '
             'rulings are recorded at ' + W + ' (PEM) and #we0ef60cda06.') + t[j:]
rep("Source: inferred: from ticket:GoodQA goodqa#16148 -- the lead's ruling", "Source: inferred: from ticket:GoodQA goodqa#16148 ; " + W + " -- the lead's ruling", 7)

# AC-1: N3 and the parity test against the real api service
rep("any CR, LF, NUL or other control character (tab included) in the value.",
    "any byte outside printable ASCII 0x20 to 0x7E in the value (CR, LF, NUL, tab, other control characters, non-ASCII and invalid UTF-8; a PEM and its base64 are ASCII, Opus N3).")
rep("Plus a parity test that runs the real `docker compose config` on the same fake env file and asserts that derive's value equals compose's value for every accepted case.",
    "Plus a parity test that reads the api service's env_file entries from the real infra/selfhost/app/compose.yaml, fails unless the /etc/goodqa/api.env entry has `format: raw`, then runs the real `docker compose config` with that entry pointed at the fake env file and asserts that derive's value equals compose's value for every accepted case.")

# AC-2: N1
rep("It refuses if: gid 64910 has another name or any member; the name has another gid;",
    "It refuses if, checked in /etc/group and through NSS (`getent group` and `getent passwd`, Opus N1): gid 64910 has another name or any member; any account has 64910 as its primary gid; the name has another gid;")

# AC-4: N2 key validation
rep("Other kinds are unaffected. Verify by: vitest on buildServer with a temp secrets dir and a stub docker.",
    "Every env key written for a launch must match `^[A-Za-z_][A-Za-z0-9_]*$` (Opus N2); any other key refuses the launch with a named error before anything is written. Other kinds are unaffected. Verify by: vitest on buildServer with a temp secrets dir and a stub docker, plus key-validation cases (empty key, `=`, space, non-ASCII).")

# AC-6 rewritten
line('- AC-6:', (
    "- AC-6: No job secret on any command line (env-file). Every launch, of every kind and for every variable (base env, JOB_ENVFILE values "
    "and the request's allowed env), passes its env through `docker run --env-file F`. For each launch the dispatcher creates a fresh "
    "directory with mkdtemp (mode 0700) under its tmpfs /tmp, writes F there with O_EXCL and mode 0600, one `KEY=VALUE` line per variable "
    "(never a line without `=`, which docker would fill from the CLI's own environment), and removes F and the directory in a finally on "
    "every path: success, failure, timeout and throw. At boot it removes any leftover `goodqa-envfile-*` directory under /tmp (Opus N2). "
    "compose declares /tmp as tmpfs for job-dispatcher (checked by real `docker compose config`). A value containing CR, LF or NUL, or a "
    "non-UTF-8 value, cannot be written: base or JOB_ENVFILE values answer 501 with a named error, request env answers 400. No `-e KEY=VALUE` "
    "remains. The create-guard still sees Env in the create body and keeps its Env checks, GUARD_HELD_ENV included. Verify by: (1) a "
    "vitest stub docker that records its full argv and the env-file's mode and directory mode at call time: the argv holds no env value, "
    "the modes are 0600 and 0700, and both are gone after the call, including when the stub fails, times out or throws; a boot test that "
    "sweeps a planted stale directory. (2) A real-engine round trip on t2-dev, after `df -h /` (stop if under 30 GB free): the real "
    "dispatcher code and the real create-guard on a local docker engine launch an allow-listed test image whose command prints its "
    "environment as hex, and the test compares it byte for byte with the intended env, for values with leading, inner and trailing "
    "whitespace, `=`, `#`, an empty value, quotes, backslashes and non-ASCII UTF-8, and for the base env key names of every restored job "
    "kind (scan, transcode, intelligence-worker, suggest-fix-worker) with fake values; the guard's GUARD_HELD_ENV refusal still fires "
    "through --env-file. (3) Post-deploy scan on the release that ships it: during the AC-11 provoked launches, a read-only sampler on the "
    "app host reads /proc/*/cmdline of docker CLI processes and records only the flag names present and the argv length, asserting "
    "`--env-file` and no `-e` or `--env`; it never prints an argument value. Source: inferred: from ticket:GoodQA goodqa#16148 ; " + W +
    " -- the lead's ruling 4 (Opus S3) and the Sonnet v2 review item 1; /proc/PID/cmdline is world-readable in the host PID namespace"))

# AC-7 rewritten
line('- AC-7:', (
    "- AC-7: No value anywhere. On a docker launch failure the dispatcher never forwards docker's stderr or err.message or err.cmd. The "
    "422 body and the dispatcher log carry `docker run failed: CATEGORY (stderr N bytes)`, where CATEGORY is one of a fixed set "
    "(guard_refused, image_not_found, invalid_reference, daemon_unreachable, other) and N the stderr byte count. Only if the first stderr "
    "line starts with an allow-listed docker error prefix (`docker: Error response from daemon: job-dispatcher-create-guard: refused (`, "
    "`Unable to find image`, `invalid reference format`) is it appended, after removing every env value of that launch by exact substring "
    "and dropping the whole line if any 8-byte substring of any env value, or of its base64, hex or JSON-escaped form, remains, then "
    "truncating to 200 characters. The guard's held-transcription reason is fixed text and stays visible, so goodqa#16136 AC-13 pairing "
    "still works. goodqa#16185 adopts the same rule (Opus M1). With a fake key, an alphanumeric marker of 32 or more characters, none of "
    "the following contains the marker, any 16-byte substring of it, or its base64 (all three alignments), hex or JSON-escaped forms: the "
    "derive script's stdout and stderr; every argv of every process the derive script spawns (recorded by a stub PATH); rw-ship's output "
    "and run directory; the dispatcher's log (boot, launch, every refusal); every docker argv; the 422, 501 and 504 bodies; the API's log "
    "line; the intelligence job row's lastErrorMessage; the test runner's output. Stub docker cases: exit 1 with empty stderr; stderr "
    "that echoes the argv and the env-file content; an echo of the value as an invalid-UTF-8 byte list; a backslash- or JSON-escaped "
    "echo; a value straddling the 200-character truncation boundary; an echo of part of the value; a maxBuffer overflow; killed by "
    "timeout; and a guard held refusal whose reason line must survive. derive is Python, run by rw-ship as `python3 -I` (isolated from "
    "PYTHON* variables), and never passes the value as an argv element. Verify by: the fake-key tests above grep every captured stream, "
    "file and argv for every form. Source: inferred: from ticket:GoodQA goodqa#16148 ; " + W + " -- review S7 (Opus a5a2642f, the marker "
    "forms) and v2 review M1 (Opus a5a2642f, the fixed category)"))

# AC-8: M2, N4
rep("Failing (c), or not being able to read (c), is a switch failure and rolls back, as in goodqa#16136 AC-7.",
    "(c) is read only from the job-dispatcher container created by this switch, identified by its container id and start time, never "
    "from an older container's log (Opus N4). Failing (c), or not being able to read (c), first re-applies the intelligence hold with a "
    "hold-only re-pin (`selfhost-ctl pin` with `--job-hold JOB_IMAGE_INTELLIGENCE_WORKER` and every other pin unchanged) and recreates "
    "only the dispatcher and the guard, which is safe even when forward-only migrations were applied (mig_hold); then it rolls back if "
    "rollback is allowed, and otherwise keeps the stack with intelligence held and exits 8 (Opus M2). Before an unholding switch, rw-ship "
    "runs the release's dispatcher image once on the VM against a throwaway secrets directory holding a fake value and a matching "
    "JOB_ENVFILE key, and requires its boot line `ok`; that run never sees the real file.")
rep("garbled output and ssh failure, each with and without the hold; missing key name; boot line absent and boot line error.",
    "garbled output and ssh failure, each with and without the hold; missing key name; boot line absent and boot line error; a boot "
    "line only in the old container's log; the pre-switch fake-JOB_ENVFILE boot failing; and (c) failing after migrations were applied, "
    "which must leave the intelligence line `\"\" # held`, the dispatcher and guard recreated, no rollback and exit 8.")

# AC-10: who runs the checks
rep("The end-to-end intelligence check (goodqa#16136 AC-12 Level 2) runs only after main lifts the hold.",
    "These checks print names and status only. Main, or an agent main authorizes for that deploy, may run them read-only through the "
    "fleet route; no person is needed and no value is read. The end-to-end intelligence check (goodqa#16136 AC-12 Level 2) runs only "
    "after main lifts the hold.")

# new NEGs
insert_after('- NEG-9 (AC-6):', (
    "- NEG-10 (AC-6): The env-file writer is handed a key with `=`, a space, an empty key, a non-ASCII key, or a value with CR, LF, NUL or "
    "invalid UTF-8: the launch is refused with a named error, nothing is written to /tmp and docker is not called. Verify by: vitest "
    "cases asserting the error, an empty tmpfs dir and no docker call. Source: inferred: from ticket:GoodQA goodqa#16148 -- v2 review N2 "
    "and N3 (Opus a5a2642f)\n"
    "- NEG-11 (AC-7): A stub docker whose stderr carries a value split across the truncation boundary, escaped, as invalid UTF-8 bytes, or "
    "in part: the 422 body holds only the category and byte count (the first line is dropped). Verify by: the AC-7 stub cases with the "
    "marker forms. Source: inferred: from ticket:GoodQA goodqa#16148 -- v2 review M1 (Opus a5a2642f)\n"
    "- NEG-12 (AC-8): gate (c) fails after forward-only migrations were applied: the intelligence hold is re-applied before anything else "
    "and no intelligence container can start. Verify by: the AC-8 pytest case, asserting the hold-only re-pin happened before any other "
    "step and the compose line is `\"\" # held`. Source: inferred: from ticket:GoodQA goodqa#16148 -- v2 review M2 (Opus a5a2642f)\n"
    "- NEG-13 (AC-2): an NSS-only collision (getent reports gid 64910 or a member that /etc/group does not, or an account whose primary "
    "gid is 64910): refused before any write. Verify by: a test with a fake getent on PATH. Source: inferred: from ticket:GoodQA "
    "goodqa#16148 -- v2 review N1 (Opus a5a2642f)"))
rep("- AC-1 to AC-10 pass, live where stated;", "- AC-1 to AC-10 and NEG-1 to NEG-13 pass, live where stated;")
open(p, 'w').write(t); print('v3 written')
