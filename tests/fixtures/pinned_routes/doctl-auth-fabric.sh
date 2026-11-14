#!/bin/bash -p
# goodqa#15976 W7: give doctl a "fabric" config on t2-dev from GCP Secret Manager.
# User-approved narrow route (ask we0224a94f24). Takes no arguments; prints nothing.
# doctl auth init needs a terminal, so the token goes into doctl's own config format
# (~/.config/doctl/fabric.yaml, 0600, used via `doctl --config`). The value never appears in
# argv, an environment variable, a log or this Mac.
# v2 (PR 248 receipt v1): absolute binaries on both ends and a fixed PATH (F1); a private
# temporary file in a 0700 directory, symlink destinations refused, atomic rename (F2);
# pipefail, the retrieval and the value both checked, the old config kept on any failure (F3).
# v3 (first live run exited 5 with no way to tell why): the retrieval status is checked on its
# own, trailing whitespace (CR, spaces, tabs) and trailing blank lines are ignored, and each
# failure has its own exit status. The status names a class only, never a byte of the value.
# Exit status: 0 = new config published; non-zero = nothing changed:
#   2 arguments given        3 config directory unusable     4 destination is a symlink or not a file
#   5 no value               6 retrieval failed              7 value length outside 32-512
#   8 value has characters outside [A-Za-z0-9_-]             9 more than one non-empty line
set -euo pipefail
PATH=/usr/bin:/bin
export PATH
[ "$#" -eq 0 ] || exit 2
# The remote script goes over stdin to an absolute /bin/bash, so no remote login-shell PATH or
# quoting decides what runs.
exec /usr/bin/ssh -T -o BatchMode=yes t2-dev /bin/bash -s >/dev/null 2>&1 <<'REMOTE'
set -euo pipefail
umask 077
PATH=/usr/bin:/bin
export PATH
G=/usr/bin/gcloud
d="$HOME/.config/doctl"
/bin/mkdir -p "$d"
[ ! -L "$d" ] && [ -d "$d" ] || exit 3
/bin/chmod 700 "$d"
f="$d/fabric.yaml"
if [ -L "$f" ] || { [ -e "$f" ] && [ ! -f "$f" ]; }; then exit 4; fi
t=$(/usr/bin/mktemp "$d/.fabric.yaml.XXXXXX")
trap '/bin/rm -f "$t"' EXIT
/bin/chmod 600 "$t"
set +e
"$G" secrets versions access latest --secret=DIGITALOCEAN_API_TOKEN --project=goodqa-28dd3 </dev/null 2>/dev/null \
  | /usr/bin/awk '
      { sub(/[ \t\r]+$/, "") }
      $0 == "" { next }
      { n++; v = $0 }
      END {
        if (n == 0) exit 5
        if (n > 1) exit 9
        if (length(v) < 32 || length(v) > 512) exit 7
        if (v !~ /^[A-Za-z0-9_-]+$/) exit 8
        print "access-token: " v
      }' > "$t"
rc=("${PIPESTATUS[@]}")
set -e
[ "${rc[0]}" -eq 0 ] || exit 6
[ "${rc[1]}" -eq 0 ] || exit "${rc[1]}"
/bin/mv -f "$t" "$f"
trap - EXIT
REMOTE
