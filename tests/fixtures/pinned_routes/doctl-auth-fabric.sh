#!/bin/bash -p
# goodqa#15976 W7: give doctl a "fabric" config on t2-dev from GCP Secret Manager.
# User-approved narrow route (ask we0224a94f24). Takes no arguments; prints nothing.
# doctl auth init needs a terminal, so the token goes into doctl's own config format
# (~/.config/doctl/fabric.yaml, 0600, used via `doctl --config`). The value never appears in
# argv, an environment variable, a log or this Mac.
# v2 (PR 248 receipt v1): absolute binaries on both ends and a fixed PATH (F1); a private
# temporary file in a 0700 directory, symlink destinations refused, atomic rename (F2);
# pipefail, the retrieval and the value both checked, the old config kept on any failure (F3).
# Exit status: 0 = new config published; non-zero = nothing changed.
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
"$G" secrets versions access latest --secret=DIGITALOCEAN_API_TOKEN --project=goodqa-28dd3 </dev/null 2>/dev/null \
  | /usr/bin/awk 'NR == 1 && length($0) >= 32 && length($0) <= 512 && $0 ~ /^[A-Za-z0-9_-]+$/ { print "access-token: " $0; ok = 1; next } { bad = 1 } END { exit (ok && !bad) ? 0 : 5 }' > "$t"
/bin/mv -f "$t" "$f"
trap - EXIT
REMOTE
