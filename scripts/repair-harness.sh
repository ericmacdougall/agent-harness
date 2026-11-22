#!/bin/bash
set -euo pipefail

choice=''
args=("$@")
while (( $# )); do
    if [[ $1 == --python ]]; then
        [[ $# -ge 2 && $2 == /* && -z $choice ]] || { printf '%s\n' '--python needs one absolute interpreter path.' >&2; exit 2; }
        choice=$2
        shift
    fi
    shift
done

if [[ -n $choice ]]; then
    candidates=("$choice")
else
    candidates=(python3 python3.15 python3.14 python3.13 python3.12 python3.11)
fi
for candidate in "${candidates[@]}"; do
    if "$candidate" -I -c 'import sys; sys.exit(sys.version_info < (3, 11))' 2>/dev/null; then
        exec "$candidate" -IB "$(dirname "$0")/repair_harness.py" "${args[@]}"
    fi
done
printf '%s\n' 'Python 3.11 or later is required.' >&2
exit 2
