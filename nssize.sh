#!/bin/bash
# on t2-dev: disk size of objects reachable from each ref namespace set
cd ~/gq-branch-clean/bt/bugtracker.git
sz() { git rev-list --objects "$@" 2>/dev/null | cut -d' ' -f1 | git cat-file --batch-check='%(objectsize:disk)' | awk '{s+=$1} END{printf "%.0f MiB\n", s/1048576}'; }
echo -n "heads+tags: "; sz --branches --tags
for ns in pull gorunner backup archive notes; do echo -n "$ns only: "; sz --glob="refs/$ns/*"; echo -n "heads+tags+$ns: "; sz --branches --tags --glob="refs/$ns/*"; done
echo -n "ALL: "; sz --all
