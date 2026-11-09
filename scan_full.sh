#!/bin/bash
# on t2-dev: secret scan over ALL commits of the rewritten mirror (not only first-parent). Prints commit shas and file names only, never matched text.
cd /home/eric/gq-branch-clean/tcr/mirror.git || exit 1
PATS='AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----|ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|sk-[A-Za-z0-9]{32,}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35}|re_[A-Za-z0-9]{20,}|eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}|(CLOUDFLARE_API_TOKEN|RESEND_API_KEY|API_KEY|SECRET|PASSWORD)[A-Z_]*\s*[=:]\s*[A-Za-z0-9_./+-]{20,}'
n=$(git rev-list --all | wc -l)
git log --all -p --no-color --format='@@COMMIT %H' -- . ':!package-lock.json' | awk -v pats="$PATS" '/^@@COMMIT /{c=$2; next} /^\+\+\+ /{f=$2; next} /^\+/ { if ($0 ~ pats) { key=c" "f; if (!(key in seen)) { seen[key]=1; print "HIT " key } } }' | head -20 > /home/eric/gq-branch-clean/tcr/scan_full.out
echo "FULL_SCAN commits=$n hits=$(wc -l < /home/eric/gq-branch-clean/tcr/scan_full.out)"
cat /home/eric/gq-branch-clean/tcr/scan_full.out
