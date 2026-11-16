#!/bin/bash
# goodqa#16148 / #16136: read-only, NAMES ONLY. Prints key names, file paths, owners and modes; never a value or a hash.
set -u
echo "== env files that define GITHUB_APP_PRIVATE_KEY* (file owner mode; key names only)"
for f in $(sudo find /etc/goodqa /opt/goodqa/infra/selfhost/app /opt/goodqa/infra/do -maxdepth 1 -type f -name '*.env' 2>/dev/null); do
  n=$(sudo sed -n 's/^\(GITHUB_APP_PRIVATE_KEY[A-Z_]*\)=.*/\1/p' "$f" | sort -u | tr '\n' ' ')
  [ -n "$n" ] && echo "$f $(sudo stat -c '%U:%G %a' "$f") keys: $n"
done
echo "== candidate key files (path owner mode; contents never read)"
sudo find /etc/goodqa /opt/goodqa /root /home -xdev -maxdepth 4 -type f \( -iname '*.pem' -o -iname '*private-key*' -o -iname '*private_key*' -o -iname '*github-app*' \) -printf '%p %u:%g %m\n' 2>/dev/null | head -20
echo "== compose references (names only)"
sudo grep -n -E 'secrets:|_FILE|GITHUB_APP_PRIVATE_KEY' /opt/goodqa/infra/selfhost/app/compose.yaml 2>/dev/null | sed -E 's/=.*$/=<redacted>/' | head -20
echo "== how api gets it (service env_file names only)"
sudo grep -n -E 'env_file|api\.env' /opt/goodqa/infra/selfhost/app/compose.yaml 2>/dev/null | head -10
