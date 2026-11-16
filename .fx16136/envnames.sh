#!/bin/bash
# goodqa#16148: key NAMES only (never values) in the self-host env files the compose references. Read-only.
C=/opt/goodqa/infra/selfhost/app/compose.yaml
FILES=$(sudo grep -oE '(path:|env_file:)[ \t]*[^ ]+\.env' "$C" | awk '{print $NF}' | sort -u)
WANT="PROJECT_INTELLIGENCE_KEYRING GITHUB_APP_ID GITHUB_APP_PRIVATE_KEY GCP_PROJECT API_PUBLIC_URL"
for f in $FILES; do
  names=$(sudo grep -oE '^[A-Za-z_][A-Za-z0-9_]*=' "$f" 2>/dev/null | tr -d '=' | sort -u)
  echo "== $(basename "$f"): $(printf '%s\n' "$names" | grep -c .) keys"
  for k in $WANT; do printf '%s\n' "$names" | grep -qx "$k" && echo "   has $k"; done
  printf '%s\n' "$names" | grep -E 'GITHUB|KEYRING|INTELLIGENCE|PUBLIC|_URL$|GCP|VERTEX' | sed 's/^/   related name: /'
done
