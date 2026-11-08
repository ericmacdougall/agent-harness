#!/usr/bin/env bash
# Run on any host: names and hashes only, never file contents of secrets. Inventory for the release path move.
cd "$HOME/repos/harness" || exit 2
echo "HOST $(hostname)"
for f in bin/rw bin/rw-ship.sh bin/rw-rollback.sh bin/rw-runtime.sh bin/selfhost-ctl.py bin/release-smoke.mjs bin/rw_register_release.py bin/rwgate.py \
  config/goodqa-release/bin/rw-ship.sh config/goodqa-release/bin/rw-rollback.sh config/goodqa-release/bin/rw-runtime.sh config/goodqa-release/bin/selfhost-ctl.py \
  config/goodqa-release/bin/release-smoke.mjs config/goodqa-release/bin/RELEASE_BINDING; do
  [ -e "$f" ] && echo "$(sha256sum "$f" | cut -c1-16) $(git status --short -- "$f" | cut -c1-2 | tr ' ' '.') $f" || echo "MISSING $f"
done
echo "SHIPCONF_KEYS"; sed -n 's/^\([A-Z_0-9]*\)=.*/\1/p' biz/release-waves/ship.conf 2>/dev/null | tr '\n' ' '; echo
echo "LOCKS"; ls locks 2>/dev/null | tr '\n' ' '; echo
echo "BUGTRACKER_REMOTES"; git -C "$HOME/repos/bugtracker" remote | tr '\n' ' '; echo
echo "TOOLS"; for t in gh git flock jq docker pnpm node python3 systemd-run rclone; do printf '%s=%s ' "$t" "$(command -v "$t" >/dev/null && echo y || echo n)"; done; echo
docker buildx version 2>&1 | head -1 | cut -c1-60
node --version; pnpm --version; python3 --version
loginctl show-user "$USER" -p Linger 2>/dev/null
echo "GH $(gh auth status 2>&1 | grep -c 'Logged in')"
[ "$1" = deep ] || exit 0
echo "RW_SHIP_REFS"
grep -oE '\$(HOME|S)/[A-Za-z0-9_./-]+|/home/eric/[A-Za-z0-9_./-]+|~/[A-Za-z0-9_./-]+' config/goodqa-release/bin/rw-ship.sh bin/rw-rollback.sh config/goodqa-release/bin/rw-runtime.sh | cut -d: -f2 | sort -u | head -80
echo "DEV2_NAMES"; grep -n -E 'dev2|\bpve\b' config/goodqa-release/bin/rw-ship.sh config/goodqa-release/bin/rw-runtime.sh | cut -c1-170 | head -20
echo "REMOTE_NAMES"; grep -n -E 'git (-C [^ ]+ )?(fetch|push) ' config/goodqa-release/bin/rw-ship.sh | cut -c1-150 | head -12
echo "MAIN_PUSH"; grep -n -E 'exec-main-push-env|MAIN_PUSH|main.push|keyfile|_KEY_FILE|GH_TOKEN|GITHUB_TOKEN' bin/rw | cut -c1-150 | head -20
