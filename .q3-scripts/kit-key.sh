#!/usr/bin/env bash
# t2-dev. New main-push key for this host: the private key is generated here and never leaves. Prints only the public key and fingerprint.
# Does not register anything on GitHub. Writes the env file rw exec-main-push-env expects (a URL and a path; no secret value).
set -u
K=$HOME/.ssh/bugtracker-main-deploy
E=$HOME/.config/goodqa/rw-ship-main-push.env
[ -e "$K" ] && { echo KEY_ALREADY_THERE; } || { umask 077; ssh-keygen -q -t ed25519 -N '' -C 'goodqa rw-ship main push t2-dev' -f "$K" || exit 2; }
chmod 600 "$K"
mkdir -p "$(dirname "$E")"
[ -e "$E" ] || { umask 077; printf 'RW_SHIP_MAIN_PUSH_URL=git@github.com:ericmacdougall/bugtracker.git\nRW_SHIP_MAIN_PUSH_KEY=%s\n' "$K" > "$E"; chmod 600 "$E"; }
ssh-keygen -lf "$K.pub" | cut -d' ' -f1-2
cat "$K.pub"
cd "$HOME/repos/harness" && python3 bin/rw check-main-push-env "$E" 2>&1 | tail -2 | cut -c1-200
echo "CHECK_RC=${PIPESTATUS[0]}"
echo "PROBE $(GIT_SSH_COMMAND="ssh -F /dev/null -o IdentityAgent=none -o IdentitiesOnly=yes -o BatchMode=yes -i $K" git -C "$HOME/repos/bugtracker" ls-remote git@github.com:ericmacdougall/bugtracker.git refs/heads/main 2>&1 | tail -1 | cut -c1-90)"
