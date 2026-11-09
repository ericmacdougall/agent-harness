#!/usr/bin/env bash
# goodqa#15561: start the local click-test stack on a pool lease (TTL 3 h). usage: [KIT=dir] [WEB_HOST=ip] [API_PORT=n] [WEB_PORT=n] run.sh <tree>
# WEB_HOST defaults to loopback; use the tailnet IP (never a public address) for a browser on another enrolled machine.
# The web build bakes the API proxy target, so a second stack needs its own API_PORT and its own build.
set -u
KIT="${KIT:-$HOME/g15561-click}"; export KIT; TREE="${1:?tree}"; export TREE
exec python3 "$HOME/repos/harness/lanes/pgpool.py" run --mode server --job "$(basename "$KIT")" --lane "$(basename "$KIT")" --ttl 10800 -- bash "$KIT/stack.sh"
