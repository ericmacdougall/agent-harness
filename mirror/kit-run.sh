#!/usr/bin/env bash
# goodqa#15561: start the local click-test stack on a pool lease (TTL 3 h). usage: run.sh <tree>
# stop it with: python3 -I ~/.claude/hooks/ah.py kill --pid <pid of this script> --reason "click-test finished"
set -u
KIT="$HOME/g15561-click"; export KIT; TREE="${1:?tree}"; export TREE
exec python3 "$HOME/repos/harness/lanes/pgpool.py" run --mode server --job g15561-click --lane g15561-click --ttl 10800 -- bash "$KIT/stack.sh"
