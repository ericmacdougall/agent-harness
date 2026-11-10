#!/bin/zsh
# goodqa#15561: hard stop of the 30-minute Funnel window for the disposable click-test stack. usage: funnel-stop.sh <seconds>
# Turns the Mac's funnel and serve for https 443 off after the delay, then writes the read-back next to this script.
sleep "${1:-1800}"
T=/Applications/Tailscale.app/Contents/MacOS/Tailscale
$T funnel --https=443 off > /dev/null 2>&1
$T serve --https=443 off > /dev/null 2>&1
{ date -u +%FT%TZ; echo "funnel status:"; $T funnel status 2>&1; echo "serve status:"; $T serve status 2>&1; } > /Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/agent-aaef3bc78b40c0c22/funnel-stop-readback.txt 2>&1
