#!/usr/bin/env python3
"""Launcher every harness hook runs through: `python3 ah_hook.py <script> [args...]`.

It is the off switch. While ~/.agent-harness/OFF exists the launcher exits 0 at once, prints nothing and never
starts the script, so every guard, gate, reminder and context block is silent, in running sessions too (they keep
calling the launcher; the launcher reads the flag each time). Without the flag it replaces itself with the script,
so stdin, stdout, stderr and the exit code are the script's own.

The user turns it off and on with `harness off` / `harness on` (also `ah off` / `ah on`); see docs/off-switch.md.
Standard library only, and deliberately tiny: a broken launcher would break every hook.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OFF = os.path.join(os.path.expanduser("~"), ".agent-harness", "OFF")


def main(argv):
    if os.path.exists(OFF):
        return 0
    if len(argv) < 2 or os.sep in argv[1] or argv[1].startswith("."):
        sys.stderr.write("ah_hook: usage: ah_hook.py <script in the hooks directory> [args...]\n")
        return 0  # a wiring mistake must not block every tool call
    script = os.path.join(HERE, argv[1])
    if not os.path.isfile(script):
        sys.stderr.write(f"ah_hook: {argv[1]} is not installed; skipped\n")
        return 0
    runner = "node" if script.endswith(".mjs") else sys.executable
    try:
        os.execvp(runner, [runner, script, *argv[2:]])
    except OSError as error:
        sys.stderr.write(f"ah_hook: could not start {argv[1]}: {error}\n")
        return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
