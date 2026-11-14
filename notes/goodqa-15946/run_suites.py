import re
import subprocess
import sys

CLONE = "/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/software-factory/s1/receipt-clone"
MODS = ["test_lane_identity", "test_lane_store", "test_lane_kit", "test_lane_crash", "test_lane_commands",
        "test_lane_cli", "test_lane_ops", "test_lane_install", "test_lane_stamp_hook", "test_lane_r1", "test_tier_gate",
        "test_tier_gate_dispatch", "test_tier_gate_owner_count", "test_ops_watch", "test_install",
        "test_install_ships_modules", "test_doctor", "test_backup_watch"]
lines = []
for m in MODS:
    done = subprocess.run([sys.executable, "-m", "unittest", "tests." + m], cwd=CLONE, capture_output=True, text=True,
                          timeout=900)
    tail = done.stderr.strip().splitlines()
    ran = next((x for x in tail if x.startswith("Ran ")), "Ran ?")
    verdict = tail[-1] if tail else "?"
    line = "$ python3 -m unittest tests.%s  exit %d  %s ... %s" % (m, done.returncode, ran.split(" in ")[0], verdict)
    print(line, flush=True)
    lines.append(line)
open(CLONE + "/../suite-results.txt", "w").write("\n".join(lines) + "\n")
