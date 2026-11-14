"""Run every suite PR 238 touches, verbosely, in a clean clone; write the RAW unittest output (goodqa#15946 r2).

Usage: python3 run_suites_r2.py <clean clone detached at the code head> <output file>
The header records the clone's HEAD and the tree hashes of harness/, tests/ and install.py, so a reviewer can check
the log against any later commit that changes only notes/: `git rev-parse <head>:harness <head>:tests <head>:install.py`.
"""
import subprocess
import sys

MODS = ["test_lane_identity", "test_lane_store", "test_lane_kit", "test_lane_crash", "test_lane_commands",
        "test_lane_cli", "test_lane_ops", "test_lane_install", "test_lane_stamp_hook", "test_lane_r1", "test_lane_r2",
        "test_spec_flow", "test_spec_flow_audit", "test_spec_flow_legacy_done", "test_spec_flow_native_review",
        "test_review_map", "test_wal", "test_wal_note_structured", "test_wal_note_sibling_ask", "test_wal_cadence",
        "test_tier_gate", "test_tier_gate_dispatch", "test_tier_gate_owner_count", "test_ops_watch", "test_install",
        "test_install_ships_modules", "test_doctor", "test_backup_watch"]


def git(clone, *args):
    return subprocess.run(["git", "-C", clone, *args], capture_output=True, text=True, check=True).stdout.strip()


def main(clone, out):
    with open(out, "w") as log:
        log.write("# raw unittest output, PR 238 (goodqa#15946), python %s\n" % sys.version.split()[0])
        log.write("# clone HEAD %s; status clean: %s\n" % (git(clone, "rev-parse", "HEAD"),
                                                            git(clone, "status", "--porcelain") == ""))
        for path in ("harness", "tests", "install.py"):
            log.write("# tree %s %s\n" % (path, git(clone, "rev-parse", "HEAD:" + path)))
        for mod in MODS:
            log.write("\n$ python3 -m unittest -v tests.%s\n" % mod)
            log.flush()
            done = subprocess.run([sys.executable, "-m", "unittest", "-v", "tests." + mod], cwd=clone,
                                  capture_output=True, text=True, timeout=1800)
            log.write(done.stdout)
            log.write(done.stderr)
            log.write("exit %d\n" % done.returncode)
            print("%s exit %d" % (mod, done.returncode), flush=True)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
