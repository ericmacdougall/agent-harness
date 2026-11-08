#!/bin/sh
# Each case is declared and bounded separately: decide() on one string, 1 GB, 60 s. Nothing is executed.
R=/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/harness-delivery/.claude/worktrees/agent-ad33ebd391da329e6
B=/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/agent-ad33ebd391da329e6/base
PROBE="python3 /Users/eric/.claude/hooks/run_probe.py"
for c in control control-echo lines-4095-echo lines-4095-quoted lines-4096-product lines-kept-reading lines-rm-f lines-compound nested nested-wide plan-amplify; do
  echo "=== HEAD decide $c"
  $PROBE --class memory --worst-case "decide() on one amplified parallel string: unbounded line building in RSS and CPU" --max-rss-gb 1 --timeout-s 60 -- python3 $R/.rt151/dos.py $R $c 2>&1 | grep -E '^(command bytes|decide|plan|Traceback|.*Error)|"outcome"|"finding"|peak_rss|"seconds"'
  echo "=== HEAD hook_main $c"
  RT_HOOK=1 $PROBE --class memory --worst-case "hook_main() on one amplified parallel string, with the real SIGALRM: unbounded line building" --max-rss-gb 1 --timeout-s 60 -- python3 $R/.rt151/dos.py $R $c 2>&1 | grep -E '^(hook_main|Traceback|.*Error)|"outcome"|"finding"|peak_rss|"seconds"'
done
for c in lines-4095-echo lines-4095-quoted plan-amplify; do
  echo "=== BASE decide $c"
  $PROBE --class memory --worst-case "decide() at base on one long parallel string" --max-rss-gb 1 --timeout-s 60 -- python3 $R/.rt151/dos.py $B $c 2>&1 | grep -E '^(command bytes|decide|Traceback|.*Error)|"outcome"|"finding"|peak_rss|"seconds"'
done
