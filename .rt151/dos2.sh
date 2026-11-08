#!/bin/sh
# Three repeats each, to show whether the verdict depends on load. decide() and hook_main() on one string; 1 GB, 60 s.
R=/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/harness-delivery/.claude/worktrees/agent-ad33ebd391da329e6
B=/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/agent-ad33ebd391da329e6/base
PROBE="python3 /Users/eric/.claude/hooks/run_probe.py"
for c in lines-rm-f plan-40k rm-compound rm-compound-small rm-product rm-product-noalias; do
  for n in 1 2 3; do
    echo "=== HEAD hook_main $c #$n"
    RT_HOOK=1 $PROBE --class memory --worst-case "hook_main() on one amplified parallel string with the real SIGALRM" --max-rss-gb 1 --timeout-s 60 -- python3 $R/.rt151/dos.py $R $c 2>&1 | grep -E '^(hook_main|Traceback|.*Error)|"finding": "' | cut -c1-210
  done
  echo "=== BASE hook_main $c"
  RT_HOOK=1 $PROBE --class memory --worst-case "hook_main() at base on one long parallel string" --max-rss-gb 1 --timeout-s 60 -- python3 $R/.rt151/dos.py $B $c 2>&1 | grep -E '^(hook_main|Traceback|.*Error)|"finding": "' | cut -c1-210
done
