#!/bin/bash
# READ-ONLY on t2-dev: free space, top consumers (home top-level, ~/repos, ~/wt, ~/.cache, ~/.local), docker df.
df -BG --output=avail,pcent / | tail -1
echo "== home top"
du -sm /home/eric/* /home/eric/.[a-z]* 2>/dev/null | sort -rn | head -15
echo "== repos"; du -sm /home/eric/repos/* 2>/dev/null | sort -rn | head -10
echo "== wt"; du -sm /home/eric/wt/* 2>/dev/null | sort -rn | head -8
echo "== docker"; docker system df 2>/dev/null; docker ps --format '{{.Names}} {{.Image}}' 2>/dev/null | head -20
echo URGDU_DONE
