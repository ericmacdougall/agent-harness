#!/usr/bin/env bash
# goodqa#15561: focused API test run on the shared pgpool (one lease, serial files). usage: run15561.sh <tag> <test files...>
# Log: ~/review-scratch/g15561-<tag>.log (ANSI stripped copy: .txt). Cap 900 s.
TAG="$1"; shift
cd "$HOME/wt-15561/apps/api" || exit 2
timeout 900 python3 "$HOME/repos/harness/lanes/pgpool.py" run --job "g15561-$TAG" --lane "g15561-$TAG" --mode server --ttl 1000 -- pnpm exec vitest run --fileParallelism=false "$@" > "$HOME/review-scratch/g15561-$TAG.log" 2>&1
RC=$?
sed 's/\x1b\[[0-9;]*m//g' "$HOME/review-scratch/g15561-$TAG.log" > "$HOME/review-scratch/g15561-$TAG.txt"
grep -E '^ (❯|✓|×) |Test Files|Tests |FAIL|AssertionError' "$HOME/review-scratch/g15561-$TAG.txt" | cut -c1-200 | head -60
echo "rc=$RC"
exit $RC
