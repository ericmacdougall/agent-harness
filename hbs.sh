#!/bin/bash
# on dev2: state of feature/harness-build-series in work/t2-course
cd /home/eric/work/t2-course || exit 1
git log --format='%h %cr %s' -4 feature/harness-build-series
git merge-base --is-ancestor dad62915 8827af1f && echo "dad62915 is ancestor of 8827af1f (work is newer)" || echo "dad62915 NOT ancestor of 8827af1f"
git log -1 --format='dad62915 %cr' dad62915
git remote -v | head -1
