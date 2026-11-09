#!/bin/bash
# on t2-dev: fresh full mirror of t2-course -> bundle -> git bundle verify -> sha256. NO Dropbox here (upload is a separate throttled step).
set -e
cd /home/eric/gq-branch-clean; mkdir -p tcb; cd tcb
ts=$(date -u +%Y%m%dT%H%M%SZ)
rm -rf mirror.git
git clone --mirror -q git@github.com:ericmacdougall/t2-course.git mirror.git
git -C mirror.git for-each-ref > refs-$ts.txt
git -C mirror.git bundle create /home/eric/gq-branch-clean/tcb/t2-course-$ts.bundle --all 2>&1 | tail -1
git -C mirror.git bundle verify /home/eric/gq-branch-clean/tcb/t2-course-$ts.bundle 2>&1 | tail -2
sha256sum t2-course-$ts.bundle > t2-course-$ts.bundle.sha256
echo "BUNDLE_READY $ts refs=$(wc -l < refs-$ts.txt) main=$(git -C mirror.git rev-parse main) $(ls -la t2-course-$ts.bundle | awk '{print $5}') bytes $(cut -d' ' -f1 t2-course-$ts.bundle.sha256)"
df -h / | tail -1
