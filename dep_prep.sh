#!/bin/bash
# on t2-dev: fresh shallow clone of t2-course main at c8fbe7b5, stage the 19 local media parts (7-25) as the media cache. Parts 1-6 are streamed in separately.
set -eu
D=/home/eric/gq-branch-clean/dep; rm -rf $D; mkdir -p $D; cd $D
git clone -q --depth 1 git@github.com:ericmacdougall/t2-course.git t2c
cd t2c
echo "HEAD $(git rev-parse HEAD)"
[ "$(git rev-parse HEAD)" = "c8fbe7b590d566b61ac9ba4494aa1f4cc2e1d76a" ] || { echo "UNEXPECTED_MAIN stop"; exit 2; }
mkdir -p .media-cache
mv /home/eric/gq-branch-clean/tc/parts/part-00*.tar .media-cache/
ls .media-cache | wc -l
df -h / | tail -1
echo PREP_DONE
