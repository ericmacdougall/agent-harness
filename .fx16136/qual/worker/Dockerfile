# Stand-in job image for the PR 1377 runtime qualification kit. Same pinned base as apps/job-dispatcher/Dockerfile,
# so the build adds one small layer and pulls nothing new. See check.mjs for what it does and does not prove.
FROM node:22-slim@sha256:83f487e0a63425e5b4d146fb5e5be574bcbe1b7b843d3ebafdd95eaf7767a7e5
COPY check.mjs /qual/check.mjs
USER node
ENTRYPOINT ["node", "/qual/check.mjs"]
