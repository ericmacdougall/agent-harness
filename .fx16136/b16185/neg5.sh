#!/bin/bash
# goodqa#16148 NEG-5: two broken variants must each fail the no-value tests. Run in apps/job-dispatcher.
set -u
run() { timeout 600 npx vitest run test/docker-failure-message.test.ts 2>&1 | sed -E 's/\x1b\[[0-9;]*m//g' | grep -E '^ +Tests ' ; }
echo "variant A: return err.message on a docker failure"
python3 -I - <<'EOF'
p='src/docker.ts'; s=open(p).read()
old="throw new DockerLaunchError('synchronous_failure', describeDockerFailure(stderr, secretValues));"
assert s.count(old)==1; s=s.replace(old,"throw new DockerLaunchError('synchronous_failure', err.message);"); open(p,'w').write(s)
EOF
run
git checkout -q -- src/docker.ts
echo "variant B: log the merged env on a docker refusal"
python3 -I - <<'EOF'
p='src/server.ts'; s=open(p).read()
old="      if (error instanceof DockerLaunchError) {\n"
assert s.count(old)==1; s=s.replace(old, old+"        req.log.error({ env: mergedEnv }, 'job-dispatcher: docker refused');\n"); open(p,'w').write(s)
EOF
run
git checkout -q -- src/server.ts
echo "restored:"; git status --short src
run
