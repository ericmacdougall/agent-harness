## Risks
- Test-only. The fake upstream answers 201 to every create, so the test proves forwarding and refusal, not Docker's own behaviour. The real-guard Docker path is in create-guard.integration.docker.test.ts.
- Nothing is merged or deployed.
