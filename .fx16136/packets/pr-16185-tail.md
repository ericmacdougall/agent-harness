
## Risks
- Residual risk, accepted in the spec: a secret-source value under 8 bytes that sits inside a longer token is not detected. Such a value is not a meaningful secret, and the category is always present.
- The 422 text changes shape. The API keeps it only as a message (job-dispatch.ts keeps 300 chars), and 422 stays a definite not-started. The held text sits inside the first 300 chars (tested).
- Over-redaction can drop a useful line. The category and byte count always remain.
- The held literal can drift from the guard's held-env.ts text until the deferred cross-constant test lands (Q1). If it drifts, the held line is dropped to the category only, `guard_refused`, so AC-13 pairing would undercount and would not leak.
- Nothing is merged or deployed. Merge and ship order are main's call (spec v4 ship order step 1).
