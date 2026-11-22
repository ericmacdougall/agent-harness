# T2Scan operator signing

The macOS signer creates a fresh approval for one named T2Scan audit. The approved batch contains executive, assurance and delivery synthesis on the pinned `gpt-6-astra` model. The signed payload binds each assignment to its packet digest and execution host. A batch expires within 15 minutes. The Linux verifier can consume each assignment once and revoke unused assignments in a batch.

## Provisioning boundary

The Mac operator runs the signer built from the reviewed, pinned release and keeps the Secure Enclave key handle in the private operator stage. The verifier pins the hardware key's public part and the audience derived from the independently verified SSH host key and executor UID. Check the target host identity before enrollment.

An ECDSA signature establishes possession of the enrolled key. The operator observes that the reviewed enrollment program creates a Secure Enclave key gated by Touch ID. Use the existing cooperating-agent trust model on the owned t2-dev host. Root ownership protects the verifier during ordinary application operation. A deliberate host administrator could replace its pin or replay state, and the workflow does not establish resistance to that administrator. Keep the broker inactive until reviewed operator enrollment succeeds.

## First-time setup and one named audit

Run this command from the exact reviewed Agent Harness release after it is merged. Use the Ed25519 fingerprint independently verified for the existing t2-dev entry in your macOS SSH known-hosts file. Pass a manifest of exactly the intended three retained audit assignments, with digests computed from their actual packets. The tool uses the existing pinned SSH account and its operator-authorized sudo on t2-dev.

```sh
python3 scripts/provision_t2scan_consent.py \
  --ref REVIEWED_MERGED_COMMIT --issuer OPERATOR_LABEL \
  --fingerprint T2_DEV_ED25519_SHA256_FINGERPRINT \
  --project PROJECT_ID --run AUDIT_RUN_ID --manifest EXACT_THREE_ASSIGNMENTS.json --apply
```

Omit `--apply` for an inspection that leaves broker files and state untouched. Apply requires a local interactive operator terminal. The command checks the release, target and manifest before enrollment. The first Touch ID prompt enrolls the signer. The command then pins the emitted public key, creates the broker and checks access as the exact execution account. A separate scope window displays the precise three assignments before a fresh Touch ID signature. Cancelling that scope leaves the separately enrolled broker without an audit grant.

The printed private `portable-consent` directory holds one capsule per signed task. Hand the capsules to the scoped native adapter through the protected application provisioning route. Refresh any long-running launcher that predates its new client-group membership. A capsule expires within 15 minutes. The installer will refuse pre-existing issuer, service or replay paths. Preserve a partial install for reconciliation.

To disable the broker, use the same command with the same `--ref`, `--issuer` and `--fingerprint`, replacing audit and apply flags with `--rollback`. It disables the socket and stops the service while retaining the issuer, replay ledger and release record. Runs already accepted stay subject to normal receipt reconciliation.

## Separate signer enrollment

If you used first-time setup, keep the signer and enrollment from its private operator directory for subsequent audits. Use the following standalone commands only if you are provisioning the signer and broker separately.

The signer supports macOS 14 or later on a Mac with Secure Enclave and enrolled Touch ID. Use the installed Apple Swift SDK to build the staged helper.

```sh
swiftc -parse-as-library scripts/t2scan_astra_operator.swift -o t2scan-astra-operator
```

The operator runs enrollment once from the protected installation. Use the administrator-verified issuer and audience. The command creates a private enrollment file and emits a public PEM key for independently verified provisioning.

```sh
./t2scan-astra-operator enroll "$operator_enrollment" "$issuer" "$audience"
```

## Authorize a batch

Prepare an input manifest with an `assignments` array containing exactly three objects. Each has `assignment`, `work_item_id` and `packet_sha256` from the actual audit assignment and packet. Use the full signed role names `executive-synthesis`, `assurance-synthesis` and `delivery-synthesis`. The proposal maker generates the task keys and random nonces and writes canonical challenge bytes to a new file.

```sh
python3 scripts/t2scan_astra_challenge.py --issuer "$issuer" --audience "$audience" \
  --project "$project" --run "$audit" --manifest "$manifest" --out "$challenge"
```

The operator opens the exact challenge with the enrolled signer. The app displays the model, target, audit, work items, packet digests and expiration before requesting fresh Touch ID. A successful approval writes a detached DER signature to a new file.

```sh
./t2scan-astra-operator sign "$challenge" "$operator_enrollment" "$signature"
```

Use the challenge and signature together as the portable proof. Do not change the challenge bytes after signing. The proof is scoped to direct Codex Astra. The existing native transcript approval and Claude-first fallback paths keep their existing authorization rules. The report still requires a genuine model receipt from each native run.

The parser tests use synthetic audit metadata and exercise the real executable without opening the enrollment or biometric UI. Before enabling a real deployment, verify the exact scope in that UI, cancellation, a successful operator signature, one-use consumption, revocation before launch and rollback on issuer replacement or loss of trusted state.
