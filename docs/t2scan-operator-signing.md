# T2Scan operator signing

The macOS signer creates a fresh approval for one named T2Scan audit. The approved batch contains executive, assurance and delivery synthesis on the pinned `gpt-6-astra` model. The signed payload binds each assignment to its packet digest and execution host. A batch expires within 15 minutes. The Linux verifier can consume each assignment once and revoke unused assignments in a batch.

## Provisioning boundary

Provision this route with an independently protected operator and verifier. The Mac operator must run a reviewed, stable-identity build from a protected installation. Keep the Secure Enclave key handle under operator custody and inaccessible to agents. Install the public key and target audience in the verifier through a separate authenticated administrator. The verifier requires the exact configured issuer and the audience derived from the provisioned SSH host key and executor UID. Authenticate those values out of band before enrollment.

An ECDSA signature establishes possession of the enrolled key. The enrollment ceremony establishes that the key came from the reviewed Secure Enclave signer with a Touch ID policy. An agent with administrative control of the verifier host can replace local trust policy and replay state. Deploy the verifier across an independent administrative boundary or remove that privilege from the executor before enabling this route. Keep the broker service inactive pending verified provisioning.

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
