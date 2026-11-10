import subprocess

subprocess.run(['scp', '-q', 't2-dev:wt-15561/packages/db/src/vault-crypto.ts', 'vault-crypto.ts'], check=True)
s = open('vault-crypto.ts').read()
old = """/** Open a stored row back to plaintext. The only function that ever produces a secret's real value from stored bytes. */
export function openVaultSecret(row: SealedVaultSecretRow, keyring: VaultKeyring): string {
  const dek = unwrapDek(row.dekWrapped, row.kekKeyId, keyring);
  try {
    return decryptSecretValue({ iv: row.iv, authTag: row.authTag, ciphertext: row.ciphertext }, dek);
  } finally {
    dek.fill(0);
  }
}
"""
new = """/**
 * goodqa#15598: a BLIND secret is a value sealed with a marker INSIDE the encrypted plaintext, so the refusal travels with the
 * bytes: every opener (about thirty call sites, including ones that pass a partial row) goes through `openVaultSecret`, which
 * decrypts, sees the marker and refuses unless the caller holds a blind-reveal capability. There is no database lookup to
 * fail open, no per-call-site check to forget, and a row with the marker can never be opened by a code path that was not
 * written to ask for the capability. Only the grantee reveal in `vault-env` issues the capability (census-tested).
 */
const BLIND_MARKER = '\\u0000gq-blind-v1\\u0000';

export class VaultBlindSecretError extends VaultCryptoError {
  constructor() {
    super('This secret is blind: only its named grantee may read it');
  }
}

declare const blindRevealBrand: unique symbol;
/** An unforgeable token, issued by `issueBlindRevealCapability`; `openVaultSecret` accepts only issued ones. */
export interface BlindRevealCapability {
  readonly [blindRevealBrand]: true;
}
const issuedCapabilities = new WeakSet<object>();
/** Only `modules/vault-env` may call this (the census test pins the importers). */
export function issueBlindRevealCapability(): BlindRevealCapability {
  const capability = Object.freeze({}) as BlindRevealCapability;
  issuedCapabilities.add(capability);
  return capability;
}

/** Seal a value as blind: the plaintext carries the marker, so any opener without the capability refuses it. */
export function sealBlindVaultSecret(plaintext: string, keyring: VaultKeyring): SealedVaultSecret {
  return sealVaultSecret(`${BLIND_MARKER}${plaintext}`, keyring);
}

/** Open a stored row back to plaintext. The only function that ever produces a secret's real value from stored bytes. A blind secret needs the capability. */
export function openVaultSecret(row: SealedVaultSecretRow, keyring: VaultKeyring, capability?: BlindRevealCapability): string {
  const dek = unwrapDek(row.dekWrapped, row.kekKeyId, keyring);
  try {
    const value = decryptSecretValue({ iv: row.iv, authTag: row.authTag, ciphertext: row.ciphertext }, dek);
    if (!value.startsWith(BLIND_MARKER)) return value;
    if (capability !== undefined && issuedCapabilities.has(capability)) return value.slice(BLIND_MARKER.length);
    throw new VaultBlindSecretError();
  } finally {
    dek.fill(0);
  }
}
"""
assert s.count(old) == 1
open('vault-crypto.ts', 'w').write(s.replace(old, new))
print('ok')
