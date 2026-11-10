import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { parseKeyring } from './secret-box';

/** Approval identifies encrypted value bytes, never a hash of guessable plaintext. KEK rewrap preserves it. */
export function vaultValueDigest(value: { ciphertext: Buffer; iv: Buffer; authTag: Buffer }): string {
  return createHash('sha256').update(value.iv).update(value.authTag).update(value.ciphertext).digest('hex');
}

/**
 * Board #120 — the secrets vault's own crypto. TWO-LAYER envelope
 * encryption, Node's built-in `crypto` ONLY (AES-256-GCM), NO GCP KMS or any
 * cloud-specific API — portable by explicit requirement.
 *
 * Deliberately NOT built on `./secret-box.ts`: that module seals a value
 * directly under the (possibly rotating) root key in ONE layer and is
 * explicitly documented as "NOT a general-purpose PII vault. It seals small
 * opaque strings." The vault needs a genuine DEK+KEK split (each secret gets
 * its own fresh random Data Encryption Key; the KEK only ever wraps DEKs,
 * never touches a secret's plaintext directly), which is a different shape.
 *
 * What IS reused from `secret-box.ts`: `parseKeyring` — the exact same
 * `keyId:base64key,...` newest-first keyring format `BUGTRACKER_VAULT_KEK`
 * is parsed with, so KEK rotation follows the SAME operational pattern this
 * codebase already ships for `FEDERATION_KEYRING`/`PROJECT_INTELLIGENCE_KEYRING`
 * rather than inventing a second one. A bare 32-byte-base64 value (no
 * `keyId:` prefix) is accepted and treated as `default` — the simple single-key
 * case the ticket describes ("env var BUGTRACKER_VAULT_KEK, 32 bytes base64").
 *
 * Every function that receives raw key material (`Buffer`) zeroes it with
 * `.fill(0)` in a `finally` block once done, so a decrypted DEK does not
 * linger in memory for the lifetime of the request beyond its actual use —
 * same discipline `apps/intelligence-worker/src/context.ts`'s
 * `withOpenRouterCredential` doc comment calls for on the sibling secret-box
 * module.
 */

const IV_BYTES = 12;
const AUTH_TAG_BYTES = 16;
const DEK_BYTES = 32;
const ALGORITHM = 'aes-256-gcm';
/** iv || tag || wrapped-dek, see wrapDek. */
const WRAPPED_DEK_BYTES = IV_BYTES + AUTH_TAG_BYTES + DEK_BYTES;

export class VaultCryptoError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'VaultCryptoError';
  }
}

export interface VaultKeyring {
  headKeyId: string;
  ring: Map<string, Buffer>;
}

/**
 * Load and validate the KEK keyring from `BUGTRACKER_VAULT_KEK`.
 *
 * REQUIRED, no silent fallback: an unset or empty value throws immediately,
 * loudly, with an actionable message — never a silent plaintext write. Local
 * dev/test must set their own explicit test KEK (`openssl rand -base64 32`,
 * or the deterministic `Buffer.alloc(32, N).toString('base64')` pattern this
 * repo's own tests already use for `FEDERATION_KEYRING`/
 * `PROJECT_INTELLIGENCE_KEYRING`). Production/dev provisioning is documented
 * in `docs/OPS.md` §2 — this function does not read Secret Manager itself,
 * it only parses whatever the process env already resolved.
 */
export function loadVaultKeyring(raw: string | undefined): VaultKeyring {
  if (!raw || raw.trim() === '') {
    throw new VaultCryptoError(
      'BUGTRACKER_VAULT_KEK is not configured — refusing to handle vault secrets. ' +
        'Generate one with `openssl rand -base64 32` for local dev/test (set it explicitly; ' +
        'there is no default). See docs/OPS.md for production/dev Secret Manager provisioning.',
    );
  }
  const ring = parseKeyring(raw);
  const headKeyId = [...ring.keys()][0];
  if (!headKeyId) {
    throw new VaultCryptoError('BUGTRACKER_VAULT_KEK parsed to an empty keyring');
  }
  return { headKeyId, ring };
}

export function generateDek(): Buffer {
  return randomBytes(DEK_BYTES);
}

/** Wrap a DEK under the keyring's CURRENT head key. Returns the keyId used and a self-contained `iv || tag || ciphertext` blob. */
export function wrapDek(dek: Buffer, keyring: VaultKeyring): { kekKeyId: string; wrapped: Buffer } {
  const key = keyring.ring.get(keyring.headKeyId);
  if (!key) throw new VaultCryptoError(`No KEK available for head keyId "${keyring.headKeyId}"`);
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv(ALGORITHM, key, iv);
  const ct = Buffer.concat([cipher.update(dek), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { kekKeyId: keyring.headKeyId, wrapped: Buffer.concat([iv, tag, ct]) };
}

/** Unwrap a DEK using whichever keyring entry originally wrapped it (`kekKeyId`), not necessarily the current head — this is what makes rotation lazy. */
export function unwrapDek(wrapped: Buffer, kekKeyId: string, keyring: VaultKeyring): Buffer {
  const key = keyring.ring.get(kekKeyId);
  if (!key) {
    throw new VaultCryptoError(
      `No KEK available for keyId "${kekKeyId}" — cannot unwrap this secret's DEK. ` +
        'If this KEK was intentionally retired, it must stay in the keyring until every row wrapped by it has been rotated.',
    );
  }
  if (wrapped.length !== WRAPPED_DEK_BYTES) {
    throw new VaultCryptoError(`Malformed wrapped DEK: expected ${WRAPPED_DEK_BYTES} bytes, got ${wrapped.length}`);
  }
  const iv = wrapped.subarray(0, IV_BYTES);
  const tag = wrapped.subarray(IV_BYTES, IV_BYTES + AUTH_TAG_BYTES);
  const ct = wrapped.subarray(IV_BYTES + AUTH_TAG_BYTES);
  try {
    const decipher = createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]);
  } catch {
    // GCM tag mismatch — deliberately not surfacing OpenSSL's own message,
    // same reasoning as secret-box.ts's openValue.
    throw new VaultCryptoError('Wrapped DEK failed authentication (wrong KEK or corrupted row)');
  }
}

export interface EncryptedSecretValue {
  iv: Buffer;
  authTag: Buffer;
  ciphertext: Buffer;
}

/** Encrypt a secret's plaintext under its own DEK. Fresh random IV every call — GCM catastrophically loses confidentiality AND integrity on IV reuse under one key. */
export function encryptSecretValue(plaintext: string, dek: Buffer): EncryptedSecretValue {
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv(ALGORITHM, dek, iv);
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return { iv, authTag: cipher.getAuthTag(), ciphertext: ct };
}

export function decryptSecretValue(enc: EncryptedSecretValue, dek: Buffer): string {
  try {
    const decipher = createDecipheriv(ALGORITHM, dek, enc.iv);
    decipher.setAuthTag(enc.authTag);
    return Buffer.concat([decipher.update(enc.ciphertext), decipher.final()]).toString('utf8');
  } catch {
    throw new VaultCryptoError('Secret ciphertext failed authentication (tampered, corrupted, or wrong DEK)');
  }
}

export interface SealedVaultSecret {
  kekKeyId: string;
  dekWrapped: Buffer;
  iv: Buffer;
  authTag: Buffer;
  ciphertext: Buffer;
}

/** High-level seal: fresh DEK, wrap it under the current head KEK, encrypt the plaintext under the DEK. Used by both create and rotate-value (a value rotation always mints a brand-new DEK too, never reuses the old one). */
export function sealVaultSecret(plaintext: string, keyring: VaultKeyring): SealedVaultSecret {
  const dek = generateDek();
  try {
    const { kekKeyId, wrapped } = wrapDek(dek, keyring);
    const enc = encryptSecretValue(plaintext, dek);
    return { kekKeyId, dekWrapped: wrapped, iv: enc.iv, authTag: enc.authTag, ciphertext: enc.ciphertext };
  } finally {
    dek.fill(0);
  }
}

export interface SealedVaultSecretRow {
  dekWrapped: Buffer;
  kekKeyId: string;
  iv: Buffer;
  authTag: Buffer;
  ciphertext: Buffer;
}

/**
 * goodqa#15598: a BLIND secret is a value sealed with a marker INSIDE the encrypted plaintext, so the refusal travels with the
 * bytes: every opener (about thirty call sites, including ones that pass a partial row) goes through `openVaultSecret`, which
 * decrypts, sees the marker and refuses unless the caller holds a blind-reveal capability. There is no database lookup to
 * fail open, no per-call-site check to forget, and a row with the marker can never be opened by a code path that was not
 * written to ask for the capability. Only the grantee reveal in `vault-env` issues the capability (census-tested).
 */
const BLIND_MARKER = '\u0000gq-blind-v1\u0000';

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

/**
 * KEK rotation: re-wrap ONE row's DEK under the keyring's current head key.
 * NEVER touches `ciphertext`/`iv`/`authTag` — only the wrapping changes, per
 * the ticket's own words ("re-wrap every DEK with a new KEK, never
 * re-encrypt the underlying ciphertext"). A no-op (returns `null`) when the
 * row's `kekKeyId` already IS the head — callers use this to report how many
 * rows were actually rewrapped vs already current.
 */
export function rewrapDekIfStale(
  row: { dekWrapped: Buffer; kekKeyId: string },
  keyring: VaultKeyring,
): { kekKeyId: string; wrapped: Buffer } | null {
  if (row.kekKeyId === keyring.headKeyId) return null;
  const dek = unwrapDek(row.dekWrapped, row.kekKeyId, keyring);
  try {
    return wrapDek(dek, keyring);
  } finally {
    dek.fill(0);
  }
}
