/**
 * cLaw HMAC Engine — Cryptographic signing and verification for integrity protection.
 *
 * Provides HMAC-SHA256 signing and verification for all cLaw integrity layers:
 * - Core Laws verification (tamper detection)
 * - Identity signing (external modification detection)
 * - Memory signing (external change detection)
 * - Binary payload signing (cross-agent attestations, DAG nodes, ledger transactions)
 *
 * The signing key is injected at initialization time. The caller is responsible
 * for key derivation and secure storage. Recommended derivation:
 *
 *   Passphrase -> Argon2id -> masterKey -> HKDF/KDF(subkeyId, context) -> hmacKey
 *
 * All comparisons use timing-safe equality to prevent timing attacks.
 * JSON objects are deep-sorted before signing for deterministic serialization.
 *
 * @packageDocumentation
 */

import crypto from 'crypto';
import fs from 'fs/promises';

// ── Constants ───────────────────────────────────────────────────────

const ALGORITHM = 'sha256';

// ── State ───────────────────────────────────────────────────────────

let signingKey: Buffer | null = null;
let initialized = false;

// ── Initialization ──────────────────────────────────────────────────

/**
 * Initialize the HMAC engine with a pre-derived signing key.
 *
 * Called during boot AFTER key derivation is complete.
 * The key should be derived from a user passphrase or other secret.
 *
 * @param key - The HMAC signing key (Buffer, typically 32 bytes)
 */
export function initializeHmac(key: Buffer): void {
  if (initialized) return;

  // Copy the key so the caller can safely zero their copy
  signingKey = Buffer.from(key);
  initialized = true;
}

/**
 * Clean up HMAC state on shutdown.
 * Zeros the key buffer before releasing the reference.
 */
export function destroyHmac(): void {
  if (signingKey) {
    signingKey.fill(0);
  }
  signingKey = null;
  initialized = false;
}

// ── Signing ─────────────────────────────────────────────────────────

/**
 * Compute HMAC-SHA256 signature for a string payload.
 *
 * @param data - UTF-8 string to sign
 * @returns Hex-encoded HMAC-SHA256 signature
 */
export function sign(data: string): string {
  if (!signingKey) {
    throw new Error('[cLaw/HMAC] Not initialized — call initializeHmac() first');
  }

  const hmac = crypto.createHmac(ALGORITHM, signingKey);
  hmac.update(data, 'utf8');
  return hmac.digest('hex');
}

/**
 * Compute HMAC-SHA256 signature for an arbitrary binary payload.
 * Returns raw bytes — callers can .toString('hex') if they need a string.
 *
 * Designed for: ledger transactions, DAG node signing, and cross-agent
 * attestations that operate on binary payloads rather than UTF-8 strings.
 *
 * @param data - Binary payload to sign
 * @returns Raw HMAC-SHA256 digest (32 bytes)
 */
export function signBytes(data: Buffer): Buffer {
  if (!signingKey) {
    throw new Error('[cLaw/HMAC] Not initialized — call initializeHmac() first');
  }

  const hmac = crypto.createHmac(ALGORITHM, signingKey);
  hmac.update(data);
  return hmac.digest();
}

/**
 * Verify an HMAC-SHA256 signature against a binary payload.
 * Uses timing-safe comparison to prevent timing attacks.
 *
 * @param data - Binary payload to verify
 * @param expectedSignature - Expected HMAC digest (raw bytes)
 * @returns true if the signature is valid
 */
export function verifyBytes(data: Buffer, expectedSignature: Buffer): boolean {
  if (!signingKey) {
    throw new Error('[cLaw/HMAC] Not initialized — call initializeHmac() first');
  }

  const actual = signBytes(data);
  if (actual.length !== expectedSignature.length) return false;
  return crypto.timingSafeEqual(actual, expectedSignature);
}

/**
 * Verify an HMAC-SHA256 signature against a string payload.
 * Uses timing-safe comparison to prevent timing attacks.
 *
 * @param data - UTF-8 string to verify
 * @param expectedSignature - Expected hex-encoded HMAC signature
 * @returns true if the signature is valid
 */
export function verify(data: string, expectedSignature: string): boolean {
  if (!signingKey) {
    throw new Error('[cLaw/HMAC] Not initialized — call initializeHmac() first');
  }

  const actual = sign(data);

  // Timing-safe comparison
  if (actual.length !== expectedSignature.length) return false;
  return crypto.timingSafeEqual(
    Buffer.from(actual, 'hex'),
    Buffer.from(expectedSignature, 'hex'),
  );
}

/**
 * Recursively sort all object keys for deterministic serialization.
 *
 * Deep-sorts ALL object keys at every nesting level to ensure
 * HMAC signatures are stable regardless of key insertion order.
 * This is critical: `{ a: 1, b: 2 }` and `{ b: 2, a: 1 }` must
 * produce the same signature.
 */
function deepSortKeys(value: unknown): unknown {
  if (value === null || value === undefined) return value;
  if (Array.isArray(value)) return value.map(deepSortKeys);
  if (typeof value === 'object') {
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      sorted[key] = deepSortKeys((value as Record<string, unknown>)[key]);
    }
    return sorted;
  }
  return value;
}

/**
 * Sign a JSON-serializable object by converting to canonical (deep-sorted) JSON string.
 *
 * @param obj - Any JSON-serializable object
 * @returns Hex-encoded HMAC-SHA256 signature of the canonical JSON
 */
export function signObject(obj: unknown): string {
  const canonical = JSON.stringify(deepSortKeys(obj));
  return sign(canonical);
}

/**
 * Verify a JSON-serializable object's signature.
 *
 * @param obj - The object to verify
 * @param expectedSignature - Expected hex-encoded HMAC signature
 * @returns true if the signature is valid
 */
export function verifyObject(obj: unknown, expectedSignature: string): boolean {
  const canonical = JSON.stringify(deepSortKeys(obj));
  return verify(canonical, expectedSignature);
}

/**
 * Sign a file's contents.
 *
 * @param filePath - Path to the file to sign
 * @returns Hex-encoded HMAC-SHA256 signature, or empty string if file doesn't exist
 */
export async function signFile(filePath: string): Promise<string> {
  try {
    const content = await fs.readFile(filePath, 'utf-8');
    return sign(content);
  } catch {
    return ''; // File doesn't exist
  }
}

/**
 * Verify a file's contents against an expected signature.
 *
 * @param filePath - Path to the file to verify
 * @param expectedSignature - Expected hex-encoded HMAC signature
 * @returns true if the file content matches the signature
 */
export async function verifyFile(filePath: string, expectedSignature: string): Promise<boolean> {
  try {
    const content = await fs.readFile(filePath, 'utf-8');
    return verify(content, expectedSignature);
  } catch {
    return false; // File doesn't exist or can't be read
  }
}

/**
 * Check if the HMAC engine is initialized and ready for signing/verification.
 */
export function isInitialized(): boolean {
  return initialized;
}

// Re-export deepSortKeys for external use (e.g., canonical serialization)
export { deepSortKeys };
