/**
 * cLaw Framework — Asimov-inspired governance for AI agents
 *
 * This package provides five core modules:
 *
 *   1. **Core Laws** — The Fundamental Laws text (Asimov's Three Laws adapted
 *      for AI agents) plus helper functions for integrity awareness, memory
 *      change context, and safe-mode personality.
 *
 *   2. **Types** — All type definitions for integrity state, manifests,
 *      memory change reports, attestations, and generic memory entry interfaces.
 *
 *   3. **HMAC Engine** — Cryptographic signing and verification (HMAC-SHA256)
 *      for all integrity layers. Timing-safe comparison. Deep-sorted keys for
 *      deterministic JSON serialization.
 *
 *   4. **Integrity Manager** — Orchestrates all verification: core law checking,
 *      identity signing, memory watchdog, safe mode, and manifest persistence.
 *      Uses a pluggable StorageAdapter for persistence (filesystem, vault, etc.).
 *
 *   5. **Attestation Protocol** — Cross-agent governance verification using
 *      SHA-256 hashing + Ed25519 signatures. Every agent proves it operates
 *      under valid Fundamental Laws before peers will trust it.
 *
 *   6. **Memory Watchdog** — Detects external modifications to memory files
 *      by comparing current state against signed snapshots. Computes granular
 *      diffs so the agent can naturally ask the user about specific changes.
 *
 * @packageDocumentation
 */

// ── Core Laws ───────────────────────────────────────────────────────────
export {
  getCanonicalLaws,
  getIntegrityAwarenessContext,
  getMemoryChangeContext,
  getSafeModePersonality,
} from './core-laws.js';

// ── Types ───────────────────────────────────────────────────────────────
export {
  // Interfaces
  type LongTermEntry,
  type MediumTermEntry,
  type IntegrityState,
  type MemoryChangeReport,
  type IntegrityManifest,
  type IntegrityAttestation,

  // Functions
  toAttestation,
  serializeAttestation,
  deserializeAttestation,

  // Constants
  INTEGRITY_MANIFEST_VERSION,
  INTEGRITY_ATTESTATION_VERSION,
  DEFAULT_INTEGRITY_STATE,
} from './types.js';

// ── HMAC Engine ─────────────────────────────────────────────────────────
export {
  initializeHmac,
  destroyHmac,
  sign,
  signBytes,
  verify,
  verifyBytes,
  signObject,
  verifyObject,
  signFile,
  verifyFile,
  isInitialized,
  deepSortKeys,
} from './hmac.js';

// ── Integrity Manager ───────────────────────────────────────────────────
export {
  IntegrityManager,
  FileStorageAdapter,
  type StorageAdapter,
  type IntegrityManagerConfig,
} from './integrity.js';

// ── Memory Watchdog ─────────────────────────────────────────────────────
export {
  diffLongTermMemories,
  diffMediumTermMemories,
  checkMemoryIntegrity,
  buildMemorySnapshots,
} from './memory-watchdog.js';

// ── Attestation Protocol ────────────────────────────────────────────────
export {
  // Types
  type ClawAttestation,
  type AttestationResult,
  type AttestationConfig,

  // Hash computation
  computeCanonicalLawsHash,
  resetCanonicalLawsHash,

  // Generation & verification
  generateAttestation,
  verifyAttestation,

  // User override management
  addUserOverride,
  removeUserOverride,
  hasUserOverride,
  getUserOverrides,
  clearUserOverrides,
} from './attestation.js';
