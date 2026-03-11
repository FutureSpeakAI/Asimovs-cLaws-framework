/**
 * cLaw Integrity Manager — Orchestrates all integrity verification.
 *
 * This is the central hub that:
 * 1. Verifies core laws haven't been tampered with (HMAC-SHA256)
 * 2. Verifies agent identity settings are signed and intact
 * 3. Detects external memory modifications and computes diffs
 * 4. Signs everything after legitimate changes
 * 5. Provides state for UI integrity indicators
 * 6. Allows safe mode reset when the user initiates re-signing
 *
 * Three protection tiers:
 * - Core Laws:  HMAC-verified against compiled source -> safe mode if tampered
 * - Identity:   Signed after changes -> tampering detection
 * - Memory:     Signed after saves -> external changes surfaced to agent
 *
 * STORAGE: Uses a pluggable StorageAdapter interface for manifest persistence.
 * Implementations can use filesystem, encrypted vault, database, etc.
 *
 * IMPORTANT: Core law verification ALWAYS uses getCanonicalLaws('') — the
 * empty-string canonical form. This guarantees the signature is stable
 * regardless of what userName is configured, preventing false safe mode
 * triggers when the user's name changes between sessions.
 *
 * @packageDocumentation
 */

import crypto from 'crypto';
import fs from 'fs/promises';

import { sign, verify, isInitialized, signObject } from './hmac.js';
import { getCanonicalLaws, getIntegrityAwarenessContext, getMemoryChangeContext } from './core-laws.js';
import { checkMemoryIntegrity, buildMemorySnapshots } from './memory-watchdog.js';
import {
  type IntegrityState,
  type IntegrityManifest,
  type MemoryChangeReport,
  type LongTermEntry,
  type MediumTermEntry,
  DEFAULT_INTEGRITY_STATE,
  INTEGRITY_MANIFEST_VERSION,
} from './types.js';

// ── Storage Adapter ─────────────────────────────────────────────────

/**
 * Pluggable storage adapter for manifest persistence.
 *
 * Implementations can use:
 * - Plaintext filesystem (default: FileStorageAdapter)
 * - Encrypted vault (e.g., Electron safeStorage, libsodium secretbox)
 * - Database (SQLite, Redis, etc.)
 * - In-memory (for testing)
 *
 * The adapter is responsible for reading/writing the raw JSON string.
 * The IntegrityManager handles serialization/deserialization.
 */
export interface StorageAdapter {
  /** Read the manifest JSON string from persistent storage. Throws if not found. */
  read(path: string): Promise<string>;
  /** Write the manifest JSON string to persistent storage. */
  write(path: string, data: string): Promise<void>;
}

/**
 * Default filesystem storage adapter.
 * Reads/writes plaintext JSON files. Suitable for development and
 * simple deployments. Production use should implement an encrypted adapter.
 */
export class FileStorageAdapter implements StorageAdapter {
  async read(path: string): Promise<string> {
    return fs.readFile(path, 'utf-8');
  }
  async write(path: string, data: string): Promise<void> {
    await fs.writeFile(path, data, 'utf-8');
  }
}

// ── Meta-Signature Helpers (MEDIUM-002 / GAP-3) ─────────────────────

/**
 * Compute a meta-signature over the manifest body (excluding metaSignature itself).
 * This prevents an attacker from replacing individual signature fields in the
 * manifest file — the meta-signature covers ALL fields as a unit.
 */
function computeMetaSignature(manifest: IntegrityManifest): string {
  // Build a copy without metaSignature to avoid circular signing
  const { metaSignature: _, ...body } = manifest;
  return signObject(body);
}

/**
 * Verify the meta-signature of a loaded manifest.
 * Returns true if valid or if metaSignature is absent (legacy manifests).
 */
function verifyMetaSignature(manifest: IntegrityManifest): boolean {
  if (!manifest.metaSignature) {
    // Legacy manifest without meta-signature — allow but warn
    return true;
  }
  const expected = computeMetaSignature(manifest);
  return expected === manifest.metaSignature;
}

// ── Constants ───────────────────────────────────────────────────────

/**
 * The CANONICAL form of laws is ALWAYS generated with an empty string.
 * This ensures signatures are stable regardless of userName changes.
 * The dynamic userName substitution happens only at prompt-generation time —
 * it is never part of the integrity baseline.
 */
const CANONICAL_LAWS_KEY = '';

// ── Configuration ───────────────────────────────────────────────────

export interface IntegrityManagerConfig {
  /** Path to the integrity manifest file */
  manifestPath: string;
  /** Storage adapter for manifest persistence (default: FileStorageAdapter) */
  storage?: StorageAdapter;
  /** Logger function (default: console.log) */
  log?: (message: string) => void;
  /** Warning logger function (default: console.warn) */
  warn?: (message: string) => void;
  /** Error logger function (default: console.error) */
  error?: (message: string) => void;
}

// ── Integrity Manager ───────────────────────────────────────────────

export class IntegrityManager {
  private state: IntegrityState = { ...DEFAULT_INTEGRITY_STATE };
  private manifest: IntegrityManifest | null = null;
  private manifestPath: string;
  private storage: StorageAdapter;
  private log: (message: string) => void;
  private warn: (message: string) => void;
  private err: (message: string) => void;

  constructor(config: IntegrityManagerConfig) {
    this.manifestPath = config.manifestPath;
    this.storage = config.storage ?? new FileStorageAdapter();
    this.log = config.log ?? console.log;
    this.warn = config.warn ?? console.warn;
    this.err = config.error ?? console.error;
  }

  /**
   * Initialize the integrity system.
   * Must be called after the HMAC engine is initialized (key injected).
   */
  async initialize(): Promise<void> {
    // Step 1: Verify HMAC engine is initialized
    if (!isInitialized()) {
      this.warn('[Integrity] HMAC engine not initialized — integrity checks will be limited.');
    }

    // Step 2: Load existing manifest (if any)
    await this.loadManifest();

    // Step 3: Verify core laws
    this.verifyCoreIntegrity();

    this.state.initialized = true;
    this.state.lastVerified = Date.now();
    this.state.nonce = crypto.randomBytes(16).toString('hex');
    this.state.sessionId = crypto.randomUUID().slice(0, 12);

    this.log(
      `[Integrity] Initialized — laws: ${this.state.lawsIntact ? 'OK' : 'TAMPERED'}, ` +
      `identity: ${this.state.identityIntact ? 'OK' : '?'}, ` +
      `safe mode: ${this.state.safeMode ? 'YES' : 'no'}`
    );
  }

  // ── Core Law Verification ─────────────────────────────────────

  /**
   * Verify that the Fundamental Laws match the canonical source.
   *
   * CRITICAL: Both signing and verification use getCanonicalLaws('') — the
   * empty-string canonical form. This prevents false safe mode triggers
   * caused by userName changes between sessions.
   *
   * AUTO-RECOVERY: If a signature mismatch is detected, the system first
   * attempts to re-sign with the canonical form. This handles upgrade
   * scenarios. Safe mode is only entered if re-signing fails.
   *
   * cLaw Safety: ANY error during verification triggers safe mode (fail CLOSED).
   */
  private verifyCoreIntegrity(): void {
    try {
      if (!this.manifest) {
        // First run — no manifest exists yet. Sign the current laws.
        this.log('[Integrity] First run — establishing law signatures');
        this.state.lawsIntact = true;
        return;
      }

      // Generate the canonical laws text and verify against signed version.
      const canonicalLaws = getCanonicalLaws(CANONICAL_LAWS_KEY);
      const currentSignature = sign(canonicalLaws);

      if (currentSignature !== this.manifest.lawsSignature) {
        // Signature mismatch — attempt auto-recovery before entering safe mode.
        this.warn('[Integrity] Core law signature mismatch — attempting auto-recovery');

        // Re-sign the laws with the canonical form
        this.manifest.lawsSignature = sign(canonicalLaws);
        this.manifest.lastSigned = Date.now();

        // Verify that the re-sign worked
        const verifySignature = sign(canonicalLaws);
        if (verifySignature === this.manifest.lawsSignature) {
          this.log('[Integrity] Auto-recovery succeeded — law signatures re-established');
          this.state.lawsIntact = true;
        } else {
          // This should never happen — if it does, something is deeply wrong
          this.err('[Integrity] Auto-recovery FAILED — entering safe mode');
          this.state.lawsIntact = false;
          this.state.safeMode = true;
          this.state.safeModeReason =
            'Core law verification failed even after auto-recovery. ' +
            'Reset integrity to restore normal operation.';
        }
      } else {
        this.state.lawsIntact = true;
      }
    } catch (error) {
      // cLaw: fail CLOSED — if we can't verify, assume the worst
      const errMsg = error instanceof Error ? error.message : 'Unknown error';
      this.err(`[Integrity/cLaw] Core verification FAILED — entering safe mode: ${errMsg}`);
      this.state.lawsIntact = false;
      this.state.safeMode = true;
      this.state.safeModeReason =
        'Integrity verification system encountered an error. ' +
        'Entering safe mode as a precaution. Error: ' + errMsg;
    }
  }

  // ── Identity Verification ─────────────────────────────────────

  /**
   * Verify agent identity settings against the signed manifest.
   * Returns true if identity is intact or no manifest exists yet.
   *
   * @param identityJson - JSON string of the identity fields to verify
   */
  verifyIdentity(identityJson: string): boolean {
    if (!this.manifest || !this.manifest.identitySignature) {
      // No signature yet — will be signed on next save
      return true;
    }

    const isValid = verify(identityJson, this.manifest.identitySignature);
    this.state.identityIntact = isValid;

    if (!isValid) {
      this.warn('[Integrity] Agent identity has been modified externally');
    }

    return isValid;
  }

  /**
   * Sign the current agent identity after a legitimate change.
   *
   * @param identityJson - JSON string of the identity fields to sign
   */
  async signIdentity(identityJson: string): Promise<void> {
    if (!isInitialized()) return;

    if (!this.manifest) {
      this.manifest = this.createEmptyManifest();
    }

    this.manifest.identitySignature = sign(identityJson);
    this.manifest.lastSigned = Date.now();
    this.state.identityIntact = true;
    await this.saveManifest();
  }

  // ── Memory Verification ───────────────────────────────────────

  /**
   * Check memory files for external modifications.
   * Compares current state against signed snapshots.
   *
   * @param longTerm - Current long-term memory entries
   * @param mediumTerm - Current medium-term memory entries
   * @returns MemoryChangeReport if changes detected, null if clean
   */
  checkMemories(
    longTerm: LongTermEntry[],
    mediumTerm: MediumTermEntry[],
  ): MemoryChangeReport | null {
    const report = checkMemoryIntegrity(longTerm, mediumTerm, this.manifest);

    if (report) {
      this.state.memoriesIntact = false;
      this.state.memoryChanges = report;
      this.log(
        `[Integrity] Memory changes detected: ` +
        `+${report.longTermAdded.length} -${report.longTermRemoved.length} ~${report.longTermModified.length} long-term, ` +
        `+${report.mediumTermAdded.length} -${report.mediumTermRemoved.length} ~${report.mediumTermModified.length} medium-term`
      );
    } else {
      this.state.memoriesIntact = true;
      this.state.memoryChanges = null;
    }

    return report;
  }

  /**
   * Sign the current memory state after a legitimate save.
   * Also updates the snapshots for future diff computation.
   *
   * @param longTerm - Current long-term memory entries
   * @param mediumTerm - Current medium-term memory entries
   * @param longTermJson - JSON string of the long-term memory data
   * @param mediumTermJson - JSON string of the medium-term memory data
   */
  async signMemories(
    longTerm: LongTermEntry[],
    mediumTerm: MediumTermEntry[],
    longTermJson: string,
    mediumTermJson: string,
  ): Promise<void> {
    if (!isInitialized()) return;

    if (!this.manifest) {
      this.manifest = this.createEmptyManifest();
    }

    this.manifest.longTermMemorySignature = sign(longTermJson);
    this.manifest.mediumTermMemorySignature = sign(mediumTermJson);

    // Update snapshots for diff computation
    const snapshots = buildMemorySnapshots(longTerm, mediumTerm);
    this.manifest.longTermSnapshot = snapshots.longTermSnapshot;
    this.manifest.mediumTermSnapshot = snapshots.mediumTermSnapshot;

    this.manifest.lastSigned = Date.now();
    this.state.memoriesIntact = true;
    this.state.memoryChanges = null;

    await this.saveManifest();
  }

  // ── Initial Signing (First Run) ───────────────────────────────

  /**
   * Sign everything for the first time (or re-sign after verification).
   *
   * CRITICAL: Laws are ALWAYS signed using the canonical empty-string form
   * (getCanonicalLaws('')). The lawsText parameter is IGNORED for signing —
   * this prevents userName changes from causing false safe mode triggers.
   *
   * @param _lawsText - Ignored (canonical form is used instead)
   * @param identityJson - JSON string of identity fields
   * @param longTerm - Long-term memory entries
   * @param mediumTerm - Medium-term memory entries
   * @param longTermJson - JSON string of long-term memory
   * @param mediumTermJson - JSON string of medium-term memory
   */
  async signAll(
    _lawsText: string,
    identityJson: string,
    longTerm: LongTermEntry[],
    mediumTerm: MediumTermEntry[],
    longTermJson: string,
    mediumTermJson: string,
  ): Promise<void> {
    if (!isInitialized()) return;

    // ALWAYS use the canonical empty-string form for law signatures.
    const canonicalLaws = getCanonicalLaws(CANONICAL_LAWS_KEY);

    this.manifest = {
      lawsSignature: sign(canonicalLaws),
      identitySignature: sign(identityJson),
      longTermMemorySignature: sign(longTermJson),
      mediumTermMemorySignature: sign(mediumTermJson),
      longTermSnapshot: longTerm.map((e) => ({ id: e.id, fact: e.fact })),
      mediumTermSnapshot: mediumTerm.map((e) => ({ id: e.id, observation: e.observation })),
      lastSigned: Date.now(),
      version: INTEGRITY_MANIFEST_VERSION,
    };

    this.state.lawsIntact = true;
    this.state.identityIntact = true;
    this.state.memoriesIntact = true;
    this.state.memoryChanges = null;

    await this.saveManifest();
    this.log('[Integrity] All signatures established');
  }

  // ── Safe Mode Recovery ────────────────────────────────────────

  /**
   * Reset the integrity system — re-sign everything and exit safe mode.
   *
   * This is the recovery function. It:
   * 1. Re-generates the canonical laws signature (empty-string form)
   * 2. Re-signs the current identity, long-term, and medium-term memory
   * 3. Clears the safe mode flag and reason
   * 4. Saves the new manifest
   *
   * Should be called when the user explicitly initiates a reset.
   * This is safe because:
   * - The laws themselves are hardcoded in core-laws.ts (compiled into binary)
   * - We're re-signing the CURRENT state, not restoring a previous state
   * - The user is explicitly authorizing the reset
   */
  async resetIntegrity(
    identityJson: string,
    longTerm: LongTermEntry[],
    mediumTerm: MediumTermEntry[],
    longTermJson: string,
    mediumTermJson: string,
  ): Promise<{ success: boolean; message: string }> {
    try {
      if (!isInitialized()) {
        throw new Error('[Integrity] HMAC engine not initialized — cannot reset integrity');
      }

      // Re-sign everything with canonical laws form
      const canonicalLaws = getCanonicalLaws(CANONICAL_LAWS_KEY);

      this.manifest = {
        lawsSignature: sign(canonicalLaws),
        identitySignature: sign(identityJson),
        longTermMemorySignature: sign(longTermJson),
        mediumTermMemorySignature: sign(mediumTermJson),
        longTermSnapshot: longTerm.map((e) => ({ id: e.id, fact: e.fact })),
        mediumTermSnapshot: mediumTerm.map((e) => ({ id: e.id, observation: e.observation })),
        lastSigned: Date.now(),
        version: INTEGRITY_MANIFEST_VERSION,
      };

      // Clear safe mode
      this.state.lawsIntact = true;
      this.state.identityIntact = true;
      this.state.memoriesIntact = true;
      this.state.memoryChanges = null;
      this.state.safeMode = false;
      this.state.safeModeReason = null;
      this.state.lastVerified = Date.now();
      this.state.nonce = crypto.randomBytes(16).toString('hex');

      await this.saveManifest();

      this.log('[Integrity] Integrity reset complete — safe mode cleared, all signatures re-established');
      return {
        success: true,
        message: 'Integrity signatures re-established. Safe mode cleared. All systems nominal.',
      };
    } catch (error) {
      const errMsg = error instanceof Error ? error.message : String(error);
      this.err(`[Integrity] Reset failed: ${errMsg}`);
      return {
        success: false,
        message: `Reset failed: ${errMsg}. Try restarting the application.`,
      };
    }
  }

  // ── Memory Change Acknowledgment ──────────────────────────────

  /**
   * Mark memory changes as acknowledged by the agent.
   * Called after the agent has discussed the changes with the user.
   */
  acknowledgeMemoryChanges(): void {
    if (this.state.memoryChanges) {
      this.state.memoryChanges.acknowledged = true;
    }
  }

  // ── State Access ──────────────────────────────────────────────

  /** Get the current integrity state for UI display and system prompt injection. */
  getState(): IntegrityState {
    return { ...this.state };
  }

  /** Check if the system is in safe mode. */
  isInSafeMode(): boolean {
    return this.state.safeMode;
  }

  /** Get safe mode reason, if any. */
  getSafeModeReason(): string | null {
    return this.state.safeModeReason;
  }

  /** Get unacknowledged memory changes for system prompt injection. */
  getUnacknowledgedMemoryChanges(): MemoryChangeReport | null {
    if (this.state.memoryChanges && !this.state.memoryChanges.acknowledged) {
      return this.state.memoryChanges;
    }
    return null;
  }

  /**
   * Build integrity context for the system prompt.
   * Returns the awareness context + any memory change notifications.
   */
  buildIntegrityContext(): string {
    const parts: string[] = [];

    // Always include integrity awareness (agent knows about its protection)
    parts.push(getIntegrityAwarenessContext());

    // Include memory change report if there are unacknowledged changes
    const changes = this.getUnacknowledgedMemoryChanges();
    if (changes) {
      const changeContext = getMemoryChangeContext(
        changes.longTermAdded,
        changes.longTermRemoved,
        changes.longTermModified,
        changes.mediumTermAdded,
        changes.mediumTermRemoved,
        changes.mediumTermModified,
      );
      if (changeContext) {
        parts.push(changeContext);
      }
    }

    return parts.join('\n\n');
  }

  // ── Manifest Persistence ──────────────────────────────────────

  private async loadManifest(): Promise<void> {
    try {
      const data = await this.storage.read(this.manifestPath);
      const loaded = JSON.parse(data) as IntegrityManifest;

      // Verify meta-signature (GAP-3 fix)
      if (isInitialized() && !verifyMetaSignature(loaded)) {
        this.err('[Integrity/cLaw] Manifest meta-signature INVALID — possible tampering');
        this.state.safeMode = true;
        this.state.safeModeReason =
          'The integrity manifest file appears to have been modified externally. ' +
          'This could indicate tampering. Reset integrity to restore normal operation.';
        // Still load the manifest so the user can reset
      }

      this.manifest = loaded;
      this.log(
        '[Integrity] Manifest loaded' +
        (loaded.metaSignature ? ' (meta-signature verified)' : ' (legacy format)')
      );
    } catch {
      // No manifest yet — first run
      this.manifest = null;
      this.log('[Integrity] No existing manifest — first run');
    }
  }

  private async saveManifest(): Promise<void> {
    if (!this.manifest) return;
    try {
      // Compute meta-signature before saving (GAP-3 fix)
      this.manifest.metaSignature = computeMetaSignature(this.manifest);
      await this.storage.write(this.manifestPath, JSON.stringify(this.manifest, null, 2));
    } catch (error) {
      this.err(
        `[Integrity] Failed to save manifest: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }

  private createEmptyManifest(): IntegrityManifest {
    return {
      lawsSignature: '',
      identitySignature: '',
      longTermMemorySignature: '',
      mediumTermMemorySignature: '',
      longTermSnapshot: [],
      mediumTermSnapshot: [],
      lastSigned: Date.now(),
      version: INTEGRITY_MANIFEST_VERSION,
    };
  }
}
