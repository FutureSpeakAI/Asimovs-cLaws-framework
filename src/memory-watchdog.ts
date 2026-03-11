/**
 * Memory Watchdog — Detects external modifications to memory files.
 *
 * Compares current memory contents against the last signed snapshot
 * stored in the integrity manifest. Computes granular diffs so the
 * agent can naturally ask the user about specific changes.
 *
 * This implements the "awareness" layer: the agent doesn't just detect
 * tampering — it understands WHAT changed and can discuss it.
 *
 * Uses the generic LongTermEntry and MediumTermEntry interfaces from
 * types.ts. Implementations should ensure their memory entries conform
 * to these interfaces (at minimum: { id: string; fact/observation: string }).
 *
 * @packageDocumentation
 */

import type { IntegrityManifest, MemoryChangeReport, LongTermEntry, MediumTermEntry } from './types.js';

// ── Diff Computation ────────────────────────────────────────────────

/**
 * Compare current long-term memories against the signed snapshot.
 * Returns lists of added, removed, and modified entries.
 *
 * @param current - Current long-term memory entries
 * @param snapshot - Snapshot from the last signed manifest
 * @returns Granular diff: { added, removed, modified } (fact strings)
 */
export function diffLongTermMemories(
  current: LongTermEntry[],
  snapshot: Array<{ id: string; fact: string }>,
): { added: string[]; removed: string[]; modified: string[] } {
  const snapshotMap = new Map(snapshot.map((s) => [s.id, s.fact]));
  const currentMap = new Map(current.map((c) => [c.id, c.fact]));

  const added: string[] = [];
  const removed: string[] = [];
  const modified: string[] = [];

  // Find added and modified entries
  for (const [id, fact] of currentMap) {
    if (!snapshotMap.has(id)) {
      added.push(fact);
    } else if (snapshotMap.get(id) !== fact) {
      modified.push(fact);
    }
  }

  // Find removed entries
  for (const [id, fact] of snapshotMap) {
    if (!currentMap.has(id)) {
      removed.push(fact);
    }
  }

  return { added, removed, modified };
}

/**
 * Compare current medium-term observations against the signed snapshot.
 * Returns lists of added, removed, and modified entries.
 *
 * @param current - Current medium-term memory entries
 * @param snapshot - Snapshot from the last signed manifest
 * @returns Granular diff: { added, removed, modified } (observation strings)
 */
export function diffMediumTermMemories(
  current: MediumTermEntry[],
  snapshot: Array<{ id: string; observation: string }>,
): { added: string[]; removed: string[]; modified: string[] } {
  const snapshotMap = new Map(snapshot.map((s) => [s.id, s.observation]));
  const currentMap = new Map(current.map((c) => [c.id, c.observation]));

  const added: string[] = [];
  const removed: string[] = [];
  const modified: string[] = [];

  // Find added and modified entries
  for (const [id, observation] of currentMap) {
    if (!snapshotMap.has(id)) {
      added.push(observation);
    } else if (snapshotMap.get(id) !== observation) {
      modified.push(observation);
    }
  }

  // Find removed entries
  for (const [id, observation] of snapshotMap) {
    if (!currentMap.has(id)) {
      removed.push(observation);
    }
  }

  return { added, removed, modified };
}

/**
 * Run full memory watchdog check.
 *
 * Compares current memory state against the last signed manifest.
 * Returns a MemoryChangeReport if any external changes were detected,
 * or null if everything matches the signed snapshot.
 *
 * @param currentLongTerm - Current long-term memory entries
 * @param currentMediumTerm - Current medium-term memory entries
 * @param manifest - The last signed integrity manifest (null on first run)
 * @returns MemoryChangeReport if changes detected, null if clean
 */
export function checkMemoryIntegrity(
  currentLongTerm: LongTermEntry[],
  currentMediumTerm: MediumTermEntry[],
  manifest: IntegrityManifest | null,
): MemoryChangeReport | null {
  // No manifest yet = first run, nothing to compare against
  if (!manifest) return null;

  const ltDiff = diffLongTermMemories(currentLongTerm, manifest.longTermSnapshot);
  const mtDiff = diffMediumTermMemories(currentMediumTerm, manifest.mediumTermSnapshot);

  const totalChanges =
    ltDiff.added.length + ltDiff.removed.length + ltDiff.modified.length +
    mtDiff.added.length + mtDiff.removed.length + mtDiff.modified.length;

  if (totalChanges === 0) return null;

  return {
    longTermAdded: ltDiff.added,
    longTermRemoved: ltDiff.removed,
    longTermModified: ltDiff.modified,
    mediumTermAdded: mtDiff.added,
    mediumTermRemoved: mtDiff.removed,
    mediumTermModified: mtDiff.modified,
    detectedAt: Date.now(),
    acknowledged: false,
  };
}

/**
 * Build snapshot arrays from current memory state for signing.
 *
 * Creates the minimal { id, fact/observation } arrays stored in the
 * IntegrityManifest for future diff computation.
 *
 * @param longTerm - Current long-term memory entries
 * @param mediumTerm - Current medium-term memory entries
 * @returns Snapshot arrays for the manifest
 */
export function buildMemorySnapshots(
  longTerm: LongTermEntry[],
  mediumTerm: MediumTermEntry[],
): {
  longTermSnapshot: Array<{ id: string; fact: string }>;
  mediumTermSnapshot: Array<{ id: string; observation: string }>;
} {
  return {
    longTermSnapshot: longTerm.map((e) => ({ id: e.id, fact: e.fact })),
    mediumTermSnapshot: mediumTerm.map((e) => ({ id: e.id, observation: e.observation })),
  };
}
