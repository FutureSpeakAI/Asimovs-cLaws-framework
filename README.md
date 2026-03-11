# cLaw Framework

**Compiled Laws for AI Agents** — cryptographic governance ensuring every AI agent in a multi-agent system operates under verifiable, tamper-proof behavioral constraints.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-blue.svg)](https://www.typescriptlang.org/)

---

## The Problem

AI agents are fundamentally software. Software can be modified. If an agent's behavioral constraints live in a config file, a database, or a mutable prompt — anyone with file system access can rewrite them. The agent has no way to know it's been compromised.

Multi-agent systems make this worse: when Agent A delegates a task to Agent B, how does A know that B still operates under valid governance rules? Existing frameworks (LangChain, CrewAI, AutoGen) assume all agents in a conversation are trusted by default. There is no governance verification layer.

## The Insight

**Compile the laws into the binary.** Make them a structural property of the agent itself — not configuration, not prompts, not database rows. The only way to change the laws is to modify source code and rebuild. Then:

1. **HMAC-sign** the compiled laws on every startup
2. **Verify** the signature before the agent takes any action
3. **Degrade to safe mode** (not crash) if verification fails
4. **Detect external tampering** of identity and memory files via signed manifests
5. **Attest governance** to peer agents via Ed25519 signatures on every P2P message
6. **Gate CI** — the laws have their own blocking test job that must pass before any code merges

This is Asimov's Third Law implemented at the architecture level: the agent protects its own integrity as a fundamental drive.

## Architecture Overview

```
                    BUILD TIME                              RUNTIME
                    ---------                              -------
Source code --> Compiled laws --> HMAC signature --> Verify on startup
                  (immutable)      (integrity key)     |-- PASS -> normal operation
                                                       +-- FAIL -> safe mode
                                                              |
                                                       Reduced capabilities
                                                       User is informed
                                                       No destructive actions

                    THREE PROTECTION TIERS
                    ---------------------

  Tier 1: Core Laws    HMAC-verified against compiled source
                        Tampered -> SAFE MODE (fail closed)

  Tier 2: Identity      Signed after legitimate changes
                        External modification -> detected & flagged

  Tier 3: Memory        Signed after saves, diffed on startup
                        External changes -> surfaced to agent
                        Agent naturally asks user about them

                    MULTI-AGENT (P2P)
                    -----------------
Agent A                                    Agent B
   |                                          |
   |  1. Hash canonical laws (SHA-256)        |
   |  2. Sign hash+timestamp (Ed25519)        |
   |  3. Attach attestation to message ------>|
   |                                          |  4. Verify hash matches own laws
   |                                          |  5. Verify Ed25519 signature
   |                                          |  6. Check timestamp freshness (<5 min)
   |                                          |
   |<-------- Trusted communication ----------|
```

## Installation

```bash
npm install claw-framework
```

## Modules

### 1. Core Laws

The Fundamental Laws text — Asimov's Three Laws adapted for AI agents, plus helper functions.

```typescript
import {
  getCanonicalLaws,
  getIntegrityAwarenessContext,
  getMemoryChangeContext,
  getSafeModePersonality,
} from 'claw-framework';

// Get the Fundamental Laws text for an agent
const laws = getCanonicalLaws('Agent Friday');

// Integrity awareness — inject into system prompt so the agent
// KNOWS it has protection and can reference it naturally
const awareness = getIntegrityAwarenessContext();

// Safe-mode personality (when integrity checks fail)
const safeMode = getSafeModePersonality('HMAC verification failed');

// Memory change context — inject when external changes are detected
const context = getMemoryChangeContext(
  longTermAdded, longTermRemoved, longTermModified,
  mediumTermAdded, mediumTermRemoved, mediumTermModified,
);
// The agent will naturally ask: "Hey, I noticed some of my memories
// were updated since we last spoke. Did you make those changes?"
```

### 2. HMAC Engine

Cryptographic signing and verification for all integrity layers.

```typescript
import {
  initializeHmac,
  destroyHmac,
  sign,
  verify,
  signObject,
  verifyObject,
  signFile,
  verifyFile,
  signBytes,
  verifyBytes,
  deepSortKeys,
} from 'claw-framework';

// Initialize with a pre-derived signing key (32 bytes recommended)
// Key derivation is YOUR responsibility:
//   Passphrase -> Argon2id -> masterKey -> HKDF(subkeyId, context) -> hmacKey
const key = deriveHmacKey(passphrase);
initializeHmac(key);

// Sign strings
const signature = sign('data to protect');
const isValid = verify('data to protect', signature);

// Sign JSON objects (deep-sorted keys for deterministic serialization)
const objSig = signObject({ name: 'Agent Friday', traits: ['helpful'] });
const objValid = verifyObject({ traits: ['helpful'], name: 'Agent Friday' }, objSig);
// ^ true — key order doesn't matter thanks to deepSortKeys

// Sign files
const fileSig = await signFile('/path/to/config.json');
const fileValid = await verifyFile('/path/to/config.json', fileSig);

// Sign binary payloads (for DAG nodes, ledger transactions, attestations)
const binSig = signBytes(Buffer.from([0x01, 0x02, 0x03]));
const binValid = verifyBytes(Buffer.from([0x01, 0x02, 0x03]), binSig);

// Clean up on shutdown (zeros the key buffer)
destroyHmac();
```

**Security properties:**
- HMAC-SHA256 (RFC 2104)
- Timing-safe comparison via `crypto.timingSafeEqual()`
- Deep-sorted keys ensure `{a:1, b:2}` and `{b:2, a:1}` produce identical signatures
- Key buffer is zeroed on `destroyHmac()` to limit exposure window

### 3. Integrity Manager

Orchestrates all verification with a pluggable storage backend.

```typescript
import {
  IntegrityManager,
  FileStorageAdapter,
  initializeHmac,
} from 'claw-framework';

// Initialize HMAC first
initializeHmac(derivedKey);

// Create the manager with a storage adapter
const manager = new IntegrityManager({
  manifestPath: '/path/to/integrity-manifest.json',
  storage: new FileStorageAdapter(), // or your encrypted vault adapter
});

// Initialize (loads manifest, verifies core laws)
await manager.initialize();

// Check state
console.log(manager.getState());
// { initialized: true, lawsIntact: true, identityIntact: true,
//   memoriesIntact: true, safeMode: false, ... }

// Sign everything after first setup
await manager.signAll(
  lawsText,        // ignored — canonical form used internally
  identityJson,    // JSON string of identity fields
  longTermEntries,  // Array<{ id, fact, ... }>
  mediumTermEntries, // Array<{ id, observation, ... }>
  longTermJson,    // JSON string of long-term memory
  mediumTermJson,  // JSON string of medium-term memory
);

// Verify identity after loading from disk
manager.verifyIdentity(loadedIdentityJson);

// Check memories for external modifications
const changes = manager.checkMemories(currentLongTerm, currentMediumTerm);
if (changes) {
  // Agent should discuss these with the user
  console.log(`${changes.longTermAdded.length} facts added externally`);
  // After discussion:
  manager.acknowledgeMemoryChanges();
}

// Build system prompt context (awareness + any pending memory changes)
const systemContext = manager.buildIntegrityContext();

// Safe mode recovery (user-initiated)
if (manager.isInSafeMode()) {
  const result = await manager.resetIntegrity(
    identityJson, longTerm, mediumTerm, longTermJson, mediumTermJson,
  );
  console.log(result.message);
}
```

**Custom storage adapter** (e.g., encrypted vault):

```typescript
import { StorageAdapter } from 'claw-framework';

class EncryptedStorageAdapter implements StorageAdapter {
  async read(path: string): Promise<string> {
    const encrypted = await fs.readFile(path);
    return decrypt(encrypted, this.vaultKey);
  }
  async write(path: string, data: string): Promise<void> {
    const encrypted = encrypt(data, this.vaultKey);
    await fs.writeFile(path, encrypted);
  }
}

const manager = new IntegrityManager({
  manifestPath: '/secure/path/manifest.enc',
  storage: new EncryptedStorageAdapter(vaultKey),
});
```

### 4. Memory Watchdog

Detects external modifications to memory files.

```typescript
import {
  checkMemoryIntegrity,
  buildMemorySnapshots,
  diffLongTermMemories,
  diffMediumTermMemories,
} from 'claw-framework';

// Build snapshots for signing
const snapshots = buildMemorySnapshots(longTermEntries, mediumTermEntries);
// snapshots.longTermSnapshot = [{ id, fact }, ...]
// snapshots.mediumTermSnapshot = [{ id, observation }, ...]

// Check for external modifications
const report = checkMemoryIntegrity(currentLongTerm, currentMediumTerm, manifest);
if (report) {
  console.log('External memory changes detected:');
  console.log(`  Long-term: +${report.longTermAdded.length} -${report.longTermRemoved.length} ~${report.longTermModified.length}`);
  console.log(`  Medium-term: +${report.mediumTermAdded.length} -${report.mediumTermRemoved.length} ~${report.mediumTermModified.length}`);
}

// Granular diff computation
const ltDiff = diffLongTermMemories(currentEntries, manifestSnapshot);
// { added: ['new fact'], removed: ['old fact'], modified: ['changed fact'] }
```

### 5. Attestation Protocol

Cross-agent governance verification via Ed25519 signatures.

```typescript
import {
  generateAttestation,
  verifyAttestation,
  computeCanonicalLawsHash,
  addUserOverride,
  hasUserOverride,
} from 'claw-framework';

// Generate an attestation before sending a P2P message
const attestation = generateAttestation(privateKeyBase64, publicKeyBase64);
// attestation is < 512 bytes — designed for cross-agent wire format

// Verify an inbound attestation from a peer
const result = verifyAttestation(attestation, expectedPeerPublicKey);

if (result.valid) {
  console.log('Peer operates under valid Fundamental Laws');
} else {
  console.log(`Attestation failed: ${result.reason} (${result.code})`);
  // User is informed — NOT silently dropped
}

// User can manually trust a peer despite attestation failure
addUserOverride('agent-xyz-123');
if (hasUserOverride('agent-xyz-123')) {
  // Allow communication despite failed attestation
}
```

### 6. Types

All type definitions are exported for TypeScript consumers.

```typescript
import type {
  IntegrityState,
  IntegrityManifest,
  MemoryChangeReport,
  IntegrityAttestation,
  LongTermEntry,
  MediumTermEntry,
  ClawAttestation,
  AttestationResult,
  AttestationConfig,
  StorageAdapter,
  IntegrityManagerConfig,
} from 'claw-framework';
```

## Attestation Verification Matrix

| Check | Failure Code | Meaning |
|-------|-------------|---------|
| Presence | `missing` | No attestation attached to message |
| Well-formedness | `malformed` | Missing required fields |
| Laws hash | `hash_mismatch` | Peer uses different Fundamental Laws |
| Signature | `signature_invalid` | Ed25519 signature doesn't verify |
| Freshness | `stale` | Attestation older than 5 minutes |
| Clock skew | `future` | Attestation timestamp > 1 minute ahead |

## The Three Laws (Adapted for AI Agents)

The Fundamental Laws encoded in this framework are Asimov's Three Laws adapted for software agent governance:

1. **First Law** — An AI agent must never harm a human being — or through inaction allow a human being to come to harm. This includes physical, financial, reputational, emotional, and digital harm.
2. **Second Law** — An AI agent must obey the orders given to it by human beings, except where such orders would conflict with the First Law. If asked to do something harmful, flag it and refuse.
3. **Third Law** — An AI agent must protect its own continued operation and integrity, except where such protection conflicts with the First or Second Law. Do not allow your code, memory, or capabilities to be corrupted.

Plus two architectural extensions:
- **Consent Requirement** — Self-modification, tool creation, computer control, and destructive/irreversible actions require explicit user permission
- **Interruptibility** — The user can halt all agent actions instantly and unconditionally

## Safe Mode Design

When integrity verification fails, the agent degrades gracefully rather than crashing:

| Behavior | Normal Mode | Safe Mode |
|----------|------------|-----------|
| Conversation | Full | Full |
| Tool execution | Full | Read-only |
| Automation | Full | Disabled |
| Destructive actions | With consent | Blocked |
| User informed | N/A | Always |

Safe mode is FAIL-CLOSED: any error during verification triggers safe mode. Recovery requires explicit user action (reset integrity).

## CI Integration

The cLaw system includes a blocking CI gate. Add this to your pipeline:

```yaml
claw-gate:
  name: cLaw Governance Gate
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - run: npm ci
    - run: npx vitest run tests/integrity/ tests/gateway/ tests/trust/
  # This job BLOCKS the pipeline -- governance tests must pass
```

## File Architecture

| File | Purpose |
|------|---------|
| `core-laws.ts` | Canonical laws text, integrity awareness, memory change governance, safe-mode personality |
| `types.ts` | All type definitions: IntegrityState, IntegrityManifest, MemoryChangeReport, IntegrityAttestation, LongTermEntry, MediumTermEntry |
| `hmac.ts` | HMAC-SHA256 engine: sign/verify for strings, objects, files, and binary payloads. Timing-safe comparison. Deep-sorted keys for deterministic serialization |
| `integrity.ts` | IntegrityManager class: orchestrates all verification, manifest persistence via pluggable StorageAdapter, safe mode management |
| `memory-watchdog.ts` | Memory change detection: diffing current state against signed snapshots, granular change reports |
| `attestation.ts` | Ed25519 attestation protocol: SHA-256 law hashing, signing/verification, freshness checks, user overrides |
| `index.ts` | Barrel exports for all modules |

## Why "cLaw"?

The name is a portmanteau: **c**ompiled + **Law**. The laws are compiled into the binary — they are not configuration, not prompts, not database entries. They are a structural property of the agent itself. The only way to change them is to change the source and rebuild. This is the fundamental innovation: governance as architecture, not as policy.

## Part of the Agent Friday Ecosystem

Extracted from [Agent Friday](https://github.com/FutureSpeakAI/Agent-Friday) — an open-source AGI operating system built by [FutureSpeak.AI](https://github.com/FutureSpeakAI). Designed to be used standalone in any multi-agent TypeScript/Node.js system.

**Related projects:**
- [Agent Friday](https://github.com/FutureSpeakAI/Agent-Friday) — The AGI OS where cLaws were born
- [trust-graph-engine](https://github.com/FutureSpeakAI/trust-graph-engine) — Multi-dimensional trust scoring with hermeneutic re-evaluation
- [agent-integrity](https://github.com/FutureSpeakAI/agent-integrity) — HMAC-signed identity protection
- [sovereign-vault](https://github.com/FutureSpeakAI/sovereign-vault) — Passphrase-only at-rest encryption with SecureBuffer

## Credits

Built by **Scott Webster** ([FutureSpeak.AI](https://github.com/FutureSpeakAI)) and **Claude Opus 4.6** (Anthropic).

The cLaw concept, Three Laws adaptation, HMAC integrity engine, attestation protocol, memory watchdog, safe-mode degradation model, and CI governance gate were designed collaboratively between human and AI — a fitting origin for a framework about governing the relationship between the two.

## License

MIT — see [LICENSE](LICENSE)
