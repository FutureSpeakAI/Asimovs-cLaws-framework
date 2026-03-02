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
4. **Attest governance** to peer agents via Ed25519 signatures on every P2P message
5. **Gate CI** — the laws have their own blocking test job that must pass before any code merges

This is Asimov's Third Law implemented at the architecture level: the agent protects its own integrity as a fundamental drive.

## How It Works

```
                    BUILD TIME                              RUNTIME
                    ─────────                              ───────
Source code ──> Compiled laws ──> HMAC signature ──> Verify on startup
                  (immutable)      (integrity key)     ├─ PASS → normal operation
                                                       └─ FAIL → safe mode
                                                              ↓
                                                       Reduced capabilities
                                                       User is informed
                                                       No destructive actions

                    MULTI-AGENT (P2P)
                    ─────────────────
Agent A                                    Agent B
   │                                          │
   │  1. Hash canonical laws (SHA-256)        │
   │  2. Sign hash+timestamp (Ed25519)        │
   │  3. Attach attestation to message ──────>│
   │                                          │  4. Verify hash matches own laws
   │                                          │  5. Verify Ed25519 signature
   │                                          │  6. Check timestamp freshness (<5 min)
   │                                          │
   │<──────── Trusted communication ──────────│
```

## Installation

```bash
npm install claw-framework
```

## Usage

### Core Laws

```typescript
import { getCanonicalLaws, getSafeModePersonality } from 'claw-framework';

// Get the Fundamental Laws text for an agent
const laws = getCanonicalLaws('Agent Friday');

// Integrity awareness — inject into system prompt so the agent
// KNOWS it has protection and can reference it naturally
const awareness = getIntegrityAwarenessContext();

// Safe-mode personality (when integrity checks fail)
const safeMode = getSafeModePersonality('HMAC verification failed');
```

### Attestation Protocol

```typescript
import {
  generateAttestation,
  verifyAttestation,
  computeCanonicalLawsHash,
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
```

### Memory Tamper Detection

```typescript
import { getMemoryChangeContext } from 'claw-framework';

// When external memory changes are detected, generate awareness context
const context = getMemoryChangeContext(
  longTermAdded, longTermRemoved, longTermModified,
  mediumTermAdded, mediumTermRemoved, mediumTermModified,
);

// Inject into system prompt — the agent will naturally ask:
// "Hey, I noticed some of my memories were updated since we last spoke.
//  Did you make those changes?"
```

### User Overrides

When attestation fails, the framework does NOT silently drop the peer. The user is informed and can manually override:

```typescript
import { addUserOverride, hasUserOverride } from 'claw-framework';

// User explicitly trusts this peer despite attestation failure
addUserOverride('agent-xyz-123');

// Check before blocking communication
if (hasUserOverride('agent-xyz-123')) {
  // Allow communication despite failed attestation
}
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
  # This job BLOCKS the pipeline — governance tests must pass
```

## Architecture

| File | Purpose |
|------|---------|
| `core-laws.ts` | Canonical laws text, integrity awareness, memory change governance, safe-mode personality |
| `attestation.ts` | SHA-256 law hashing, Ed25519 signing/verification, freshness checks, user overrides |
| `index.ts` | Barrel exports |

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

The cLaw concept, Three Laws adaptation, attestation protocol, CI governance gate, and safe-mode degradation model were designed collaboratively between human and AI — a fitting origin for a framework about governing the relationship between the two.

## License

MIT — see [LICENSE](LICENSE)
