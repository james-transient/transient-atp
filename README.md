<!--
  SPDX-FileCopyrightText: Copyright 2026 Transient Intelligence Ltd
  SPDX-License-Identifier: Apache-2.0
-->

# Agent Transaction Protocol (ATP) 1.0

**The open protocol specification for autonomous agent action governance.**

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](./LICENSE)
[![Spec](https://img.shields.io/badge/spec-ATP%201.0-green.svg)](./spec/ATP_1_0_SPEC.md)
[![Conformance](https://img.shields.io/badge/conformance-machine--verified-brightgreen.svg)](./conformance-kit/)
[![npm](https://img.shields.io/npm/v/@atp-protocol/spec.svg)](https://www.npmjs.com/package/@atp-protocol/spec)

Autonomous agents can now act without a human in the loop: browse, purchase, execute code, call APIs, move money. The missing piece is not capability. It is governance: a standardised way to record what an agent was authorised to do, what decision was made, and what happened, in a form that is tamper-evident and independently verifiable.

Without that, you cannot audit an agent, hold a system accountable, or safely delegate anything that matters to an autonomous process.

## What ATP defines

Every governed agent action produces three canonical objects:

| Object | What it represents |
|--------|-------------------|
| `Intent` | The declared action the agent wants to perform, and the identity making the request |
| `Decision` | The governance outcome: `allow`, `approve`, or `deny` |
| `Receipt` | The immutable, cryptographically signed record of the action and its outcome |

Receipts are signed with Ed25519, tied to a public key published at `/.well-known/atp-keys`, and verifiable by any party with no dependency on the issuing system.

## This repository

| Path | Contents |
|------|----------|
| `spec/` | ATP 1.0 normative specification |
| `spec/test-vectors/` | Canonicalization + signature interoperability vectors |
| `conformance/` | Conformance checklist with stable requirement IDs (`ATP-L1-*`) |
| `conformance-kit/` | Reproducible conformance contracts and verification artifacts |
| `packages/spec` | [`@atp-protocol/spec`](https://www.npmjs.com/package/@atp-protocol/spec) — protocol constants, JSON schemas, Ed25519 signing, replay guard |
| `packages/conformance-cli` | `@atp/conformance-cli` — conformance runner and validator CLI |
| `packages/release-guard` | `@atp/release-guard` — non-normative reference CLI for release governance process profile |

## Application profiles

ATP is a protocol standard. Application profiles reuse the same `Intent` -> `Decision` -> `Receipt` model for specific high-impact workflows.

The release governance process profile applies ATP to governed package publishing and release actions:

- Declared publish intent
- Policy decision gate
- Signed receipt bound to release artifact evidence

ATP does not replace packaging hygiene controls. It makes high-impact release actions harder to execute silently and easier to audit.

See [`spec/ATP_1_0_RELEASE_GOVERNANCE_PROFILE.md`](./spec/ATP_1_0_RELEASE_GOVERNANCE_PROFILE.md).

## Getting started

```bash
npm install
npm run conformance:kit
```

To run the full industry-grade gate:

```bash
npm run conformance:industry
npm run conformance:industry:strict
```

## Using the packages

```bash
npm install @atp-protocol/spec
```

**Sign and verify a receipt:**

```js
import { createHash } from 'node:crypto';
import { generateSigningKeyPair, signReceipt, verifyReceiptSignature, canonicalBytes, exportPublicKeyAsJwk, buildJwks } from '@atp-protocol/spec';

const { privateKey, publicKey } = generateSigningKeyPair();

const eventSnapshot = { action: 'purchase', item: 'flowers' };
const now = new Date().toISOString();

const receipt = {
  receipt_id: 'TR-1', intent_id: 'TI-1', decision_id: 'TD-1',
  execution_status: 'executed', schemaVersion: '1.0.0',
  occurred_at: now, received_at: now, sealed_at: now, captured_at: now,
  event_snapshot: eventSnapshot,
  event_snapshot_hash: createHash('sha256').update(canonicalBytes(eventSnapshot)).digest('hex'),
  correlation_id: 'sess-1'
};

const signed = signReceipt(receipt, privateKey, 'key-2026-01');

// Serve at /.well-known/atp-keys
const jwks = buildJwks([ exportPublicKeyAsJwk(publicKey, 'key-2026-01') ]);

const { ok } = verifyReceiptSignature(signed, publicKey);
```

**Enforce replay protection:**

```js
import { ReplayGuard } from '@atp-protocol/spec';

const guard = new ReplayGuard();
const { ok, reason } = guard.check(receipt);
```

## Intended use

ATP is for teams that need to govern and audit autonomous agent behaviour across systems:

- Implement ATP in an agent runtime and produce machine-verifiable conformance evidence
- Require ATP conformance evidence in vendor or platform selection
- Build auditing, accountability, and compliance tooling on a shared open standard

## Versioning and releases

See [`docs/VERSIONING_POLICY.md`](./docs/VERSIONING_POLICY.md) and [`docs/RELEASE_POLICY.md`](./docs/RELEASE_POLICY.md).

## Acknowledgements

See [`ACKNOWLEDGEMENTS.md`](./ACKNOWLEDGEMENTS.md) for standards and prior work that informed this specification.

## Licence

Apache 2.0. See [`LICENSE`](./LICENSE) and [`NOTICE`](./NOTICE).

© 2026 Transient Intelligence Ltd. Agent Transaction Protocol (ATP) is a specification created and published by Transient Intelligence Ltd.
