<!--
  SPDX-FileCopyrightText: Copyright 2026 Transient Intelligence Ltd
  SPDX-License-Identifier: Apache-2.0
-->

# Agent Transaction Protocol (ATP) 1.0

**The open protocol specification for autonomous agent action governance.**

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](./LICENSE)
[![Spec](https://img.shields.io/badge/spec-ATP%201.0-green.svg)](./spec/ATP_1_0_SPEC.md)
[![Conformance](https://img.shields.io/badge/conformance-machine--verified-brightgreen.svg)](./conformance-kit/)

*Created and maintained by [Transient Intelligence Ltd](https://transientintelligence.com)*

## The problem

Autonomous agents can now act without a human in the loop: browse, purchase, execute code, call APIs, move money. The missing piece is not capability. It is governance: a standardised way to record what an agent was authorised to do, what decision was made, and what happened — in a form that is tamper-evident and independently verifiable.

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
| `conformance/` | Conformance checklist with stable requirement IDs (`ATP-L1-*`) |
| `conformance-kit/` | Reproducible conformance contracts and verification artifacts |
| `packages/spec` | `@atp/spec` — protocol constants, JSON schemas, Ed25519 signing, replay guard |
| `packages/conformance-cli` | `@atp/conformance-cli` — conformance runner and validator CLI |

## Getting started

```bash
npm install
npm run conformance:kit
```

To run the full industry-grade gate:

```bash
npm run conformance:industry
npm run conformance:industry:strict   # higher-assurance profile
```

## Using the packages

**Sign and verify a receipt:**

```js
import { generateSigningKeyPair, signReceipt, verifyReceiptSignature, exportPublicKeyAsJwk, buildJwks } from '@atp/spec';

const { privateKey, publicKey } = generateSigningKeyPair();
const signed = signReceipt(receipt, privateKey, 'key-2026-01');

// Serve at /.well-known/atp-keys
const jwks = buildJwks([ exportPublicKeyAsJwk(publicKey, 'key-2026-01') ]);

const { ok } = verifyReceiptSignature(signed, publicKey);
```

**Enforce replay protection:**

```js
import { ReplayGuard } from '@atp/spec';

const guard = new ReplayGuard(); // 5 minute window, 30 second clock skew tolerance
const { ok, reason } = guard.check(receipt);
```

**Run the conformance CLI:**

```bash
npm exec -- atp-conformance kit
npm exec -- atp-conformance industry
npm exec -- atp-conformance run --openclaw-frames conformance-kit/fixtures/openclaw/gateway-frames-live.json
```

## Intended use

ATP is designed for teams that need to govern and audit autonomous agent behaviour across systems:

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
