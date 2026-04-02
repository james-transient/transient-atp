<!--
  SPDX-FileCopyrightText: Copyright 2026 Transient Intelligence Ltd
  SPDX-License-Identifier: Apache-2.0
-->

# Agent Transaction Protocol (ATP) 1.0 Specification

## Status

Initial release. This document defines version 1.0 of the Agent Transaction Protocol.

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY, and OPTIONAL in this document are to be interpreted as described in RFC 2119 and RFC 8174.

## Abstract

ATP is a protocol for governing and verifying autonomous agent actions against a shared standard. It defines the lifecycle of an agent action from intent through decision to receipt, with machine-verifiable conformance.

## Core Objects

- `Intent`: the declared action an agent intends to perform.
- `Decision`: the governance outcome (allow, approve, or deny) applied to the intent.
- `Receipt`: the immutable record of the action, decision, and execution outcome.

## ATP-L1 Receipt Requirements

### Identifiers

- `receipt_id` MUST be immutable and match format `TR-<numeric>`.
- `intent_id` MUST be immutable and match format `TI-<numeric>`.
- `decision_id` MUST be immutable and match format `TD-<numeric>`.
- `intent.intent_id` MUST match the top-level `intent_id`.
- `decision.decision_id` MUST match the top-level `decision_id`.
- `decision.intent_id` MUST match the top-level `intent_id`.

### Timestamps

- `occurred_at`, `received_at`, and `sealed_at` MUST be RFC 3339 date-time strings.
- `occurred_at <= received_at <= sealed_at` MUST hold.
- `captured_at` MUST be a valid RFC 3339 date-time string.

### Snapshot Integrity

- `event_snapshot` MUST be a non-null object.
- `event_snapshot_hash` MUST match the canonical SHA-256 hash of `event_snapshot`.

### Correlation

- `correlation_id` MUST be non-empty.

### Schema Version

- `schemaVersion` MUST be present and equal `1.0.0`.

## Signing

ATP 1.0 ATP-L1 conformance MUST use Ed25519 with canonical JSON serialization for receipt signing.

ATP's signing model draws on established patterns in the agent attestation space, including Ed25519 and canonical JSON serialization as used by W3C Verifiable Credentials, JSON Web Signatures (RFC 7515), and similar protocols. The baseline canonicalization scheme MUST be `RFC8785-JCS`. Implementations parsing historical versions of ATP (pre-1.1.0) MAY support the deprecated `ATP-JCS-SORTED-UTF8` scheme, but MUST NOT issue new signatures using it.

### Canonicalization
 
 Canonicalization algorithm identifier: `RFC8785-JCS`.
 
 The signing payload MUST be constructed as follows:
 
 1. Clone the full receipt object.
 2. Remove the `signature` field from the clone.
 3. Serialize the resulting object according to [RFC 8785 (JSON Canonicalization Scheme - JCS)](https://www.rfc-editor.org/rfc/rfc8785.html).
 4. Encode as UTF-8 bytes.

Normative canonicalization and signature test vectors are published in:

- `spec/test-vectors/canonicalization-signature.v2.json`

### Signature Object

When Ed25519 signing is used, `signature` MUST be an object with:

- `alg` (string, REQUIRED): MUST be `Ed25519`.
- `kid` (string, REQUIRED): key identifier for the signing key.
- `sig` (string, REQUIRED): base64url-encoded Ed25519 signature over canonical payload bytes.
- `canonicalization` (string, REQUIRED): MUST be `RFC8785-JCS`.
- `version` (string, OPTIONAL): signing version identifier.

Implementations MAY parse legacy hash-only signatures in format `sha256:<64-hex>` to support migration workflows, but this form is not sufficient for ATP-L1 conformance. The `sha256:` string form is deprecated as of ATP 1.0 and MUST NOT be accepted in ATP 2.0. Validators MUST surface a deprecation warning when this form is presented.

### Verification

1. Parse and validate required receipt fields.
2. Confirm `signature.alg == "Ed25519"`.
3. Resolve public key by `signature.kid`.
4. Rebuild canonical payload bytes with `signature` removed.
5. Verify Ed25519 signature over canonical payload bytes.

## Decision Outcome Semantics

The `allow`/`approve`/`deny` model is informed by inline Policy Enforcement Point (PEP) patterns used in agent sandbox runtimes. ATP formalises these decisions as protocol-level artifacts that can be independently verified after the fact. See `ACKNOWLEDGEMENTS.md`.

- `allow`: action proceeds without approval gate.
- `approve`: action requires explicit approval before proceeding.
- `deny`: action is prevented by policy or governance control.

## Execution Status Semantics

- `executed`: action completed successfully.
- `blocked`: action was halted by a governance control.
- `expired`: action approval window elapsed before resolution.
- `error`: action encountered a runtime failure.

## Privacy

Implementations SHOULD use `input_hash` and `output_hash` fields (SHA-256 digest of canonicalized payload) instead of embedding raw sensitive payloads in the receipt. Raw payloads SHOULD NOT be included unless policy explicitly requires retention.

## Metadata Extensions
 
 The root ATP receipt, as well as the `intent` and `decision` sub-objects, MAY include a `metadata` dictionary to contain vendor-specific, runtime-specific, or domain-specific data (for example: internal trace IDs, deployment environments, debugging flags, LLM token counts, or arbitrary developer graffiti keys).
 
 - `metadata` (object, OPTIONAL): MUST only contain values that are predictably serialized by the cryptographic canonicalization scheme.
 - Verifiers MUST NOT reject receipts solely due to the presence of unrecognized key-value pairs within the `metadata` namespaces.
 - Because `metadata` is included in the ATP Canonicalization payload, mutating these fields *after* signing will invalidate the signature.
 
 ## Cost and Attribution
 
 Implementations MAY include a `cost` object with:
 
 - `amount` (string, REQUIRED): decimal string representation.
 - `currency` (string, REQUIRED): ISO 4217 code or protocol-specific token symbol (e.g. `USD`, `FLW`).
 - `unit` (string, OPTIONAL): e.g. `request`, `token`, `execution`.
 - `payer` (string, OPTIONAL): actor attributed the cost of the action.

## Transport

### HTTP Header

- Header name: `X-ATP-Receipt`
- Value: base64url-encoded UTF-8 JSON receipt object.

### HTTP Response Body

- Field name: `receipt`
- Value: raw JSON receipt object.

When both are present, they MUST be semantically equivalent. A mismatch MUST be treated as an error.

## Discovery

Services advertising ATP support SHOULD expose `/.well-known/atp-config` with a capability document:

```json
{
  "atp": {
    "version": "1.0",
    "signing": ["Ed25519"],
    "canonicalization": "RFC8785-JCS",
    "transport": ["X-ATP-Receipt", "body.receipt"],
    "keys_endpoint": "/.well-known/atp-keys"
  }
}
```

## Security Considerations

- **Key rotation:** `kid` MUST support key rotation. Verifiers SHOULD retain historical keys for signature validity windows.
- **Replay protection:** consumers MUST enforce uniqueness of `receipt_id` within a bounded observation window of at least 5 minutes. See `ATP_1_0_TRANSPORT.md § Replay Protection`.
- **Privacy:** raw inputs and outputs SHOULD NOT be embedded in receipts. Use `input_hash`/`output_hash`.
- **Canonicalization safety:** signing and verifying implementations MUST use identical canonicalisation. Divergence invalidates signatures.
- **Issuer trust context:** verifiers MUST know the issuing origin before resolving `signature.kid` and MUST treat the issuer origin and JWKS endpoint as part of the trust boundary.

## Conformance

Conformance for ATP 1.0 is evaluated through:

- `conformance/ATP_1_0_CONFORMANCE_CHECKLIST.md`
- `conformance-kit/expected/contract.json`

## Application Profiles

ATP 1.0 MAY be applied to domain-specific or workflow-specific governance contexts while preserving the same canonical object lifecycle and invariants.

The release governance profile is defined in:

- `spec/ATP_1_0_RELEASE_GOVERNANCE_PROFILE.md`

---

© 2026 Transient Intelligence Ltd. Agent Transaction Protocol (ATP) is a specification created and published by Transient Intelligence Ltd. Licensed under the Apache License, Version 2.0.
