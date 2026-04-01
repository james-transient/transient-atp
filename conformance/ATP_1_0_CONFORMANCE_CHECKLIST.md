<!--
  SPDX-FileCopyrightText: Copyright 2026 Transient Intelligence Ltd
  SPDX-License-Identifier: Apache-2.0
-->

# ATP 1.0 Conformance Checklist

The key words MUST, MUST NOT, REQUIRED, SHALL, SHOULD, SHOULD NOT, RECOMMENDED, MAY, and OPTIONAL in this document are to be interpreted as described in RFC 2119 and RFC 8174.

## Requirement Register

### Core Objects

- `ATP-L1-OBJ-001`: A conforming runtime MUST emit canonical `Intent`, `Decision`, and `Receipt` objects on every governed action.

### Receipt Identifiers

- `ATP-L1-RCV-001`: `receipt_id` MUST be present, immutable, and match pattern `TR-<numeric>`.
- `ATP-L1-RCV-002`: `intent_id` MUST be present, immutable, and match pattern `TI-<numeric>`.
- `ATP-L1-RCV-003`: `decision_id` MUST be present, immutable, and match pattern `TD-<numeric>`.
- `ATP-L1-RCV-004`: `intent.intent_id` MUST equal the top-level `intent_id`.
- `ATP-L1-RCV-005`: `decision.decision_id` MUST equal the top-level `decision_id`.
- `ATP-L1-RCV-006`: `decision.intent_id` MUST equal the top-level `intent_id`.

### Timestamps

- `ATP-L1-TS-001`: `occurred_at`, `received_at`, and `sealed_at` MUST be RFC 3339 date-time strings.
- `ATP-L1-TS-002`: `occurred_at <= received_at <= sealed_at` MUST hold.
- `ATP-L1-TS-003`: `captured_at` MUST be a valid RFC 3339 date-time string.

### Snapshot Integrity

- `ATP-L1-SNP-001`: `event_snapshot` MUST be a non-null object.
- `ATP-L1-SNP-002`: `event_snapshot_hash` MUST match the canonical SHA-256 digest of `event_snapshot`.

### Correlation

- `ATP-L1-COR-001`: `correlation_id` MUST be non-empty.

### Schema

- `ATP-L1-SCH-001`: `schemaVersion` MUST be present and MUST equal `1.0.0`.

### Signing

- `ATP-L1-SIG-001`: `signature` MUST be present and MUST NOT be empty.
- `ATP-L1-SIG-002`: Implementations SHOULD use the Ed25519 signing object form (`alg`, `kid`, `sig`, `canonicalization`).
- `ATP-L1-SIG-003`: Implementations using legacy hash form MUST use pattern `sha256:<64-hex>` and SHOULD migrate to Ed25519 object form.
- `ATP-L1-SIG-004`: The signing payload MUST be constructed using canonicalization algorithm `ATP-JCS-SORTED-UTF8` with the `signature` field removed.

### Decision Semantics

- `ATP-L1-DEC-001`: `decision.outcome` MUST be one of `allow`, `approve`, or `deny`.
- `ATP-L1-DEC-002`: `execution_status` MUST be one of `executed`, `blocked`, `expired`, or `error`.

### Scenario Coverage

- `ATP-L1-COV-001`: Conformance evidence MUST cover all three decision outcomes: `allow`, `approve`, `deny`.
- `ATP-L1-COV-002`: Conformance evidence MUST cover all four execution statuses: `executed`, `blocked`, `expired`, `error`.

### Key Distribution

- `ATP-L1-KEY-001`: Services issuing signed receipts MUST publish public keys at `/.well-known/atp-keys` as a JWKS-compatible document.
- `ATP-L1-KEY-002`: Each key entry MUST include `kty: "OKP"`, `crv: "Ed25519"`, `kid`, and `x` (base64url raw public key bytes).
- `ATP-L1-KEY-003`: Retired keys MUST remain in the JWKS for at least 30 days after last use.
- `ATP-L1-KEY-004`: The `/.well-known/atp-config` document SHOULD include a `keys_endpoint` field.

### Replay Protection

- `ATP-L1-RPL-001`: Receipt verifiers MUST maintain an observation set and reject duplicate `receipt_id` values within the window with reason code `receipt_replay_detected`.
- `ATP-L1-RPL-002`: The observation window MUST be at least 5 minutes.
- `ATP-L1-RPL-003`: Receipts with `sealed_at` outside the window SHOULD be rejected with reason code `receipt_outside_window`.

### Signature Deprecation

- `ATP-L1-DEP-001`: Validators MUST surface a deprecation warning (`receipt_deprecated_legacy_signature`) when a `sha256:` string signature is presented.
- `ATP-L1-DEP-002`: Implementations MUST NOT accept the `sha256:` string form in ATP 2.0.

### Privacy (RECOMMENDED)

- `ATP-L1-PRV-001`: Implementations SHOULD include `input_hash` and `output_hash` instead of embedding raw payloads.
- `ATP-L1-PRV-002`: Sensitive raw inputs and outputs SHOULD NOT be embedded in receipts unless policy requires retention.

### Cost Attribution (OPTIONAL)

- `ATP-L1-CST-001`: Implementations MAY include a `cost` object with `amount` and `currency` fields.
- `ATP-L1-CST-002`: `cost.amount` MUST be a decimal string if present.

### Release Governance Process Profile (Application Profile)

- `ATP-L1-RGP-001`: For governed `registry.publish` actions, implementations MUST emit ATP `Intent`, `Decision`, and `Receipt` objects.
- `ATP-L1-RGP-002`: The lifecycle stages `preflight declaration`, `policy evaluation`, `execution authorization`, and `post-execution attestation` MUST be represented in evidence.
- `ATP-L1-RGP-003`: Lifecycle stage order MUST be `preflight declaration` -> `policy evaluation` -> `execution authorization` -> `post-execution attestation`.
- `ATP-L1-RGP-004`: Where policy requires explicit approval, an `approval gate` stage MUST be represented between policy evaluation and execution authorization.
- `ATP-L1-RGP-005`: Where policy requires explicit approval, `decision.outcome` MUST be `approve` before execution is authorized.
- `ATP-L1-RGP-004`: `intent.context` MUST include `package_name`, `package_version`, `expected_tarball_sha256`, and `expected_manifest_sha256` for `registry.publish`.
- `ATP-L1-RGP-006`: `intent.context` MUST include `package_name`, `package_version`, `expected_tarball_sha256`, and `expected_manifest_sha256` for `registry.publish`.
- `ATP-L1-RGP-007`: Release profile receipts MUST satisfy ATP-L1 receipt invariants.
- `ATP-L1-RGP-008`: Digest binding MUST hold between intent and receipt evidence (`expected_tarball_sha256 == release.tarball_sha256` and `expected_manifest_sha256 == release.manifest_sha256`).
- `ATP-L1-RGP-009`: If blocked path policy is configured, published manifest paths MUST NOT include blocked paths.
- `ATP-L1-RGP-010`: Implementations MUST fail closed on deny decisions for publish actions.
- `ATP-L1-RGP-011`: Release profile receipts MUST use Ed25519 object signatures and MUST NOT use deprecated legacy `sha256:` signature strings.
- `ATP-L1-RGP-012`: Release profile signatures MUST be verifiable using a key resolved by `signature.kid` in provided key material.

## Verification Artifacts

- `conformance-kit/artifacts/latest-report.json`
- `conformance-kit/artifacts/latest-validation.json`

## Pass Condition

Conformance is PASS only when all MUST-level requirements are satisfied and all required scenario coverage is present. SHOULD-level requirements are noted in validation output as advisories.

---

© 2026 Transient Intelligence Ltd. Agent Transaction Protocol (ATP) is a specification created and published by Transient Intelligence Ltd. Licensed under the Apache License, Version 2.0.
