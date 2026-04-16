# ATP 1.0 Conformance Kit

## Purpose

This kit provides a reproducible, local-first method to validate ATP 1.0 conformance claims against a machine-readable contract.

## Scope

- Runs a deterministic conformance proof harness.
- Verifies ATP-L1 receipt invariants.
- Verifies scenario coverage for decision outcomes and execution statuses.
- Produces versionable JSON artifacts for audit and review.

## Prerequisites

- Node.js 20+
- `npm install` run from repository root

## Run

From repository root:

```bash
npm run conformance:kit
npm run conformance:release
```

For the stricter industry-grade gate:

```bash
npm run conformance:industry
npm run conformance:industry:strict   # higher-assurance profile — see note below
```

> **Note on `conformance:industry:strict`:** This profile requires external setup before it will pass — specifically, at least two implemented interop targets in `conformance-kit/expected/interop-matrix.json` and an independent verifier command configured via the `ATP_INDEPENDENT_VERIFIER_CMD` environment variable. It is intended for release hardening and external trust posture, not local development. Running it without that setup will fail on `INTEROP-MATRIX` and `INDEPENDENT-VERIFIER-HOOK` by design.

Run through the CLI package:

```bash
npm exec -- atp-conformance kit
npm exec -- atp-conformance industry
npm exec -- atp-conformance run --runtimes-fixture conformance-kit/fixtures/external/runtimes.v1.json
```

## Outputs

- `conformance-kit/artifacts/latest-report.json`
- `conformance-kit/artifacts/latest-validation.json`
- `conformance-kit/artifacts/latest-industry-gate.json`
- `conformance-kit/artifacts/latest-digests.json`
- `conformance-kit/artifacts/latest-release-governance.json`

## Pass Criteria

Validation is PASS only when:

- Overall result is `PASS`.
- Required scenario matrix is complete.
- Required runtime entries are present and match contract assertions.

## Qualification Note

This kit provides reproducible ATP 1.0 conformance evidence from published tests and contracts. Claims of independent third-party verification MUST be backed by externally published attestation artifacts.

## Contract

The expected conformance contract is defined in:

- `conformance-kit/expected/contract.json`
- `conformance-kit/expected/industry-gate.json`
- `conformance-kit/expected/industry-gate.strict.json`
- `conformance-kit/expected/release-governance.contract.json`

External signed fixture corpus for interoperability checks:

- `conformance-kit/fixtures/external/runtimes.v1.json`

## Fixture Generation

To regenerate test fixtures with fresh Ed25519 signatures, run:

```bash
node conformance-kit/scripts/generate-fixtures.mjs
```

This generates 8 comprehensive test scenarios covering:
- Decision outcomes: allow, approve, deny
- Execution statuses: executed, blocked, expired, error
- Policy evaluation: different action classes (read, delete)
- Optional fields: input_hash, output_hash, cost, metadata

All signatures are valid Ed25519 with RFC8785-JCS canonicalization.

Validate an existing report against the contract:

```bash
npm exec -- atp-conformance validate --contract conformance-kit/expected/contract.json --report conformance-kit/artifacts/latest-report.json
npm exec -- atp-conformance release-validate --contract conformance-kit/expected/release-governance.contract.json --report conformance-kit/artifacts/latest-release-governance.json
```

`industry-gate.json` controls stricter gate behavior, including:

- minimum defined interop targets
- minimum implemented interop targets
- whether independent verifier configuration is required

`industry-gate.strict.json` is a higher-assurance profile intended for release hardening and external trust posture.

---

© 2026 Transient Intelligence Ltd. Agent Transaction Protocol (ATP) is a specification created and published by Transient Intelligence Ltd. Licensed under the Apache License, Version 2.0.
