<!--
  SPDX-FileCopyrightText: Copyright 2026 Transient Intelligence Ltd
  SPDX-License-Identifier: Apache-2.0
-->

# ATP 1.0 Release Governance Process Profile

## Status

This document defines a non-domain-specific ATP 1.0 application profile for release and package publication governance.

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY, and OPTIONAL in this document are to be interpreted as described in RFC 2119 and RFC 8174.

## Purpose

This profile applies the ATP `Intent` -> `Decision` -> `Receipt` lifecycle to high-impact outbound release actions such as package publication.

The objective is process governance and attestable evidence, not prevention guarantees.

## Profile Scope

This profile applies when an implementation governs actions equivalent to `registry.publish`.

It does not replace package manager configuration hygiene (`files`, `.npmignore`, or equivalent). It adds a fail-closed decision process and verifiable evidence for what was approved and executed.

## Lifecycle Requirements

For each governed publish transaction, implementations MUST represent the following lifecycle stages:

1. **Preflight Declaration**
2. **Policy Evaluation**
3. **Approval Gate** (when policy requires explicit approval)
4. **Execution Authorization**
5. **Post-Execution Attestation**

The `Intent` object MUST be declared before policy evaluation.

Lifecycle order MUST be:

- `preflight declaration` -> `policy evaluation` -> `execution authorization` -> `post-execution attestation`

Execution MUST NOT proceed if policy evaluation returns a deny decision.

Where policy requires approval, execution MUST NOT proceed until approval is resolved with an `approve` outcome.

Where policy requires approval, an `approval gate` stage MUST be present between policy evaluation and execution authorization.

## Intent Requirements (Release Profile)

For `registry.publish` intents, `intent.context` MUST include:

- `package_name`
- `package_version`
- `expected_tarball_sha256`
- `expected_manifest_sha256`

`intent.context` SHOULD include:

- `commit_sha`
- `tag`
- `publish_target` (for example, npm registry URL or logical target)

## Decision Requirements (Release Profile)

The decision MUST express one of ATP outcomes:

- `allow`: execution is authorized without approval pause.
- `approve`: execution requires explicit approval.
- `deny`: execution is blocked.

The decision rationale MUST identify policy basis in machine-readable form (for example `reason_code` and policy metadata in context).

## Receipt Requirements (Release Profile)

The receipt MUST satisfy ATP-L1 receipt invariants.

For release profile receipts, `event_snapshot` MUST include:

- `release.tarball_sha256`
- `release.manifest_sha256`
- `release.manifest_paths` (array of published paths)
- `release.publish_attempted` (boolean)

Digest binding MUST hold:

- `intent.context.expected_tarball_sha256` MUST equal `event_snapshot.release.tarball_sha256`
- `intent.context.expected_manifest_sha256` MUST equal `event_snapshot.release.manifest_sha256`

If a blocked path policy is configured, `event_snapshot.release.manifest_paths` MUST NOT contain blocked paths.

Release profile receipts MUST use Ed25519 object signatures (`signature.alg == "Ed25519"`). Deprecated legacy `sha256:` string signatures MUST NOT be used for this profile.

Release profile signatures MUST be verifiable using key material that resolves `signature.kid` (for example, profile-scoped JWKS or equivalent key distribution mechanism).

## Conformance Notes

Conformance to this profile is additive to ATP-L1. A release profile implementation is conforming only when:

- ATP-L1 receipt validation is successful
- lifecycle stage requirements are satisfied
- decision gate semantics are enforced
- digest binding requirements are satisfied

## Non-Normative Implementation Note

Reference tooling MAY provide helper commands such as `check`, `decide`, and `publish`, but tooling behavior is non-normative unless it is explicitly required by conformance contracts.

---

© 2026 Transient Intelligence Ltd. Agent Transaction Protocol (ATP) is a specification created and published by Transient Intelligence Ltd. Licensed under the Apache License, Version 2.0.
