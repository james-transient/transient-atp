# ATP Release Policy

## Release Gate

A release is eligible only when all required gates pass:

- `npm run conformance:kit`
- `npm run conformance:industry`
- `npm run test:spec`
- `npm run test:cli`

## Artifact Requirements

Release evidence MUST include:

- `conformance-kit/artifacts/latest-report.json`
- `conformance-kit/artifacts/latest-validation.json`
- `conformance-kit/artifacts/latest-industry-gate.json`
- `conformance-kit/artifacts/latest-digests.json`

## Change Control

- Breaking protocol changes require a MAJOR version bump and migration notes.
- Non-breaking protocol expansions require a MINOR version bump.
- Documentation-only fixes may use PATCH when semantics are unchanged.

## Public Claims Rule

Public statements MUST remain within `conformance/ATP_PUBLIC_CLAIM_BOUNDARIES.md` and reference verifiable release artifacts.
