# ATP 1.0 Industry-Grade Checklist

This checklist extends ATP-L1 conformance with stronger release controls.

## Additional Gate Requirements

- `ATP-IND-001`: Base conformance kit MUST pass.
- `ATP-IND-002`: Negative ATP invariant tests MUST detect malformed receipts with expected reason codes.
- `ATP-IND-003`: Interop matrix MUST define at least three runtime targets and MUST satisfy configured implemented-target minimum.
- `ATP-IND-004`: Conformance artifacts MUST include SHA-256 digest outputs.
- `ATP-IND-005`: Independent verifier requirement MUST be enforced by contract when enabled.
- `ATP-IND-006`: CI MUST run conformance gates on pushes and pull requests.

## Execution

Run from repository root:

```bash
npm run conformance:industry
```

## Outputs

- `conformance-kit/artifacts/latest-industry-gate.json`
- `conformance-kit/artifacts/latest-digests.json`
