# @atp/release-guard

Reference CLI for the ATP release governance process profile.

This package is **non-normative**. ATP conformance is determined by protocol requirements and conformance contracts, not by this implementation.

## Commands

```bash
# 1) Collect release artifact evidence
npm exec -- atp-release-guard check --package-dir . --blocked-paths "src/internal/,secrets/" --out .atp/check.json

# 2) Evaluate decision gate
npm exec -- atp-release-guard decide --check-report .atp/check.json --require-approval --out .atp/decision.json

# 3) Produce publish receipt (dry-run by default)
npm exec -- atp-release-guard publish --check-report .atp/check.json --decision .atp/decision.json --approved --out .atp/publish.json
```

To execute `npm publish` after decision checks, pass `--execute` to `publish`.

## Notes

- This CLI is intended as reference process tooling for `registry.publish` governance.
- Implementations may differ if they satisfy ATP profile requirements.
