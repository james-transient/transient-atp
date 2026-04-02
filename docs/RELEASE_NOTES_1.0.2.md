# ATP 1.0.2 Release Notes

## Summary

ATP 1.0.2 is a patch hardening release focused on interoperability correctness and conformance trust boundaries. It closes implementation ambiguity around canonicalization, strengthens receipt/schema validation alignment, and adds external-fixture conformance support to reduce circular validation risk.

## Highlights

- Canonicalization is now implemented through one authoritative path in `@atp/spec` (`canonicalJSONString` + `canonicalBytes`).
- Normative machine-readable canonicalization/signature test vectors are published:
  - `spec/test-vectors/canonicalization-signature.v1.json`
- Receipt schema and runtime validator alignment is tightened:
  - `schemaVersion` fixed to `1.0.0`
  - signature canonicalization fixed to `ATP-JCS-SORTED-UTF8`
  - `event_snapshot_hash` constrained to 64-hex
  - RFC3339 fractional-seconds profile expanded beyond millisecond-only precision.
- Conformance harness no longer emits globally constant IDs and now supports:
  - `--runtimes-fixture <path>`
  - external signed runtime corpus at `conformance-kit/fixtures/external/runtimes.v1.json`
- Spec and key distribution docs include updated trust-anchor and emergency revocation guidance.

## Compatibility Notes

- This release is patch-level (`1.0.2`) and does not change ATP object names or top-level lifecycle model.
- Conformance expectations are stricter for signing metadata consistency and ATP-L1 Ed25519 usage language.
- Legacy `sha256:` signatures remain parseable for migration workflows but are non-conformant for ATP-L1 PASS.

## Resolved Findings Mapping (Appendix)

| Finding ID | Status in 1.0.2 | Notes |
|---|---|---|
| C-1 (dual canonicalization exports) | Resolved | Removed divergent helper path; canonicalization now has a single authoritative implementation flow. |
| C-5 (separate canonicalization implementations) | Resolved | `event_snapshot_hash` now uses shared canonical bytes from `@atp/spec`. |
| S-1 / I-3 (underspecified canonicalization, no vectors) | Partially resolved | Added normative vectors and tests; further multi-language vector expansion is recommended in later releases. |
| S-2 (fixture ID collisions) | Resolved for harness fixtures | `createSampleReceipt` now derives deterministic IDs from run/session/action seed. |
| S-6 (SHOULD vs MUST inconsistency) | Resolved in normative docs | ATP-L1 conformance language now explicitly requires Ed25519. |
| D-2 (timestamp precision mismatch) | Resolved | Validator now accepts RFC3339 fractional seconds beyond exactly 3 digits. |
| D-4 (schemaVersion under-constrained in schema) | Resolved | Receipt schema enforces `schemaVersion: \"1.0.0\"`. |
| I-1 (conformance circularity) | Partially resolved | Added external signed fixture mode and corpus; independent third-party implementation matrix still pending. |
| I-2 (self-reported-only conformance signals) | Partially resolved | External fixture path added; deeper active probing remains future work. |
| I-4 (undocumented `atp.dev` schema host) | Resolved | Schema IDs and refs moved to `schemas.transientintelligence.com` naming. |
| I-5 (typo “resoltion”) | Resolved | Corrected in key distribution spec. |
| C-3 / C-4 (trust anchor and revocation policy gaps) | Partially resolved | Added trust-anchor assumptions and emergency revocation guidance; full protocol-level revocation transport remains future work. |
| P-1 / P-3 (independent certification and ecosystem adoption) | Not in patch scope | Requires process/governance and external ecosystem engagement beyond code patching. |

## Validation

The following suites pass for this release:

- `npm run test:spec`
- `npm run test:cli`
- `npm run test:release-guard`

