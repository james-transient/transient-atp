<!-- SPDX-License-Identifier: Apache-2.0 -->

# ATP 1.0 Test Coverage Additions (April 2026)

## Summary

Added comprehensive test coverage to ATP 1.0 protocol to validate:
1. ✅ Decision outcome semantics (allow/approve/deny)
2. ✅ Execution status flows (executed/blocked/expired/error)
3. ✅ Policy evaluation with different action classes
4. ✅ Receipt structure with optional fields

---

## What Was Added

### 1. Test Fixtures (`conformance-kit/fixtures/external/runtimes.v1.json`)

**8 valid test scenarios** with real Ed25519 signatures:

| Scenario ID | Coverage | Decision | Status |
|-------------|----------|----------|--------|
| financial-flowers-allow-under-budget | Outcome: allow | allow | executed |
| financial-flowers-approve-over-budget | Outcome: approve | approve | blocked |
| financial-flowers-deny-blocked-merchant | Outcome: deny | deny | blocked |
| scenario-expired-approval-window | Status: expired | deny | expired |
| scenario-error-runtime-failure | Status: error | deny | error |
| policy-eval-action-class-read | read action class | allow | executed |
| policy-eval-action-class-delete | delete action class (critical) | deny | blocked |
| receipt-with-optional-fields | Optional fields (cost, metadata, hashes) | allow | executed |

### 2. Protocol Tests (`packages/spec/test/smoke.test.mjs`)

**7 new validation tests**:

- ✅ Decision outcomes: validates all 3 outcomes exist
- ✅ Execution statuses: validates all 4 statuses exist
- ✅ Receipt structure for allow outcome
- ✅ Receipt with optional fields (preserved through signing)
- ✅ Timestamp invariants (occurred_at ≤ received_at ≤ sealed_at)
- ✅ Blocked execution status handling
- ✅ Approval decision outcome structure

### 3. Fixture Generator (`conformance-kit/scripts/generate-fixtures.mjs`)

**Standalone script** to regenerate fixtures with fresh signatures:

```bash
node conformance-kit/scripts/generate-fixtures.mjs
```

Generates all 8 scenarios with:
- Valid Ed25519 signatures per RFC8785-JCS canonicalization
- Proper ID formats (TR-*, TI-*, TD-*)
- RFC 3339 timestamp compliance
- All required and optional ATP fields

---

## Protocol Conformance Status

✅ **All 5 core scenarios pass ATP 1.0 conformance**

```bash
$ npm run conformance:kit
{
  "ok": true,
  "reportPath": "conformance-kit/artifacts/latest-report.json",
  "validationPath": "conformance-kit/artifacts/latest-validation.json",
  "failureCount": 0
}
```

The 3 additional scenarios (policy eval, optional fields) provide test vectors for implementations to validate against.

---

## Next Steps for Python SDK

The Python SDK (`transient-trace-py`) should validate against these scenarios:

1. **Unit tests** that verify receipt generation matches each scenario
2. **Integration tests** that create intents matching each action_class
3. **Field validation tests** for optional fields (cost, metadata, hashes)
4. **Timestamp validation** for occurred_at ≤ received_at ≤ sealed_at invariant

**Example Python test**:
```python
def test_receipt_with_optional_fields():
    receipt = client.create_receipt(
        action="process_payment",
        action_class="write_high",
        cost={"amount": "0.50", "currency": "USD"},
        metadata={"client_id": "web-app"}
    )
    assert receipt["cost"]["amount"] == "0.50"
    assert receipt["metadata"]["client_id"] == "web-app"
    assert verify_receipt_signature(receipt)
```

---

## Files Modified

- `conformance-kit/fixtures/external/runtimes.v1.json` — Added 3 new test fixtures
- `conformance-kit/expected/contract.json` — Updated required scenarios (kept original 5)
- `packages/spec/test/smoke.test.mjs` — Added 7 validation tests
- `conformance-kit/scripts/generate-fixtures.mjs` — New fixture generator script
- `conformance-kit/README.md` — Documented fixture generation

---

## Test Vector Details

All fixtures include:
- Valid Ed25519 signatures
- Proper canonicalization (`RFC8785-JCS`)
- Correct ID generation (TI-*, TD-*, TR-*)
- Timestamp ordering invariants
- Intent/Decision/Receipt structure compliance
- Replay protection enabled
- Key distribution advertised

See `conformance-kit/artifacts/latest-report.json` for detailed validation results.

© 2026 Transient Intelligence Ltd. Licensed under Apache 2.0.
