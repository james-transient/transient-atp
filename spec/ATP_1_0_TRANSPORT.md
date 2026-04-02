# ATP 1.0 Transport Binding

## Status

Normative. Part of ATP 1.0.

The key words MUST, MUST NOT, REQUIRED, SHALL, SHOULD, SHOULD NOT, RECOMMENDED, MAY, and OPTIONAL in this document are to be interpreted as described in RFC 2119 and RFC 8174.

## Scope

This document defines how ATP receipts are conveyed over HTTP and how ATP-capable services advertise their capabilities.

## HTTP Header Binding

ATP receipts MAY be conveyed in an HTTP response header:

```
X-ATP-Receipt: <base64url(UTF-8 JSON receipt)>
```

- The header value MUST be a base64url-encoded UTF-8 JSON-serialized receipt object.
- The receipt MUST conform to ATP-L1 requirements as defined in `ATP_1_0_SPEC.md`.
- A server MUST NOT include this header unless the receipt fully conforms.

## HTTP Body Binding

ATP receipts MAY be included as a `receipt` field in any JSON response body:

```json
{
  "result": "...",
  "receipt": { ... }
}
```

- The `receipt` field value MUST be a valid ATP receipt object (not a string).

## Consistency

When both `X-ATP-Receipt` header and `receipt` body field are present in the same response, they MUST be semantically equivalent. A receiving agent MUST treat any discrepancy between the two as an integrity error.

## Client Behaviour

Clients consuming ATP responses SHOULD:

1. Prefer the `receipt` body field when both forms are present.
2. Validate the receipt against ATP-L1 requirements before acting on it.
3. Record the `receipt_id` for replay protection.

## Discovery

Services that support ATP SHOULD expose a capability document at:

```
GET /.well-known/atp-config
```

Response:

```json
{
  "atp": {
    "version": "1.0",
    "signing": ["Ed25519"],
    "canonicalization": "ATP-JCS-SORTED-UTF8",
    "transport": ["X-ATP-Receipt", "body.receipt"],
    "keys_endpoint": "/.well-known/atp-keys"
  }
}
```

- `signing`: supported signing algorithms in preference order.
- `transport`: supported delivery mechanisms in preference order.
- `canonicalization`: canonicalization algorithm used for signing.
- `keys_endpoint`: URI of the JWKS public key document (see `ATP_1_0_KEY_DISTRIBUTION.md`). If absent, verifiers MUST fall back to `/.well-known/atp-keys` on the same origin.

If a service does not expose `/.well-known/atp-config`, clients MUST NOT assume ATP support.

## Replay Protection

Receipt consumers MUST enforce uniqueness of `receipt_id` within a bounded observation window.

### Requirements

- A verifier MUST maintain a set of observed `receipt_id` values.
- If a `receipt_id` is presented more than once within the observation window, the verifier MUST reject the duplicate with reason `receipt_replay_detected`.
- The observation window MUST be at least as long as the maximum expected transit delay for receipts (RECOMMENDED: 5 minutes).
- A receipt whose `sealed_at` timestamp falls outside the observation window MAY be rejected with reason `receipt_outside_window`.
- A receipt with a missing or non-parseable `sealed_at` MUST be rejected (`receipt_invalid_datetime_format`) before replay window checks are applied.
- Verifiers MAY use any storage mechanism for the seen-ID set (in-memory, Redis, database), provided the chosen mechanism is consistent across all replicas that accept receipts.

### Observation Window

The observation window is the time range `[now - window_duration, now + clock_skew_tolerance]`:

- `window_duration`: RECOMMENDED minimum 5 minutes.
- `clock_skew_tolerance`: RECOMMENDED maximum 30 seconds.

Receipts with `sealed_at` earlier than `now - window_duration` SHOULD be rejected unless the implementation explicitly supports delayed-delivery scenarios.

### Reason Codes

| Reason code | Meaning |
|---|---|
| `receipt_replay_detected` | `receipt_id` was already observed within the window. |
| `receipt_outside_window` | `sealed_at` is outside the permitted observation window. |
