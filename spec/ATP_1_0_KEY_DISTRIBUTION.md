# ATP 1.0 Key Distribution

## Status

Normative. Part of ATP 1.0.

The key words MUST, MUST NOT, REQUIRED, SHALL, SHOULD, SHOULD NOT, RECOMMENDED, MAY, and OPTIONAL in this document are to be interpreted as described in RFC 2119 and RFC 8174.

## Scope

This document defines how signing key material is published, discovered, and resolved by ATP receipt verifiers.

## Key Identifier

Every Ed25519 signing key MUST be assigned a stable, unique key identifier (`kid`). The `kid` value:

- MUST be a non-empty string.
- SHOULD be a short opaque token (e.g. `atp-prod-2026-03`).
- MUST NOT change for the lifetime of a key.
- MUST NOT be reused after a key is retired.

## JWKS Endpoint

Services that issue signed ATP receipts MUST publish their public signing keys as a JSON Web Key Set (JWKS) compatible document at:

```
GET /.well-known/atp-keys
```

### Response format

```json
{
  "keys": [
    {
      "kty": "OKP",
      "crv": "Ed25519",
      "kid": "atp-prod-2026-03",
      "use": "sig",
      "x": "<base64url public key bytes>"
    }
  ]
}
```

- `kty` MUST be `OKP`.
- `crv` MUST be `Ed25519`.
- `kid` MUST match the `kid` used in issued receipt signatures.
- `use` SHOULD be `sig`.
- `x` MUST be the base64url-encoded raw 32-byte Ed25519 public key.
- `revoked_at` (string, OPTIONAL): RFC 3339 date-time string indicating when this key was compromised or retired. Verifiers MUST reject any receipt signed with this key if its `sealed_at` timestamp is greater than or equal to `revoked_at`.
- The endpoint MUST return HTTP 200 with `Content-Type: application/json`.
- The response MUST include all currently active keys.
- The response SHOULD include recently retired keys for a minimum rotation window of 30 days.

### Key resolution by verifiers

When verifying a receipt, a verifier MUST:

1. Extract `signature.kid` from the receipt.
2. Fetch `/.well-known/atp-keys` from the issuing service.
3. Locate the key entry matching `kid`.
4. If no matching key is found in the current or active rotation window, a verifier MAY assume it was removed and MUST reject the receipt (`receipt_key_not_found`).
5. If the matching key contains a `revoked_at` property:
   - Parse `received_at` or `sealed_at` from the receipt.
   - If the receipt timestamp is strictly later than the `revoked_at` timestamp, the verifier MUST reject the receipt with reason `receipt_key_revoked`.
6. Reconstruct the Ed25519 public key from `x`.
7. Verify the receipt signature per `ATP_1_0_SPEC.md § Signing`.

Verifiers SHOULD cache the JWKS response. Cache lifetime SHOULD NOT exceed 1 hour. Verifiers MUST re-fetch if a `kid` is not found in the cached set before failing permanently.

## Trust Anchor Requirements

Key distribution trust is anchored in the issuer origin. Verifiers MUST:

1. Resolve `/.well-known/atp-keys` over HTTPS from the known issuer origin.
2. Validate the TLS certificate chain using platform trust stores.
3. Treat a TLS validation failure as a hard verification failure.

Implementations MAY add stronger controls (for example certificate pinning, signed JWKS envelopes, or DNSSEC-backed origin validation). Where such controls are used, they SHOULD be documented in conformance declarations.

## Key Rotation

Key rotation MUST follow this procedure:

1. Generate a new key pair with a new `kid`.
2. Add the new public key to `/.well-known/atp-keys` **before** signing any receipts with the new key.
3. Begin issuing receipts with the new `kid`.
4. Retain the old public key in `/.well-known/atp-keys` for at least 30 days after the last receipt was signed with it.
5. Remove the old key after the retention window.

Clients MUST NOT assume a specific `kid` value is stable across deployments.

## Emergency Key Revocation

If signing key compromise is suspected, issuers MUST:

1. Immediately stop signing with the compromised `kid`.
2. Publish a replacement key with a new `kid`.
3. Mark the compromised key as revoked in `/.well-known/atp-keys` by appending a `revoked_at` RFC 3339 timestamp.
4. Keep the compromised and revoked key in the published endpoint for at least 30 days, or indefinitely.
5. Reject new receipt issuance requests with compromised keys from the revocation timestamp onward.

ATP 1.0 does not define a universal CRL/OCSP-equivalent transport. Implementations SHOULD document revocation signaling channels and retention policy for compromised keys.

## Integration with Discovery

The `/.well-known/atp-config` capability document (defined in `ATP_1_0_TRANSPORT.md`) SHOULD include a `keys_endpoint` field pointing to the JWKS URI:

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

If `keys_endpoint` is absent from the discovery document, verifiers MUST fall back to `/.well-known/atp-keys` on the same origin.

## Out-of-band Key Distribution

Where HTTPS-based discovery is not available, key material MAY be distributed out-of-band (e.g. pre-shared in a configuration file or deployment manifest). In this case:

- The distribution mechanism MUST be documented by the implementer.
- Keys MUST be rotated on the same schedule.
- Implementations relying solely on out-of-band distribution SHOULD note this in their conformance declaration.
