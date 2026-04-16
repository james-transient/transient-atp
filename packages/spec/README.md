# @atp-protocol/spec

Protocol constants, JSON schemas, Ed25519 signing, and replay protection for the **Agent Transaction Protocol (ATP) 1.0** — the open specification for autonomous agent action governance.

## Install

```bash
npm install @atp-protocol/spec
```

## Usage

### Protocol constants

```js
import { ATP_PROTOCOL, ATP_VERSION, ATP_DECISION_OUTCOMES, ATP_EXECUTION_STATUSES } from '@atp-protocol/spec';

console.log(ATP_PROTOCOL);          // "ATP"
console.log(ATP_VERSION);           // "1.0"
console.log(ATP_DECISION_OUTCOMES); // ["allow", "approve", "deny"]
console.log(ATP_EXECUTION_STATUSES);// ["executed", "blocked", "expired", "error"]
```

### Sign and verify a receipt

```js
import { generateSigningKeyPair, signReceipt, verifyReceiptSignature } from '@atp-protocol/spec';

const { publicKey, privateKey } = generateSigningKeyPair();

const receipt = {
  receipt_id: 'TR-123',
  intent_id: 'TI-456',
  decision_id: 'TD-789',
  execution_status: 'executed',
  schemaVersion: '1.0.0',
  occurred_at: new Date().toISOString(),
  received_at: new Date().toISOString(),
  sealed_at: new Date().toISOString(),
  captured_at: new Date().toISOString(),
  event_snapshot: { action: 'purchase' },
  event_snapshot_hash: '...',
  correlation_id: 'sess-1'
};

const signed = signReceipt(receipt, privateKey, 'my-key-id');
const result = verifyReceiptSignature(signed, publicKey);
// result.ok === true
```

### Replay protection

```js
import { ReplayGuard } from '@atp-protocol/spec';

const guard = new ReplayGuard({ windowMs: 300_000, skewMs: 5_000 });
const result = guard.check(signedReceipt);
// result.ok === true (first presentation)
// result.ok === false, result.reason === 'receipt_replay_detected' (duplicate)
```

### JSON schemas

```js
import { getSchemaPath } from '@atp-protocol/spec';

const intentSchema = getSchemaPath('intent');   // absolute path to intent.schema.json
const decisionSchema = getSchemaPath('decision');
const receiptSchema = getSchemaPath('receipt');
```

Or import directly:

```js
import intentSchema from '@atp-protocol/spec/schemas/intent';
import decisionSchema from '@atp-protocol/spec/schemas/decision';
import receiptSchema from '@atp-protocol/spec/schemas/receipt';
```

## Exports

| Export | Description |
|--------|-------------|
| `ATP_PROTOCOL` | Protocol identifier — `"ATP"` |
| `ATP_VERSION` | Protocol version — `"1.0"` |
| `ATP_DECISION_OUTCOMES` | `["allow", "approve", "deny"]` |
| `ATP_EXECUTION_STATUSES` | `["executed", "blocked", "expired", "error"]` |
| `ATP_SIGNING_ALGORITHM` | `"Ed25519"` |
| `generateSigningKeyPair()` | Generate an Ed25519 key pair (PEM) |
| `signReceipt(receipt, privateKey, kid)` | Sign a receipt with Ed25519 + RFC8785-JCS |
| `verifyReceiptSignature(receipt, publicKey)` | Verify a signed receipt |
| `receiptFingerprint(receipt)` | SHA-256 fingerprint of a receipt |
| `canonicalJSONString(obj)` | RFC8785-JCS canonical JSON string |
| `canonicalBytes(obj)` | RFC8785-JCS canonical bytes (for hashing) |
| `exportPublicKeyAsJwk(publicKey, kid)` | Export public key as JWK |
| `buildJwks(keys)` | Build a JWKS document |
| `ReplayGuard` | Sliding-window replay protection |
| `getSchemaPath(name)` | Resolve path to a bundled JSON schema |

## License

Apache-2.0
