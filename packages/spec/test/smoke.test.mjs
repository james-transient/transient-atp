import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { resolve } from "node:path";
import {
  ATP_PROTOCOL,
  ATP_VERSION,
  ATP_DECISION_OUTCOMES,
  ATP_EXECUTION_STATUSES,
  getSchemaPath,
  generateSigningKeyPair,
  signReceipt,
  verifyReceiptSignature,
  receiptFingerprint,
  canonicalJSONString,
  canonicalBytes,
  exportPublicKeyAsJwk,
  ATP_SIGNING_ALGORITHM,
  ReplayGuard
} from "../src/index.mjs";

test("spec exports protocol constants", () => {
  assert.equal(ATP_PROTOCOL, "ATP");
  assert.equal(ATP_VERSION, "1.0");
  assert.deepEqual(ATP_DECISION_OUTCOMES, ["allow", "approve", "deny"]);
  assert.deepEqual(ATP_EXECUTION_STATUSES, ["executed", "blocked", "expired", "error"]);
});

test("signing: generateSigningKeyPair returns PEM strings", () => {
  const { publicKey, privateKey } = generateSigningKeyPair();
  assert.match(publicKey, /BEGIN PUBLIC KEY/);
  assert.match(privateKey, /BEGIN PRIVATE KEY/);
  assert.equal(ATP_SIGNING_ALGORITHM, "Ed25519");
});

test("signing: sign and verify round-trip", () => {
  const { publicKey, privateKey } = generateSigningKeyPair();
  const receipt = { receipt_id: "TR-1", intent_id: "TI-1", decision_id: "TD-1" };
  const signed = signReceipt(receipt, privateKey, "test-key");
  assert.equal(typeof signed.signature, "object");
  assert.equal(signed.signature.alg, "Ed25519");
  const result = verifyReceiptSignature(signed, publicKey);
  assert.equal(result.ok, true);
});

test("signing: verification fails after tampering", () => {
  const { publicKey, privateKey } = generateSigningKeyPair();
  const receipt = { receipt_id: "TR-1", intent_id: "TI-1", decision_id: "TD-1" };
  const signed = signReceipt(receipt, privateKey, "test-key");
  signed.decision_id = "TD-9999";
  const result = verifyReceiptSignature(signed, publicKey);
  assert.equal(result.ok, false);
});

test("signing: verification fails when canonicalization metadata is invalid", () => {
  const { publicKey, privateKey } = generateSigningKeyPair();
  const receipt = { receipt_id: "TR-1", intent_id: "TI-1", decision_id: "TD-1" };
  const signed = signReceipt(receipt, privateKey, "test-key");
  signed.signature.canonicalization = "NOT-ATP";
  const result = verifyReceiptSignature(signed, publicKey);
  assert.equal(result.ok, false);
  assert.match(String(result.detail ?? ""), /canonicalization/i);
});

test("signing: verification fails when expected kid does not match", () => {
  const { publicKey, privateKey } = generateSigningKeyPair();
  const receipt = { receipt_id: "TR-1", intent_id: "TI-1", decision_id: "TD-1" };
  const signed = signReceipt(receipt, privateKey, "kid-original");
  const result = verifyReceiptSignature(signed, publicKey, { expectedKid: "kid-other" });
  assert.equal(result.ok, false);
  assert.match(String(result.detail ?? ""), /kid mismatch/i);
});

test("signing: verification fails on invalid base64url encoding", () => {
  const { publicKey, privateKey } = generateSigningKeyPair();
  const receipt = { receipt_id: "TR-1", intent_id: "TI-1", decision_id: "TD-1" };
  const signed = signReceipt(receipt, privateKey, "kid-base64");
  signed.signature.sig = `${signed.signature.sig}+`;
  const result = verifyReceiptSignature(signed, publicKey);
  assert.equal(result.ok, false);
  assert.match(String(result.detail ?? ""), /base64url/i);
});

test("signing: verification fails on invalid Ed25519 signature length", () => {
  const { publicKey, privateKey } = generateSigningKeyPair();
  const receipt = { receipt_id: "TR-1", intent_id: "TI-1", decision_id: "TD-1" };
  const signed = signReceipt(receipt, privateKey, "kid-size");
  signed.signature.sig = "AQ";
  const result = verifyReceiptSignature(signed, publicKey);
  assert.equal(result.ok, false);
  assert.match(String(result.detail ?? ""), /64 bytes/i);
});

test("signing: verification fails when signature version is unsupported", () => {
  const { publicKey, privateKey } = generateSigningKeyPair();
  const receipt = { receipt_id: "TR-1", intent_id: "TI-1", decision_id: "TD-1" };
  const signed = signReceipt(receipt, privateKey, "kid-version");
  signed.signature.version = "ATP-ED25519-999";
  const result = verifyReceiptSignature(signed, publicKey);
  assert.equal(result.ok, false);
  assert.match(String(result.detail ?? ""), /unsupported signature version/i);
});

test("signing: receiptFingerprint is deterministic", () => {
  const receipt = { receipt_id: "TR-1", intent_id: "TI-1", decision_id: "TD-1" };
  const fp1 = receiptFingerprint(receipt);
  const fp2 = receiptFingerprint(receipt);
  assert.equal(fp1, fp2);
  assert.match(fp1, /^[a-f0-9]{64}$/);
});

test("signing: exportPublicKeyAsJwk returns valid JWK shape", () => {
  const { publicKey } = generateSigningKeyPair();
  const jwk = exportPublicKeyAsJwk(publicKey, "test-kid");
  assert.equal(jwk.kty, "OKP");
  assert.equal(jwk.crv, "Ed25519");
  assert.equal(jwk.kid, "test-kid");
  assert.equal(jwk.use, "sig");
  assert.match(jwk.x, /^[A-Za-z0-9_-]+$/);
});

test("replay guard: accepts first presentation, rejects duplicate", () => {
  const guard = new ReplayGuard({ windowMs: 60000, skewMs: 5000 });
  const receipt = { receipt_id: "TR-123", sealed_at: new Date().toISOString() };
  const first = guard.check(receipt);
  assert.equal(first.ok, true);
  const second = guard.check(receipt);
  assert.equal(second.ok, false);
  assert.equal(second.reason, "receipt_replay_detected");
});

test("replay guard: rejects receipt outside observation window", () => {
  const guard = new ReplayGuard({ windowMs: 60000, skewMs: 5000 });
  const old = new Date(Date.now() - 120000).toISOString();
  const receipt = { receipt_id: "TR-456", sealed_at: old };
  const result = guard.check(receipt);
  assert.equal(result.ok, false);
  assert.equal(result.reason, "receipt_outside_window");
});

test("replay guard: rejects invalid sealed_at format", () => {
  const guard = new ReplayGuard({ windowMs: 60000, skewMs: 5000 });
  const result = guard.check({ receipt_id: "TR-789", sealed_at: "not-a-date" });
  assert.equal(result.ok, false);
  assert.equal(result.reason, "receipt_invalid_datetime_format");
});

test("schema files are loadable json", async () => {
  const names = ["intent", "decision", "receipt"];
  for (const name of names) {
    const raw = await readFile(getSchemaPath(name), "utf8");
    const parsed = JSON.parse(raw);
    assert.equal(parsed.type, "object");
  }
});

test("receipt schema locks schemaVersion and canonicalization constants", async () => {
  const receiptSchemaRaw = await readFile(getSchemaPath("receipt"), "utf8");
  const receiptSchema = JSON.parse(receiptSchemaRaw);
  assert.equal(receiptSchema.properties.schemaVersion.const, "1.0.0");
  const objectSignature = receiptSchema.properties.signature.oneOf.find((entry) => entry.type === "object");
  assert.equal(objectSignature.properties.canonicalization.const, "RFC8785-JCS");
});

test("canonicalization/signature vector matches expected payload and signature", async () => {
  const vectorPath = resolve(process.cwd(), "..", "..", "spec", "test-vectors", "canonicalization-signature.v2.json");
  const vector = JSON.parse(await readFile(vectorPath, "utf8"));
  const canonicalPayload = canonicalJSONString(vector.receipt);
  const canonicalPayloadSha256 = createHash("sha256").update(canonicalBytes(vector.receipt)).digest("hex");
  assert.equal(canonicalPayload, vector.canonicalPayload);
  assert.equal(canonicalPayloadSha256, vector.canonicalPayloadSha256);
  assert.equal(vector.signedReceipt.signature.canonicalization, "RFC8785-JCS");
  assert.equal(vector.signedReceipt.signature.kid, vector.kid);
  assert.equal(typeof vector.signedReceipt.signature.sig, "string");
  assert.match(vector.signedReceipt.signature.sig, /^[A-Za-z0-9_-]+$/);
  const verification = verifyReceiptSignature(vector.signedReceipt, vector.publicKey, { expectedKid: vector.kid });
  assert.equal(verification.ok, true);
});

test("canonicalization/signature vector fails verification when signature is mutated", async () => {
  const vectorPath = resolve(process.cwd(), "..", "..", "spec", "test-vectors", "canonicalization-signature.v2.json");
  const vector = JSON.parse(await readFile(vectorPath, "utf8"));
  const forged = structuredClone(vector.signedReceipt);
  forged.signature.sig = `${forged.signature.sig.slice(0, -1)}A`;
  const verification = verifyReceiptSignature(forged, vector.publicKey, { expectedKid: vector.kid });
  assert.equal(verification.ok, false);
});

test("decision outcomes: allow/approve/deny are all valid", () => {
  const outcomes = ATP_DECISION_OUTCOMES;
  assert.deepEqual(outcomes, ["allow", "approve", "deny"]);
  assert.equal(outcomes.length, 3);
});

test("execution statuses: executed/blocked/expired/error are all valid", () => {
  const statuses = ATP_EXECUTION_STATUSES;
  assert.deepEqual(statuses, ["executed", "blocked", "expired", "error"]);
  assert.equal(statuses.length, 4);
});

test("receipt structure: required fields for allow outcome", () => {
  const { publicKey, privateKey } = generateSigningKeyPair();
  const receipt = {
    receipt_id: "TR-1",
    intent_id: "TI-1",
    decision_id: "TD-1",
    execution_status: "executed",
    schemaVersion: "1.0.0",
    occurred_at: "2026-03-31T00:00:00.000Z",
    received_at: "2026-03-31T00:00:00.000Z",
    sealed_at: "2026-03-31T00:00:02.000Z",
    captured_at: "2026-03-31T00:00:02.000Z",
    event_snapshot: { action: "test" },
    event_snapshot_hash: "a".repeat(64),
    correlation_id: "sess-1"
  };
  const signed = signReceipt(receipt, privateKey, "test-kid");
  assert.equal(signed.receipt_id, "TR-1");
  assert.equal(signed.execution_status, "executed");
  assert.equal(signed.schemaVersion, "1.0.0");
  assert.equal(typeof signed.signature, "object");
  assert.equal(signed.signature.alg, "Ed25519");
  assert.equal(signed.signature.canonicalization, "RFC8785-JCS");
});

test("receipt structure: optional fields (input_hash, output_hash, cost, metadata) are preserved", () => {
  const { publicKey, privateKey } = generateSigningKeyPair();
  const receipt = {
    receipt_id: "TR-2",
    intent_id: "TI-2",
    decision_id: "TD-2",
    execution_status: "executed",
    schemaVersion: "1.0.0",
    occurred_at: "2026-03-31T00:00:00.000Z",
    received_at: "2026-03-31T00:00:00.000Z",
    sealed_at: "2026-03-31T00:00:02.000Z",
    captured_at: "2026-03-31T00:00:02.000Z",
    event_snapshot: { action: "payment" },
    event_snapshot_hash: "b".repeat(64),
    correlation_id: "sess-2",
    input_hash: "c".repeat(64),
    output_hash: "d".repeat(64),
    cost: {
      amount: "0.50",
      currency: "USD",
      unit: "request"
    },
    metadata: {
      client_id: "web-app",
      trace_id: "xyz-789"
    }
  };
  const signed = signReceipt(receipt, privateKey, "test-kid");
  assert.equal(signed.input_hash, "c".repeat(64));
  assert.equal(signed.output_hash, "d".repeat(64));
  assert.equal(signed.cost.amount, "0.50");
  assert.equal(signed.metadata.client_id, "web-app");
});

test("timestamp invariant: occurred_at <= received_at <= sealed_at must hold", () => {
  const { publicKey, privateKey } = generateSigningKeyPair();
  const base = new Date("2026-03-31T00:00:00.000Z").getTime();
  const receipt = {
    receipt_id: "TR-3",
    intent_id: "TI-3",
    decision_id: "TD-3",
    execution_status: "executed",
    schemaVersion: "1.0.0",
    occurred_at: new Date(base + 0).toISOString(),
    received_at: new Date(base + 1000).toISOString(),
    sealed_at: new Date(base + 2000).toISOString(),
    captured_at: new Date(base + 2000).toISOString(),
    event_snapshot: { action: "test" },
    event_snapshot_hash: "e".repeat(64),
    correlation_id: "sess-3"
  };
  const signed = signReceipt(receipt, privateKey, "test-kid");
  const o = new Date(signed.occurred_at).getTime();
  const r = new Date(signed.received_at).getTime();
  const s = new Date(signed.sealed_at).getTime();
  assert.equal(o <= r, true);
  assert.equal(r <= s, true);
});

test("decision with approve outcome includes expires_at", () => {
  const { publicKey, privateKey } = generateSigningKeyPair();
  const base = new Date("2026-03-31T00:00:00.000Z").getTime();
  const receipt = {
    receipt_id: "TR-4",
    intent_id: "TI-4",
    decision_id: "TD-4",
    execution_status: "blocked",
    schemaVersion: "1.0.0",
    occurred_at: new Date(base).toISOString(),
    received_at: new Date(base).toISOString(),
    sealed_at: new Date(base + 2000).toISOString(),
    captured_at: new Date(base + 2000).toISOString(),
    event_snapshot: { action: "critical" },
    event_snapshot_hash: "f".repeat(64),
    correlation_id: "sess-4"
  };
  const signed = signReceipt(receipt, privateKey, "test-kid");
  assert.equal(typeof signed.signature, "object");
  assert.equal(signed.execution_status, "blocked");
});
