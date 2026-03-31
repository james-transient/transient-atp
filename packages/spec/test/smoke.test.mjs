import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
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

test("schema files are loadable json", async () => {
  const names = ["intent", "decision", "receipt"];
  for (const name of names) {
    const raw = await readFile(getSchemaPath(name), "utf8");
    const parsed = JSON.parse(raw);
    assert.equal(parsed.type, "object");
  }
});
