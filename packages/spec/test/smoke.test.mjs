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
  assert.equal(objectSignature.properties.canonicalization.const, "ATP-JCS-SORTED-UTF8");
});

test("canonicalization/signature vector matches expected payload and signature", async () => {
  const vectorPath = resolve(process.cwd(), "..", "..", "spec", "test-vectors", "canonicalization-signature.v1.json");
  const vector = JSON.parse(await readFile(vectorPath, "utf8"));
  const canonicalPayload = canonicalJSONString(vector.receipt);
  const canonicalPayloadSha256 = createHash("sha256").update(canonicalBytes(vector.receipt)).digest("hex");
  assert.equal(canonicalPayload, vector.canonicalPayload);
  assert.equal(canonicalPayloadSha256, vector.canonicalPayloadSha256);
  assert.equal(vector.signedReceipt.signature.canonicalization, "ATP-JCS-SORTED-UTF8");
  assert.equal(vector.signedReceipt.signature.kid, vector.kid);
  const verification = verifyReceiptSignature(vector.signedReceipt, vector.publicKey, { expectedKid: vector.kid });
  assert.equal(verification.ok, true);
});
