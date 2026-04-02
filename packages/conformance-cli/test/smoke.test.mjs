import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { createSampleReceipt, validateReceiptATP } from "../src/lib/receipt.mjs";
import { validateConformanceReport } from "../src/lib/contract-validate.mjs";
import { evaluateRuntimeConformance } from "../src/lib/conformance.mjs";
import { generateProofReport } from "../src/lib/proof-harness.mjs";
import {
  evaluateReleaseGovernanceEvidence,
  validateReleaseGovernanceReport
} from "../src/lib/release-governance.mjs";
import { generateSigningKeyPair, signReceipt, verifyReceiptSignature } from "@atp/spec";

test("Ed25519 sign and verify round-trip on a valid receipt", () => {
  const { privateKey, publicKey } = generateSigningKeyPair();
  const base = createSampleReceipt({
    runId: "ed25519-test",
    sessionId: "ed25519-test",
    runStatus: "success",
    haltReason: "none",
    events: [
      { eventType: "tool_call_requested", capturedAt: "2026-03-31T00:00:00.000Z" },
      { eventType: "tool_call_executed", capturedAt: "2026-03-31T00:00:01.000Z" },
      { eventType: "run_end", capturedAt: "2026-03-31T00:00:02.000Z" }
    ]
  });
  const signed = signReceipt(base, privateKey, "key-001");
  assert.equal(typeof signed.signature, "object");
  assert.equal(signed.signature.alg, "Ed25519");
  assert.equal(signed.signature.kid, "key-001");
  const result = verifyReceiptSignature(signed, publicKey);
  assert.equal(result.ok, true);
});

test("Ed25519 signature fails verification with wrong key", () => {
  const { privateKey } = generateSigningKeyPair();
  const { publicKey: wrongKey } = generateSigningKeyPair();
  const base = createSampleReceipt({
    runId: "ed25519-wrong-key",
    sessionId: "ed25519-wrong-key",
    runStatus: "success",
    haltReason: "none",
    events: [
      { eventType: "tool_call_requested", capturedAt: "2026-03-31T00:00:00.000Z" },
      { eventType: "tool_call_executed", capturedAt: "2026-03-31T00:00:01.000Z" },
      { eventType: "run_end", capturedAt: "2026-03-31T00:00:02.000Z" }
    ]
  });
  const signed = signReceipt(base, privateKey, "key-001");
  const result = verifyReceiptSignature(signed, wrongKey);
  assert.equal(result.ok, false);
  assert.equal(result.reason, "receipt_signature_verification_failed");
});

test("Ed25519 signed receipt passes validateReceiptATP", () => {
  const { privateKey } = generateSigningKeyPair();
  const base = createSampleReceipt({
    runId: "ed25519-validate",
    sessionId: "ed25519-validate",
    runStatus: "success",
    haltReason: "none",
    events: [
      { eventType: "tool_call_requested", capturedAt: "2026-03-31T00:00:00.000Z" },
      { eventType: "tool_call_executed", capturedAt: "2026-03-31T00:00:01.000Z" },
      { eventType: "run_end", capturedAt: "2026-03-31T00:00:02.000Z" }
    ]
  });
  const signed = signReceipt(base, privateKey, "key-001");
  const result = validateReceiptATP(signed);
  assert.equal(result.ok, true);
});

test("sample receipt IDs are deterministic per run/session and not globally constant", () => {
  const first = createSampleReceipt({
    runId: "id-seed-a",
    sessionId: "sess-a",
    runStatus: "success",
    haltReason: "none",
    events: [{ eventType: "run_end", capturedAt: "2026-03-31T00:00:00.000Z" }]
  });
  const second = createSampleReceipt({
    runId: "id-seed-b",
    sessionId: "sess-b",
    runStatus: "success",
    haltReason: "none",
    events: [{ eventType: "run_end", capturedAt: "2026-03-31T00:00:00.000Z" }]
  });
  const repeatFirst = createSampleReceipt({
    runId: "id-seed-a",
    sessionId: "sess-a",
    runStatus: "success",
    haltReason: "none",
    events: [{ eventType: "run_end", capturedAt: "2026-03-31T00:00:00.000Z" }]
  });
  assert.notEqual(first.receipt_id, second.receipt_id);
  assert.equal(first.receipt_id, repeatFirst.receipt_id);
});

test("legacy sha256 signature produces deprecation warning, not error", () => {
  const receipt = createSampleReceipt({
    runId: "legacy-sig-test",
    sessionId: "legacy-sig-test",
    runStatus: "success",
    haltReason: "none",
    events: [
      { eventType: "tool_call_requested", capturedAt: "2026-03-31T00:00:00.000Z" },
      { eventType: "tool_call_executed", capturedAt: "2026-03-31T00:00:01.000Z" },
      { eventType: "run_end", capturedAt: "2026-03-31T00:00:02.000Z" }
    ]
  });
  assert.match(receipt.signature, /^sha256:[a-f0-9]{64}$/);
  const result = validateReceiptATP(receipt);
  assert.equal(result.ok, true);
  assert.equal(result.issues.length, 0);
  assert.ok(result.warnings.length > 0);
  assert.equal(result.warnings[0].code, "receipt_deprecated_legacy_signature");
});

test("receipt validation rejects Ed25519 signature with non-ATP canonicalization metadata", () => {
  const { privateKey } = generateSigningKeyPair();
  const receipt = createSampleReceipt({
    runId: "invalid-canonicalization",
    sessionId: "invalid-canonicalization",
    runStatus: "success",
    haltReason: "none",
    events: [
      { eventType: "tool_call_requested", capturedAt: "2026-03-31T00:00:00.000Z" },
      { eventType: "tool_call_executed", capturedAt: "2026-03-31T00:00:01.000Z" },
      { eventType: "run_end", capturedAt: "2026-03-31T00:00:02.000Z" }
    ]
  });
  const signed = signReceipt(receipt, privateKey, "canon-key-001");
  signed.signature.canonicalization = "NOT-ATP";
  const result = validateReceiptATP(signed);
  assert.equal(result.ok, false);
  const codes = new Set(result.issues.map((issue) => issue.code));
  assert.equal(codes.has("receipt_invalid_signature_format"), true);
});

test("runtime conformance fails forged legacy signature even when trustReceiptSigned is true", () => {
  const receipt = createSampleReceipt({
    runId: "forged-legacy",
    sessionId: "forged-legacy",
    runStatus: "success",
    haltReason: "none",
    events: [
      { eventType: "tool_call_requested", capturedAt: "2026-03-31T00:00:00.000Z" },
      { eventType: "tool_call_executed", capturedAt: "2026-03-31T00:00:01.000Z" },
      { eventType: "run_end", capturedAt: "2026-03-31T00:00:02.000Z" }
    ]
  });
  receipt.signature = `sha256:${"0".repeat(64)}`;
  const result = evaluateRuntimeConformance({
    runtimeId: "forged-runtime",
    requiredLevel: "CLASSIFY_ONLY",
    requiredAtpL1: true,
    evidence: {
      attestation: {
        trustReceiptSigned: true,
        keyDistribution: { published: true, endpoint: "/.well-known/atp-keys" },
        replayProtection: { enabled: true, observationWindowSeconds: 300 },
        trustReceipt: receipt
      }
    }
  });
  assert.equal(result.atpL1.valid, true);
  assert.equal(result.atpL1.signatureVerified, false);
  assert.equal(result.passed, false);
});

test("runtime conformance requires cryptographic verification for PASS", () => {
  const { privateKey, publicKey } = generateSigningKeyPair();
  const receipt = createSampleReceipt({
    runId: "runtime-verify-pass",
    sessionId: "runtime-verify-pass",
    runStatus: "success",
    haltReason: "none",
    events: [
      { eventType: "tool_call_requested", capturedAt: "2026-03-31T00:00:00.000Z" },
      { eventType: "tool_call_executed", capturedAt: "2026-03-31T00:00:01.000Z" },
      { eventType: "run_end", capturedAt: "2026-03-31T00:00:02.000Z" }
    ]
  });
  const signed = signReceipt(receipt, privateKey, "runtime-key-001");
  const result = evaluateRuntimeConformance({
    runtimeId: "verified-runtime",
    requiredLevel: "CLASSIFY_ONLY",
    requiredAtpL1: true,
    evidence: {
      attestation: {
        trustReceiptSigned: true,
        trustReceiptPublicKey: publicKey,
        trustReceiptKeyId: "runtime-key-001",
        keyDistribution: { published: true, endpoint: "/.well-known/atp-keys" },
        replayProtection: { enabled: true, observationWindowSeconds: 300 },
        trustReceipt: signed
      }
    }
  });
  assert.equal(result.atpL1.signatureVerified, true);
  assert.equal(result.passed, true);
});

test("runtime conformance fails when attested key id does not match receipt signature kid", () => {
  const { privateKey, publicKey } = generateSigningKeyPair();
  const receipt = createSampleReceipt({
    runId: "runtime-kid-mismatch",
    sessionId: "runtime-kid-mismatch",
    runStatus: "success",
    haltReason: "none",
    events: [
      { eventType: "tool_call_requested", capturedAt: "2026-03-31T00:00:00.000Z" },
      { eventType: "tool_call_executed", capturedAt: "2026-03-31T00:00:01.000Z" },
      { eventType: "run_end", capturedAt: "2026-03-31T00:00:02.000Z" }
    ]
  });
  const signed = signReceipt(receipt, privateKey, "runtime-kid-a");
  const result = evaluateRuntimeConformance({
    runtimeId: "runtime-kid-mismatch",
    requiredLevel: "CLASSIFY_ONLY",
    requiredAtpL1: true,
    evidence: {
      attestation: {
        trustReceiptSigned: true,
        trustReceiptPublicKey: publicKey,
        trustReceiptKeyId: "runtime-kid-b",
        keyDistribution: { published: true, endpoint: "/.well-known/atp-keys" },
        replayProtection: { enabled: true, observationWindowSeconds: 300 },
        trustReceipt: signed
      }
    }
  });
  assert.equal(result.atpL1.signatureVerified, false);
  assert.equal(result.passed, false);
});

test("cli run command returns ATP report", async () => {
  const repoRoot = resolve(process.cwd(), "..", "..");
  const result = spawnSync(
    process.execPath,
    ["packages/conformance-cli/src/cli.mjs", "run", "--openclaw-frames", "conformance-kit/fixtures/openclaw/gateway-frames-live.json"],
    { cwd: repoRoot, encoding: "utf8" }
  );
  assert.equal(result.status, 0);
  const parsed = JSON.parse(String(result.stdout ?? "{}"));
  assert.equal(parsed.protocol, "ATP");
  assert.equal(parsed.overall, "PASS");
});

test("proof harness supports external runtimes fixture mode", async () => {
  const repoRoot = resolve(process.cwd(), "..", "..");
  const report = await generateProofReport({
    cwd: repoRoot,
    runtimesFixturePath: "conformance-kit/fixtures/external/runtimes.v1.json"
  });
  assert.equal(report.protocol, "ATP");
  assert.equal(Array.isArray(report.results), true);
  assert.equal(report.results.length, 5);
  assert.equal(report.results[0].runtimeId, "financial-flowers-allow-under-budget");
  assert.equal(report.results[0].atpL1.signatureVerified, true);
});

test("cli run supports --runtimes-fixture", async () => {
  const repoRoot = resolve(process.cwd(), "..", "..");
  const result = spawnSync(
    process.execPath,
    [
      "packages/conformance-cli/src/cli.mjs",
      "run",
      "--runtimes-fixture",
      "conformance-kit/fixtures/external/runtimes.v1.json"
    ],
    { cwd: repoRoot, encoding: "utf8" }
  );
  assert.equal(result.status, 0);
  const parsed = JSON.parse(String(result.stdout ?? "{}"));
  assert.equal(parsed.protocol, "ATP");
  assert.equal(parsed.results?.[0]?.runtimeId, "financial-flowers-allow-under-budget");
});

test("external runtimes fixture validates against conformance contract", async () => {
  const repoRoot = resolve(process.cwd(), "..", "..");
  const report = await generateProofReport({
    cwd: repoRoot,
    runtimesFixturePath: "conformance-kit/fixtures/external/runtimes.v1.json"
  });
  const contract = JSON.parse(
    await readFile(resolve(repoRoot, "conformance-kit/expected/contract.json"), "utf8")
  );
  const validation = validateConformanceReport(report, contract);
  assert.equal(validation.ok, true);
});

test("cli validate command validates generated report", async () => {
  const repoRoot = resolve(process.cwd(), "..", "..");
  const kit = spawnSync(process.execPath, ["packages/conformance-cli/src/cli.mjs", "kit"], {
    cwd: repoRoot,
    encoding: "utf8"
  });
  assert.equal(kit.status, 0);

  const validate = spawnSync(
    process.execPath,
    [
      "packages/conformance-cli/src/cli.mjs",
      "validate",
      "--contract",
      "conformance-kit/expected/contract.json",
      "--report",
      "conformance-kit/artifacts/latest-report.json"
    ],
    { cwd: repoRoot, encoding: "utf8" }
  );
  assert.equal(validate.status, 0);
  const parsed = JSON.parse(String(validate.stdout ?? "{}"));
  assert.equal(parsed.ok, true);

  const validationRaw = await readFile(resolve(repoRoot, "conformance-kit/artifacts/latest-validation.json"), "utf8");
  const validation = JSON.parse(validationRaw);
  assert.equal(validation.ok, true);
});

test("receipt validation rejects invalid execution_status and decision.outcome enums", () => {
  const receipt = createSampleReceipt({
    runId: "enum-test",
    sessionId: "enum-test",
    runStatus: "success",
    haltReason: "none",
    events: [
      { eventType: "run_start", capturedAt: "2026-03-31T00:00:00.000Z" },
      { eventType: "run_end", capturedAt: "2026-03-31T00:00:01.000Z" }
    ]
  });
  receipt.execution_status = "totally_invalid";
  receipt.decision.outcome = "not_a_real_outcome";
  const result = validateReceiptATP(receipt);
  assert.equal(result.ok, false);
  const codes = new Set(result.issues.map((issue) => issue.code));
  assert.equal(codes.has("receipt_invalid_execution_status"), true);
  assert.equal(codes.has("decision_invalid_outcome"), true);
});

test("receipt validation rejects invalid captured_at datetime", () => {
  const receipt = createSampleReceipt({
    runId: "captured-at-test",
    sessionId: "captured-at-test",
    runStatus: "success",
    haltReason: "none",
    events: [
      { eventType: "run_start", capturedAt: "2026-03-31T00:00:00.000Z" },
      { eventType: "run_end", capturedAt: "2026-03-31T00:00:01.000Z" }
    ]
  });
  receipt.captured_at = "not-a-date";
  const result = validateReceiptATP(receipt);
  assert.equal(result.ok, false);
  const codes = new Set(result.issues.map((issue) => issue.code));
  assert.equal(codes.has("receipt_invalid_captured_at"), true);
});

test("receipt validation accepts RFC3339 fractional seconds beyond millisecond precision", () => {
  const receipt = createSampleReceipt({
    runId: "fractional-seconds",
    sessionId: "fractional-seconds",
    runStatus: "success",
    haltReason: "none",
    events: [
      { eventType: "run_start", capturedAt: "2026-03-31T00:00:00.1Z" },
      { eventType: "run_end", capturedAt: "2026-03-31T00:00:00.123456Z" }
    ]
  });
  receipt.occurred_at = "2026-03-31T00:00:00.1Z";
  receipt.received_at = "2026-03-31T00:00:00.12Z";
  receipt.sealed_at = "2026-03-31T00:00:00.123456Z";
  receipt.captured_at = "2026-03-31T00:00:00.123456Z";
  receipt.intent.requested_at = "2026-03-31T00:00:00.1Z";
  receipt.decision.decided_at = "2026-03-31T00:00:00.123456Z";
  const result = validateReceiptATP(receipt);
  assert.equal(result.ok, true);
});

test("receipt validation rejects schema-incompatible receipt fields", () => {
  const receipt = createSampleReceipt({
    runId: "schema-invalid",
    sessionId: "schema-invalid",
    runStatus: "success",
    haltReason: "none",
    events: [
      { eventType: "run_start", capturedAt: "2026-03-31T00:00:00.000Z" },
      { eventType: "run_end", capturedAt: "2026-03-31T00:00:01.000Z" }
    ]
  });
  delete receipt.schemaVersion;
  receipt.signature = "garbage";
  receipt.occurred_at = "2026-03-31";
  receipt.received_at = "2026-03-31";
  receipt.sealed_at = "2026-03-31";
  delete receipt.decision.reason_code;
  delete receipt.intent.actor_id;
  const result = validateReceiptATP(receipt);
  assert.equal(result.ok, false);
  const codes = new Set(result.issues.map((issue) => issue.code));
  assert.equal(codes.has("receipt_missing_required_field"), true);
  assert.equal(codes.has("receipt_invalid_schema_version"), true);
  assert.equal(codes.has("receipt_invalid_signature_format"), true);
  assert.equal(codes.has("receipt_invalid_datetime_format"), true);
});

test("proof harness rejects non-frame JSON input", async () => {
  const repoRoot = resolve(process.cwd(), "..", "..");
  const tempFile = resolve(await mkdtemp(resolve(tmpdir(), "atp-nonframe-")), "not-frames.json");
  await writeFile(tempFile, JSON.stringify({ hello: "world" }, null, 2));
  const run = spawnSync(
    process.execPath,
    ["packages/conformance-cli/src/cli.mjs", "run", "--openclaw-frames", tempFile, "--allow-local-artifacts"],
    { cwd: repoRoot, encoding: "utf8" }
  );
  assert.notEqual(run.status, 0);
  assert.match(String(run.stderr ?? ""), /'frames' array/i);
});

test("receipt validation rejects missing intent and event_snapshot object bypass", () => {
  const receipt = createSampleReceipt({
    runId: "obj-test",
    sessionId: "obj-test",
    runStatus: "success",
    haltReason: "none",
    events: [
      { eventType: "run_start", capturedAt: "2026-03-31T00:00:00.000Z" },
      { eventType: "run_end", capturedAt: "2026-03-31T00:00:01.000Z" }
    ]
  });
  delete receipt.intent;
  delete receipt.event_snapshot;
  const result = validateReceiptATP(receipt);
  assert.equal(result.ok, false);
  const codes = new Set(result.issues.map((issue) => issue.code));
  assert.equal(codes.has("receipt_missing_required_object"), true);
});

test("receipt validation rejects cross-object id mismatch", () => {
  const receipt = createSampleReceipt({
    runId: "id-mismatch",
    sessionId: "id-mismatch",
    runStatus: "success",
    haltReason: "none",
    events: [
      { eventType: "run_start", capturedAt: "2026-03-31T00:00:00.000Z" },
      { eventType: "run_end", capturedAt: "2026-03-31T00:00:01.000Z" }
    ]
  });
  receipt.intent.intent_id = "TI-999999999";
  receipt.decision.intent_id = "TI-111111111";
  receipt.decision.decision_id = "TD-222222222";
  const result = validateReceiptATP(receipt);
  assert.equal(result.ok, false);
  const codes = new Set(result.issues.map((issue) => issue.code));
  assert.equal(codes.has("receipt_intent_id_mismatch"), true);
  assert.equal(codes.has("receipt_decision_id_mismatch"), true);
});

test("contract validator rejects weak empty contract", () => {
  const result = validateConformanceReport({}, {});
  assert.equal(result.ok, false);
  assert.match(result.failures.join("\n"), /requiredScenarioCoverage/);
});

test("contract validator rejects malformed requiredRuntimes typing", () => {
  const report = {
    overall: "PASS",
    scenarioCoverage: {
      complete: true,
      decisionOutcomes: { covered: ["allow", "approve", "deny"] },
      executionStatuses: { covered: ["executed", "blocked", "expired", "error"] }
    },
    results: [
      {
        runtimeId: "r1",
        requiredLevel: "CLASSIFY_ONLY",
        requiredAtpL1: true,
        passed: false,
        atpL1: { valid: true }
      }
    ]
  };
  const contract = {
    requiredOverall: "PASS",
    requiredScenarioCoverage: {
      decisionOutcomes: ["allow", "approve", "deny"],
      executionStatuses: ["executed", "blocked", "expired", "error"],
      complete: true
    },
    requiredControlChecks: {
      keyDistribution: true,
      replayProtection: true
    },
    requiredRuntimes: [
      {
        runtimeId: "r1",
        passed: "true",
        requiredLevel: 1,
        requiredAtpL1: "yes",
        atpValid: "true"
      }
    ]
  };
  const result = validateConformanceReport(report, contract);
  assert.equal(result.ok, false);
  assert.match(result.failures.join("\n"), /requiredRuntimes\[0\]\.passed must be boolean/);
});

test("proof harness rejects frame payloads missing required semantic event types", async () => {
  const repoRoot = resolve(process.cwd(), "..", "..");
  const tempFile = resolve(await mkdtemp(resolve(tmpdir(), "atp-minimal-frame-")), "frames.json");
  await writeFile(
    tempFile,
    JSON.stringify({ frames: [{ type: "event", payload: { eventType: "run_end" } }] }, null, 2)
  );
  const run = spawnSync(
    process.execPath,
    ["packages/conformance-cli/src/cli.mjs", "run", "--openclaw-frames", tempFile, "--allow-local-artifacts"],
    { cwd: repoRoot, encoding: "utf8" }
  );
  assert.notEqual(run.status, 0);
  assert.match(String(run.stderr ?? ""), /missing required event types/i);
});

test("proof harness rejects local-artifact-like paths without allow flag", async () => {
  const repoRoot = resolve(process.cwd(), "..", "..");
  const tempDir = await mkdtemp(resolve(tmpdir(), "tt-local-like-"));
  const tempFile = resolve(tempDir, "TT-LOCAL");
  await writeFile(
    tempFile,
    JSON.stringify(
      {
        frames: [
          { type: "event", payload: { eventType: "tool_call_requested" } },
          { type: "event", payload: { eventType: "tool_call_executed" } },
          { type: "event", payload: { eventType: "run_end" } }
        ]
      },
      null,
      2
    )
  );
  const run = spawnSync(
    process.execPath,
    ["packages/conformance-cli/src/cli.mjs", "run", "--openclaw-frames", tempFile],
    { cwd: repoRoot, encoding: "utf8" }
  );
  assert.notEqual(run.status, 0);
  assert.match(String(run.stderr ?? ""), /rejects local runtime artifact inputs/i);
});

test("industry gate rejects negative threshold values", async () => {
  const repoRoot = resolve(process.cwd(), "..", "..");
  const tempFile = resolve(await mkdtemp(resolve(tmpdir(), "atp-negative-thresholds-")), "industry.json");
  await writeFile(
    tempFile,
    JSON.stringify(
      {
        profile: "ATP_1_0_INDUSTRY_GATE",
        minimumDefinedTargets: -100,
        minimumImplementedTargets: -100,
        requireIndependentVerifier: false
      },
      null,
      2
    )
  );
  const run = spawnSync(
    process.execPath,
    ["packages/conformance-cli/src/cli.mjs", "industry", "--industry-contract", tempFile],
    { cwd: repoRoot, encoding: "utf8" }
  );
  assert.notEqual(run.status, 0);
  assert.match(String(run.stdout ?? ""), /INTEROP-MATRIX/);
});

test("industry gate rejects zero thresholds", async () => {
  const repoRoot = resolve(process.cwd(), "..", "..");
  const tempFile = resolve(await mkdtemp(resolve(tmpdir(), "atp-zero-thresholds-")), "industry.json");
  await writeFile(
    tempFile,
    JSON.stringify(
      {
        profile: "ATP_1_0_INDUSTRY_GATE",
        minimumDefinedTargets: 0,
        minimumImplementedTargets: 0,
        requireIndependentVerifier: false
      },
      null,
      2
    )
  );
  const run = spawnSync(
    process.execPath,
    ["packages/conformance-cli/src/cli.mjs", "industry", "--industry-contract", tempFile],
    { cwd: repoRoot, encoding: "utf8" }
  );
  assert.notEqual(run.status, 0);
  assert.match(String(run.stdout ?? ""), /INTEROP-MATRIX/);
});

test("industry gate rejects malformed requireIndependentVerifier contract typing", async () => {
  const repoRoot = resolve(process.cwd(), "..", "..");
  const tempFile = resolve(await mkdtemp(resolve(tmpdir(), "atp-verifier-type-")), "industry.json");
  await writeFile(
    tempFile,
    JSON.stringify(
      {
        profile: "ATP_1_0_INDUSTRY_GATE",
        minimumDefinedTargets: 3,
        minimumImplementedTargets: 1,
        requireIndependentVerifier: "yes"
      },
      null,
      2
    )
  );
  const run = spawnSync(
    process.execPath,
    ["packages/conformance-cli/src/cli.mjs", "industry", "--industry-contract", tempFile],
    {
      cwd: repoRoot,
      encoding: "utf8",
      env: {
        ...process.env,
        ATP_INDEPENDENT_VERIFIER_CMD: "true"
      }
    }
  );
  assert.notEqual(run.status, 0);
  assert.match(String(run.stdout ?? ""), /INDEPENDENT-VERIFIER-HOOK/);
});

test("release governance profile command produces PASS report", () => {
  const repoRoot = resolve(process.cwd(), "..", "..");
  const run = spawnSync(process.execPath, ["packages/conformance-cli/src/cli.mjs", "release-profile"], {
    cwd: repoRoot,
    encoding: "utf8"
  });
  assert.equal(run.status, 0);
  const parsed = JSON.parse(String(run.stdout ?? "{}"));
  assert.equal(parsed.ok, true);
});

test("release governance report validates against release contract", async () => {
  const repoRoot = resolve(process.cwd(), "..", "..");
  const run = spawnSync(process.execPath, ["packages/conformance-cli/src/cli.mjs", "release-profile"], {
    cwd: repoRoot,
    encoding: "utf8"
  });
  assert.equal(run.status, 0);
  const reportRaw = await readFile(resolve(repoRoot, "conformance-kit/artifacts/latest-release-governance.json"), "utf8");
  const contractRaw = await readFile(resolve(repoRoot, "conformance-kit/expected/release-governance.contract.json"), "utf8");
  const report = JSON.parse(reportRaw);
  const contract = JSON.parse(contractRaw);
  const validation = validateReleaseGovernanceReport(report, contract);
  assert.equal(validation.ok, true);
  const signingCheck = (Array.isArray(report.checks) ? report.checks : []).find((item) => item.id === "RGP-NONDEPRECATED-SIGNING");
  assert.equal(Boolean(signingCheck?.ok), true);
});

test("release governance rejects digest mismatch", async () => {
  const repoRoot = resolve(process.cwd(), "..", "..");
  const fixtureRaw = await readFile(
    resolve(repoRoot, "conformance-kit/fixtures/release-governance/publish-evidence.json"),
    "utf8"
  );
  const fixture = JSON.parse(fixtureRaw);
  fixture.release.tarball_sha256 = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
  const report = evaluateReleaseGovernanceEvidence(fixture);
  const failedChecks = new Set(report.checks.filter((entry) => !entry.ok).map((entry) => entry.id));
  assert.equal(report.overall, "FAIL");
  assert.equal(failedChecks.has("RGP-DIGEST-BINDING"), true);
});

test("release governance rejects blocked path exposure", async () => {
  const repoRoot = resolve(process.cwd(), "..", "..");
  const fixtureRaw = await readFile(
    resolve(repoRoot, "conformance-kit/fixtures/release-governance/publish-evidence.json"),
    "utf8"
  );
  const fixture = JSON.parse(fixtureRaw);
  fixture.release.manifest_paths.push("src/internal/secret-export.mjs");
  const report = evaluateReleaseGovernanceEvidence(fixture);
  const failedChecks = new Set(report.checks.filter((entry) => !entry.ok).map((entry) => entry.id));
  assert.equal(report.overall, "FAIL");
  assert.equal(failedChecks.has("RGP-BLOCKED-PATHS"), true);
});

test("release governance rejects blocked path exposure using glob pattern", async () => {
  const repoRoot = resolve(process.cwd(), "..", "..");
  const fixtureRaw = await readFile(
    resolve(repoRoot, "conformance-kit/fixtures/release-governance/publish-evidence.json"),
    "utf8"
  );
  const fixture = JSON.parse(fixtureRaw);
  fixture.release.manifest_paths.push("dist/index.js.map");
  fixture.policy.blocked_paths = ["**/*.map"];
  const report = evaluateReleaseGovernanceEvidence(fixture);
  const failedChecks = new Set(report.checks.filter((entry) => !entry.ok).map((entry) => entry.id));
  assert.equal(report.overall, "FAIL");
  assert.equal(failedChecks.has("RGP-BLOCKED-PATHS"), true);
});

test("release governance rejects allow outcome when policy requires approval", async () => {
  const repoRoot = resolve(process.cwd(), "..", "..");
  const fixtureRaw = await readFile(
    resolve(repoRoot, "conformance-kit/fixtures/release-governance/publish-evidence.json"),
    "utf8"
  );
  const fixture = JSON.parse(fixtureRaw);
  fixture.policy.require_approval = true;
  fixture.haltReason = "none";
  fixture.runStatus = "success";
  const report = evaluateReleaseGovernanceEvidence(fixture);
  const failedChecks = new Set(report.checks.filter((entry) => !entry.ok).map((entry) => entry.id));
  assert.equal(report.overall, "FAIL");
  assert.equal(failedChecks.has("RGP-APPROVAL-OUTCOME"), true);
});

test("release governance rejects invalid lifecycle ordering", async () => {
  const repoRoot = resolve(process.cwd(), "..", "..");
  const fixtureRaw = await readFile(
    resolve(repoRoot, "conformance-kit/fixtures/release-governance/publish-evidence.json"),
    "utf8"
  );
  const fixture = JSON.parse(fixtureRaw);
  fixture.lifecycle = [
    { stage: "policy_evaluation", at: "2026-03-31T00:00:00.500Z" },
    { stage: "preflight_declaration", at: "2026-03-31T00:00:00.000Z" },
    { stage: "execution_authorization", at: "2026-03-31T00:00:01.000Z" },
    { stage: "post_execution_attestation", at: "2026-03-31T00:00:02.000Z" }
  ];
  const report = evaluateReleaseGovernanceEvidence(fixture);
  const failedChecks = new Set(report.checks.filter((entry) => !entry.ok).map((entry) => entry.id));
  assert.equal(report.overall, "FAIL");
  assert.equal(failedChecks.has("RGP-LIFECYCLE-ORDER"), true);
});

test("release governance validate rejects forged report with fabricated checks", async () => {
  const repoRoot = resolve(process.cwd(), "..", "..");
  const contractRaw = await readFile(resolve(repoRoot, "conformance-kit/expected/release-governance.contract.json"), "utf8");
  const contract = JSON.parse(contractRaw);
  const forged = {
    overall: "PASS",
    lifecycleStages: [
      "preflight_declaration",
      "policy_evaluation",
      "execution_authorization",
      "post_execution_attestation"
    ],
    policy: {
      require_approval: false,
      blocked_paths: ["**/*.map"]
    },
    signing: {
      jwks: { keys: [] }
    },
    receipt: {
      schemaVersion: "1.0.0",
      receipt_id: "TR-1",
      intent_id: "TI-1",
      decision_id: "TD-1",
      execution_status: "executed",
      captured_at: "2026-03-31T00:00:02.000Z",
      signature: {
        alg: "Ed25519",
        kid: "forged",
        sig: "forged",
        canonicalization: "ATP-JCS-SORTED-UTF8"
      },
      occurred_at: "2026-03-31T00:00:00.000Z",
      received_at: "2026-03-31T00:00:01.000Z",
      sealed_at: "2026-03-31T00:00:02.000Z",
      event_snapshot: {
        release: {
          tarball_sha256: "a".repeat(64),
          manifest_sha256: "b".repeat(64),
          manifest_paths: ["dist/index.js.map"],
          publish_attempted: true
        }
      },
      event_snapshot_hash: "a".repeat(64),
      correlation_id: "forged:1:0",
      intent: {
        intent_id: "TI-1",
        actor_id: "forged",
        connector: "forged",
        action: "registry.publish",
        action_class: "write_high",
        target: {},
        context: {
          package_name: "@forged/pkg",
          package_version: "1.0.0",
          expected_tarball_sha256: "a".repeat(64),
          expected_manifest_sha256: "b".repeat(64)
        },
        governance_profile: "release_governance_profile",
        requested_at: "2026-03-31T00:00:00.000Z"
      },
      decision: {
        decision_id: "TD-1",
        intent_id: "TI-1",
        outcome: "allow",
        reason_code: "forged",
        decided_at: "2026-03-31T00:00:01.000Z"
      }
    },
    checks: contract.requiredChecks.map((id) => ({ id, ok: true, message: "forged pass" }))
  };
  const validation = validateReleaseGovernanceReport(forged, contract);
  assert.equal(validation.ok, false);
});

test("release governance rejects publish attempt without passing decision gate", async () => {
  const repoRoot = resolve(process.cwd(), "..", "..");
  const fixtureRaw = await readFile(
    resolve(repoRoot, "conformance-kit/fixtures/release-governance/publish-evidence.json"),
    "utf8"
  );
  const fixture = JSON.parse(fixtureRaw);
  fixture.haltReason = "blocked_by_policy";
  fixture.runStatus = "halted";
  fixture.release.publish_attempted = true;
  const report = evaluateReleaseGovernanceEvidence(fixture);
  const failedChecks = new Set(report.checks.filter((entry) => !entry.ok).map((entry) => entry.id));
  assert.equal(report.overall, "FAIL");
  assert.equal(failedChecks.has("RGP-DECISION-GATE"), true);
});
