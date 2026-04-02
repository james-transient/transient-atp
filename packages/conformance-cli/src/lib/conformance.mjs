import {
  ATP_DECISION_OUTCOMES,
  ATP_EXECUTION_STATUSES,
  ATP_PROTOCOL,
  ATP_VERSION,
  verifyReceiptSignature
} from "@atp/spec";
import { validateReceiptATP } from "./receipt.mjs";

export function evaluateRuntimeConformance(runtime) {
  const attestation = runtime?.evidence?.attestation;
  const receipt = attestation?.trustReceipt;
  const atp = validateReceiptATP(receipt);
  const publicKey = typeof attestation?.trustReceiptPublicKey === "string"
    ? attestation.trustReceiptPublicKey
    : "";
  const expectedKid = typeof attestation?.trustReceiptKeyId === "string" && attestation.trustReceiptKeyId.trim().length > 0
    ? attestation.trustReceiptKeyId
    : undefined;
  const signatureVerification = publicKey && typeof receipt?.signature === "object"
    ? verifyReceiptSignature(receipt, publicKey, { expectedKid })
    : { ok: false, reason: "receipt_signature_verification_failed", detail: "missing Ed25519 signature or public key" };
  const keyDistributionOk = Boolean(
    attestation?.keyDistribution?.published === true &&
    typeof attestation?.keyDistribution?.endpoint === "string" &&
    attestation.keyDistribution.endpoint.trim().length > 0
  );
  const replayWindowSeconds = Number(attestation?.replayProtection?.observationWindowSeconds);
  const replayProtectionOk = Boolean(
    attestation?.replayProtection?.enabled === true &&
    Number.isFinite(replayWindowSeconds) &&
    replayWindowSeconds >= 300
  );
  const passed =
    runtime?.requiredAtpL1 === true
      ? atp.ok && signatureVerification.ok === true
      : true;

  return {
    runtimeId: runtime.runtimeId,
    requiredLevel: runtime.requiredLevel,
    requiredAtpL1: Boolean(runtime.requiredAtpL1),
    passed,
    atpL1: {
      valid: atp.ok,
      issues: atp.issues,
      warnings: atp.warnings,
      signatureVerified: signatureVerification.ok === true,
      signatureVerificationReason: signatureVerification.ok ? null : String(signatureVerification?.reason ?? "receipt_signature_verification_failed"),
      signatureVerificationDetail: signatureVerification.ok ? null : String(signatureVerification?.detail ?? "signature verification failed"),
      keyDistribution: keyDistributionOk,
      replayProtection: replayProtectionOk
    },
    scenario: {
      decisionOutcome: receipt?.decision?.outcome ?? "unknown",
      executionStatus: receipt?.execution_status ?? "unknown"
    }
  };
}

export function buildScenarioCoverage(results) {
  const coveredOutcomes = new Set();
  const coveredExecutionStatuses = new Set();
  for (const result of results) {
    coveredOutcomes.add(String(result?.scenario?.decisionOutcome ?? "unknown"));
    coveredExecutionStatuses.add(String(result?.scenario?.executionStatus ?? "unknown"));
  }
  const outcomeCovered = ATP_DECISION_OUTCOMES.filter((item) => coveredOutcomes.has(item));
  const executionCovered = ATP_EXECUTION_STATUSES.filter((item) => coveredExecutionStatuses.has(item));
  const outcomeMissing = ATP_DECISION_OUTCOMES.filter((item) => !coveredOutcomes.has(item));
  const executionMissing = ATP_EXECUTION_STATUSES.filter((item) => !coveredExecutionStatuses.has(item));

  return {
    complete: outcomeMissing.length === 0 && executionMissing.length === 0,
    decisionOutcomes: {
      required: ATP_DECISION_OUTCOMES,
      covered: outcomeCovered,
      missing: outcomeMissing
    },
    executionStatuses: {
      required: ATP_EXECUTION_STATUSES,
      covered: executionCovered,
      missing: executionMissing
    }
  };
}

export function runConformanceProofHarness({ runtimes }) {
  const results = (Array.isArray(runtimes) ? runtimes : []).map(evaluateRuntimeConformance);
  const scenarioCoverage = buildScenarioCoverage(results);
  const controlChecks = {
    keyDistribution: results.every((entry) => entry?.requiredAtpL1 !== true || entry?.atpL1?.keyDistribution === true),
    replayProtection: results.every((entry) => entry?.requiredAtpL1 !== true || entry?.atpL1?.replayProtection === true)
  };
  const overall = results.every((entry) => entry.passed) && scenarioCoverage.complete &&
    controlChecks.keyDistribution && controlChecks.replayProtection
    ? "PASS"
    : "FAIL";
  return {
    generatedAt: new Date().toISOString(),
    protocol: ATP_PROTOCOL,
    version: ATP_VERSION,
    overall,
    scenarioCoverage,
    controlChecks,
    results
  };
}
