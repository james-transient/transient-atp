import { ATP_DECISION_OUTCOMES, ATP_EXECUTION_STATUSES, ATP_PROTOCOL, ATP_VERSION } from "@atp/spec";
import { validateReceiptATP } from "./receipt.mjs";

export function evaluateRuntimeConformance(runtime) {
  const receipt = runtime?.evidence?.attestation?.trustReceipt;
  const atp = validateReceiptATP(receipt);
  const passed =
    runtime?.requiredAtpL1 === true
      ? atp.ok && runtime?.evidence?.attestation?.trustReceiptSigned === true
      : true;

  return {
    runtimeId: runtime.runtimeId,
    requiredLevel: runtime.requiredLevel,
    requiredAtpL1: Boolean(runtime.requiredAtpL1),
    passed,
    atpL1: {
      valid: atp.ok,
      issues: atp.issues
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
  const overall = results.every((entry) => entry.passed) && scenarioCoverage.complete ? "PASS" : "FAIL";
  return {
    generatedAt: new Date().toISOString(),
    protocol: ATP_PROTOCOL,
    version: ATP_VERSION,
    overall,
    scenarioCoverage,
    results
  };
}
