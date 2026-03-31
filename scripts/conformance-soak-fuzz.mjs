import { mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { performance } from "node:perf_hooks";
import {
  createSampleReceipt,
  hashEventSnapshot,
  validateReceiptATP
} from "../packages/conformance-cli/src/lib/receipt.mjs";
import { validateConformanceReport } from "../packages/conformance-cli/src/lib/contract-validate.mjs";
import { generateProofReport } from "../packages/conformance-cli/src/lib/proof-harness.mjs";

function parseIntArg(argv, flag, fallback) {
  const idx = argv.indexOf(flag);
  if (idx === -1) return fallback;
  const parsed = Number.parseInt(String(argv[idx + 1] ?? ""), 10);
  if (!Number.isInteger(parsed) || parsed < 1) {
    throw new Error(`${flag} must be a positive integer`);
  }
  return parsed;
}

function randInt(maxExclusive) {
  return Math.floor(Math.random() * maxExclusive);
}

function buildInvalidMutators() {
  return [
    (r) => { r.signature = "nope"; },
    (r) => { delete r.schemaVersion; },
    (r) => { r.schemaVersion = "9.9.9"; },
    (r) => { delete r.intent; },
    (r) => { delete r.decision; },
    (r) => { delete r.event_snapshot; },
    (r) => { if (r.intent) r.intent.intent_id = "TI-999"; },
    (r) => { if (r.decision) r.decision.intent_id = "TI-123"; },
    (r) => { if (r.decision) r.decision.decision_id = "TD-321"; },
    (r) => { r.execution_status = "weird"; },
    (r) => { if (r.decision) r.decision.outcome = "maybe"; },
    (r) => { r.captured_at = "invalid"; },
    (r) => { r.occurred_at = "2026-03-31"; },
    (r) => { r.received_at = "2026-03-31"; },
    (r) => { r.sealed_at = "2026-03-31"; },
    (r) => { r.event_snapshot_hash = "deadbeef"; },
    (r) => { r.receipt_id = "TR-abc"; },
    (r) => { r.intent_id = "TI-abc"; },
    (r) => { r.decision_id = "TD-abc"; },
    (r) => { if (r.intent) delete r.intent.actor_id; },
    (r) => { if (r.decision) delete r.decision.reason_code; },
    (r) => { r.correlation_id = ""; }
  ];
}

async function main() {
  const argv = process.argv.slice(2);
  const receiptInvalidRuns = parseIntArg(argv, "--receipt-invalid-runs", 12000);
  const receiptValidRuns = parseIntArg(argv, "--receipt-valid-runs", 3000);
  const contractMalformedRuns = parseIntArg(argv, "--contract-malformed-runs", 4000);
  const pathGuardRuns = parseIntArg(argv, "--path-guard-runs", 1000);
  const allowOverrideRuns = parseIntArg(argv, "--allow-override-runs", 25);

  const startedAt = performance.now();
  const cwd = process.cwd();
  const baseReceipt = createSampleReceipt({
    runId: "soak",
    sessionId: "soak",
    runStatus: "success",
    haltReason: "none",
    events: [
      { eventType: "run_start", capturedAt: "2026-03-31T00:00:00.000Z" },
      { eventType: "run_end", capturedAt: "2026-03-31T00:00:01.000Z" }
    ]
  });
  const invalidMutators = buildInvalidMutators();

  let receiptInvalidUnexpectedPasses = 0;
  for (let i = 0; i < receiptInvalidRuns; i += 1) {
    const receipt = structuredClone(baseReceipt);
    const mutCount = 1 + randInt(4);
    for (let j = 0; j < mutCount; j += 1) {
      invalidMutators[randInt(invalidMutators.length)](receipt);
    }
    if (validateReceiptATP(receipt).ok) {
      receiptInvalidUnexpectedPasses += 1;
    }
  }

  let receiptValidUnexpectedFails = 0;
  for (let i = 0; i < receiptValidRuns; i += 1) {
    const receipt = structuredClone(baseReceipt);
    receipt.correlation_id = `soak:${i}`;
    receipt.event_snapshot.events = [
      ...(receipt.event_snapshot.events ?? []),
      { eventType: `extra_${i}`, capturedAt: "2026-03-31T00:00:02.000Z" }
    ];
    receipt.event_snapshot_hash = hashEventSnapshot(receipt.event_snapshot);
    if (!validateReceiptATP(receipt).ok) {
      receiptValidUnexpectedFails += 1;
    }
  }

  const report = {
    overall: "PASS",
    scenarioCoverage: {
      decisionOutcomes: { covered: ["allow", "approve", "deny"] },
      executionStatuses: { covered: ["executed", "blocked", "expired", "error"] },
      complete: true
    },
    results: [
      {
        runtimeId: "r1",
        requiredLevel: "CLASSIFY_ONLY",
        requiredAtpL1: true,
        passed: true,
        atpL1: { valid: true }
      }
    ]
  };
  const goodContract = {
    requiredOverall: "PASS",
    requiredScenarioCoverage: {
      decisionOutcomes: ["allow"],
      executionStatuses: ["executed"],
      complete: true
    },
    requiredRuntimes: [
      {
        runtimeId: "r1",
        requiredLevel: "CLASSIFY_ONLY",
        requiredAtpL1: true,
        passed: true,
        atpValid: true
      }
    ]
  };

  let contractMalformedUnexpectedPasses = 0;
  for (let i = 0; i < contractMalformedRuns; i += 1) {
    const malformed = {
      requiredOverall: i % 2 === 0 ? "PASS" : 42,
      requiredScenarioCoverage: i % 5 === 0
        ? {}
        : {
            decisionOutcomes: i % 3 === 0 ? [] : "allow",
            executionStatuses: i % 7 === 0 ? "executed" : [],
            complete: i % 11 === 0 ? true : "yes"
          },
      requiredRuntimes: [
        {
          runtimeId: "r1",
          passed: i % 2 === 0 ? "true" : null,
          requiredLevel: i % 3 === 0 ? 123 : null,
          requiredAtpL1: "yes",
          atpValid: "no"
        }
      ]
    };
    if (validateConformanceReport(report, malformed).ok) {
      contractMalformedUnexpectedPasses += 1;
    }
  }
  const contractGoodPass = validateConformanceReport(report, goodContract).ok;

  const payload = JSON.stringify({
    frames: [
      { type: "event", payload: { eventType: "tool_call_requested" } },
      { type: "event", payload: { eventType: "tool_call_executed" } },
      { type: "event", payload: { eventType: "run_end" } }
    ]
  });
  let pathGuardBlocked = 0;
  let pathGuardEscaped = 0;
  for (let i = 0; i < pathGuardRuns; i += 1) {
    const kind = i % 5;
    const name = kind === 0
      ? ".tt-local"
      : kind === 1
        ? "TT-LOCAL"
        : kind === 2
          ? "local-runtime-artifact"
          : kind === 3
            ? "outside-fixture"
            : "frame";
    const filePath = join(tmpdir(), `${name}-${i}.json`);
    await writeFile(filePath, payload);
    try {
      await generateProofReport({
        cwd,
        openclawFramesPath: filePath,
        allowLocalArtifacts: false
      });
      pathGuardEscaped += 1;
    } catch {
      pathGuardBlocked += 1;
    }
  }

  let allowOverridePasses = 0;
  for (let i = 0; i < allowOverrideRuns; i += 1) {
    const filePath = join(tmpdir(), `allow-soak-${i}.json`);
    await writeFile(filePath, payload);
    try {
      const reportOut = await generateProofReport({
        cwd,
        openclawFramesPath: filePath,
        allowLocalArtifacts: true
      });
      if (reportOut?.overall === "PASS") allowOverridePasses += 1;
    } catch {
      // no-op
    }
  }

  const summary = {
    generatedAt: new Date().toISOString(),
    profile: "ATP_SOAK_FUZZ_V1",
    receiptFuzz: {
      invalidRuns: receiptInvalidRuns,
      invalidUnexpectedPasses: receiptInvalidUnexpectedPasses,
      validRuns: receiptValidRuns,
      validUnexpectedFails: receiptValidUnexpectedFails
    },
    contractFuzz: {
      malformedRuns: contractMalformedRuns,
      malformedUnexpectedPasses: contractMalformedUnexpectedPasses,
      goodContractPass: contractGoodPass
    },
    pathGuardFuzz: {
      runs: pathGuardRuns,
      blocked: pathGuardBlocked,
      escaped: pathGuardEscaped
    },
    allowOverride: {
      runs: allowOverrideRuns,
      passes: allowOverridePasses
    },
    durationMs: Math.round(performance.now() - startedAt)
  };

  await mkdir("conformance-kit/artifacts", { recursive: true });
  await writeFile("conformance-kit/artifacts/latest-soak-fuzz.json", JSON.stringify(summary, null, 2));
  console.log(JSON.stringify(summary, null, 2));

  const hasFailures =
    receiptInvalidUnexpectedPasses > 0
    || receiptValidUnexpectedFails > 0
    || contractMalformedUnexpectedPasses > 0
    || !contractGoodPass
    || pathGuardEscaped > 0
    || allowOverridePasses !== allowOverrideRuns;

  if (hasFailures) process.exitCode = 1;
}

main().catch((error) => {
  console.error("conformance-soak-fuzz failed:", error);
  process.exitCode = 1;
});
