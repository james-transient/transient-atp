import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { runConformanceKit } from "./conformance-kit.mjs";
import { createSampleReceipt, validateReceiptATP } from "./receipt.mjs";

function hashText(value) {
  return createHash("sha256").update(value).digest("hex");
}

function runVerifierCommand(command, cwd) {
  if (!command) return { configured: false, ok: true, exitCode: 0, output: "" };
  const result = spawnSync("sh", ["-lc", command], { cwd, encoding: "utf8" });
  return {
    configured: true,
    ok: result.status === 0,
    exitCode: Number(result.status ?? 1),
    output: `${String(result.stdout ?? "")}\n${String(result.stderr ?? "")}`.trim()
  };
}

function expectedFailure(result, code) {
  return result.ok === false && result.issues.some((issue) => issue?.code === code);
}

function runNegativeTests() {
  const base = createSampleReceipt({
    runId: "neg-run",
    sessionId: "neg-session",
    runStatus: "success",
    haltReason: "none",
    events: [
      { eventType: "run_start", capturedAt: "2026-03-31T00:00:00.000Z" },
      { eventType: "run_end", capturedAt: "2026-03-31T00:00:01.000Z" }
    ]
  });
  const cases = [
    { id: "NEG-ID-FORMAT", expectedCode: "receipt_invalid_id_format", receipt: { ...base, receipt_id: "TR-abc" } },
    { id: "NEG-SNAPSHOT-HASH", expectedCode: "receipt_invalid_snapshot_hash", receipt: { ...base, event_snapshot_hash: "deadbeef" } },
    {
      id: "NEG-TIMESTAMP-ORDER",
      expectedCode: "receipt_invalid_timestamp_order",
      receipt: {
        ...base,
        occurred_at: "2026-03-31T00:00:03.000Z",
        received_at: "2026-03-31T00:00:02.000Z",
        sealed_at: "2026-03-31T00:00:01.000Z"
      }
    },
    { id: "NEG-MISSING-CORRELATION", expectedCode: "receipt_missing_required_field", receipt: { ...base, correlation_id: "" } }
  ];
  return cases.map((entry) => {
    const result = validateReceiptATP(entry.receipt);
    return {
      testId: entry.id,
      ok: expectedFailure(result, entry.expectedCode),
      expectedCode: entry.expectedCode,
      observedCodes: result.issues.map((issue) => issue.code)
    };
  });
}

function checkInteropMatrix(matrix, { minimumDefinedTargets, minimumImplementedTargets }) {
  const entries = Array.isArray(matrix?.targets) ? matrix.targets : [];
  const implemented = entries.filter((entry) => entry?.status === "implemented");
  const parsedMinimumDefinedTargets = Number(minimumDefinedTargets ?? 0);
  const parsedMinimumImplementedTargets = Number(minimumImplementedTargets ?? 0);
  const thresholdsValid =
    Number.isInteger(parsedMinimumDefinedTargets)
    && Number.isInteger(parsedMinimumImplementedTargets)
    && parsedMinimumDefinedTargets >= 1
    && parsedMinimumImplementedTargets >= 1
    && parsedMinimumImplementedTargets <= parsedMinimumDefinedTargets;
  return {
    totalTargets: entries.length,
    implementedTargets: implemented.length,
    minimumDefinedTargets: parsedMinimumDefinedTargets,
    minimumImplementedTargets: parsedMinimumImplementedTargets,
    thresholdsValid,
    ok:
      thresholdsValid
      && entries.length >= parsedMinimumDefinedTargets
      && implemented.length >= parsedMinimumImplementedTargets
  };
}

export async function runIndustryGate({
  cwd = process.cwd(),
  industryContractPath = "conformance-kit/expected/industry-gate.json",
  interopPath = "conformance-kit/expected/interop-matrix.json",
  reportPath = "conformance-kit/artifacts/latest-report.json",
  validationPath = "conformance-kit/artifacts/latest-validation.json",
  digestPath = "conformance-kit/artifacts/latest-digests.json",
  industryPath = "conformance-kit/artifacts/latest-industry-gate.json"
} = {}) {
  const industryContract = JSON.parse(await readFile(resolve(cwd, industryContractPath), "utf8"));
  const interopMatrix = JSON.parse(await readFile(resolve(cwd, interopPath), "utf8"));

  await runConformanceKit({ cwd });

  const reportRaw = await readFile(resolve(cwd, reportPath), "utf8");
  const validationRaw = await readFile(resolve(cwd, validationPath), "utf8");
  const report = JSON.parse(reportRaw);
  const validation = JSON.parse(validationRaw);
  const checks = [];

  checks.push({
    id: "BASE-CONFORMANCE-KIT",
    ok: validation.ok === true && report.overall === "PASS",
    details: "Base conformance kit returns PASS."
  });

  const negativeResults = runNegativeTests();
  checks.push({
    id: "NEGATIVE-TESTS",
    ok: negativeResults.every((entry) => entry.ok),
    details: "Negative ATP invariant tests must fail with expected reason codes.",
    results: negativeResults
  });

  const interopCheck = checkInteropMatrix(interopMatrix, {
    minimumDefinedTargets: Number(industryContract?.minimumDefinedTargets ?? industryContract?.minimumInteropTargets ?? 1),
    minimumImplementedTargets: Number(industryContract?.minimumImplementedTargets ?? 1)
  });
  checks.push({
    id: "INTEROP-MATRIX",
    ok: interopCheck.ok,
    details: interopCheck.thresholdsValid
      ? "Interop target matrix meets minimum breadth."
      : "Interop matrix thresholds are invalid; must be non-negative integers.",
    result: interopCheck
  });

  const digests = {
    generatedAt: new Date().toISOString(),
    files: [
      { path: reportPath, sha256: hashText(reportRaw) },
      { path: validationPath, sha256: hashText(validationRaw) }
    ]
  };
  await mkdir(resolve(cwd, "conformance-kit/artifacts"), { recursive: true });
  await writeFile(resolve(cwd, digestPath), JSON.stringify(digests, null, 2));
  checks.push({
    id: "ARTIFACT-DIGESTS",
    ok: true,
    details: "Artifact SHA-256 digests generated.",
    result: { path: digestPath }
  });

  const verifierResult = runVerifierCommand(process.env.ATP_INDEPENDENT_VERIFIER_CMD, cwd);
  const verifierRequirementRaw = industryContract?.requireIndependentVerifier;
  const verifierRequirementValid = typeof verifierRequirementRaw === "boolean";
  const requireIndependentVerifier = verifierRequirementRaw === true;
  const verifierOk = verifierRequirementValid
    ? (requireIndependentVerifier ? verifierResult.configured && verifierResult.ok : verifierResult.ok)
    : false;
  checks.push({
    id: "INDEPENDENT-VERIFIER-HOOK",
    ok: verifierOk,
    details: !verifierRequirementValid
      ? "Invalid contract: requireIndependentVerifier must be boolean."
      : verifierResult.configured
        ? "Independent verifier command executed."
        : requireIndependentVerifier
          ? "Independent verifier is required by contract but not configured."
          : "No verifier command configured; hook available.",
    result: {
      ...verifierResult,
      required: requireIndependentVerifier,
      requirementValid: verifierRequirementValid
    }
  });

  const failedChecks = checks.filter((check) => check.ok !== true).map((check) => check.id);
  const industryReport = {
    generatedAt: new Date().toISOString(),
    profile: "ATP_1_0_INDUSTRY_GATE",
    overall: failedChecks.length === 0 ? "PASS" : "FAIL",
    checks,
    failedChecks
  };
  await writeFile(resolve(cwd, industryPath), JSON.stringify(industryReport, null, 2));
  return {
    ok: failedChecks.length === 0,
    overall: industryReport.overall,
    failedChecks,
    industryReportPath: industryPath,
    digestPath
  };
}
