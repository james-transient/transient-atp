import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { generateProofReport } from "./proof-harness.mjs";
import { validateConformanceReport } from "./contract-validate.mjs";
import { runReleaseGovernanceProfile, validateReleaseGovernanceReport } from "./release-governance.mjs";

export async function runConformanceKit({
  cwd = process.cwd(),
  contractPath = "conformance-kit/expected/contract.json",
  releaseGovernanceContractPath = "conformance-kit/expected/release-governance.contract.json",
  reportOutPath = "conformance-kit/artifacts/latest-report.json",
  validationOutPath = "conformance-kit/artifacts/latest-validation.json",
  releaseGovernanceOutPath = "conformance-kit/artifacts/latest-release-governance.json",
  openclawFramesPath = "conformance-kit/fixtures/openclaw/gateway-frames-live.json",
  runtimesFixturePath
} = {}) {
  const contractAbs = resolve(cwd, contractPath);
  const releaseGovernanceContractAbs = resolve(cwd, releaseGovernanceContractPath);
  const reportAbs = resolve(cwd, reportOutPath);
  const validationAbs = resolve(cwd, validationOutPath);
  const artifactsDir = resolve(cwd, "conformance-kit/artifacts");

  const contract = JSON.parse(await readFile(contractAbs, "utf8"));
  const releaseGovernanceContract = JSON.parse(await readFile(releaseGovernanceContractAbs, "utf8"));
  const report = await generateProofReport({ cwd, openclawFramesPath, runtimesFixturePath });
  const validation = validateConformanceReport(report, contract);
  const releaseProfileRun = await runReleaseGovernanceProfile({ cwd, reportOutPath: releaseGovernanceOutPath });
  const releaseProfileReport = JSON.parse(await readFile(resolve(cwd, releaseGovernanceOutPath), "utf8"));
  const releaseProfileValidation = validateReleaseGovernanceReport(releaseProfileReport, releaseGovernanceContract);
  const overallOk = validation.ok && releaseProfileValidation.ok && releaseProfileRun.ok;

  await mkdir(artifactsDir, { recursive: true });
  await writeFile(reportAbs, JSON.stringify(report, null, 2));
  await writeFile(
    validationAbs,
    JSON.stringify(
      {
        generatedAt: new Date().toISOString(),
        ok: overallOk,
        failures: validation.failures,
        releaseGovernance: {
          ok: releaseProfileValidation.ok,
          failures: releaseProfileValidation.failures,
          reportPath: releaseGovernanceOutPath,
          contractPath: releaseGovernanceContractPath
        },
        reportPath: reportOutPath,
        contractPath
      },
      null,
      2
    )
  );

  return {
    ok: overallOk,
    reportPath: reportOutPath,
    validationPath: validationOutPath,
    failureCount: validation.failures.length + releaseProfileValidation.failures.length
  };
}
