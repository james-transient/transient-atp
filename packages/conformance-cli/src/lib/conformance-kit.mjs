import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { generateProofReport } from "./proof-harness.mjs";
import { validateConformanceReport } from "./contract-validate.mjs";

export async function runConformanceKit({
  cwd = process.cwd(),
  contractPath = "conformance-kit/expected/contract.json",
  reportOutPath = "conformance-kit/artifacts/latest-report.json",
  validationOutPath = "conformance-kit/artifacts/latest-validation.json",
  openclawFramesPath = "conformance-kit/fixtures/openclaw/gateway-frames-live.json"
} = {}) {
  const contractAbs = resolve(cwd, contractPath);
  const reportAbs = resolve(cwd, reportOutPath);
  const validationAbs = resolve(cwd, validationOutPath);
  const artifactsDir = resolve(cwd, "conformance-kit/artifacts");

  const contract = JSON.parse(await readFile(contractAbs, "utf8"));
  const report = await generateProofReport({ cwd, openclawFramesPath });
  const validation = validateConformanceReport(report, contract);

  await mkdir(artifactsDir, { recursive: true });
  await writeFile(reportAbs, JSON.stringify(report, null, 2));
  await writeFile(
    validationAbs,
    JSON.stringify(
      {
        generatedAt: new Date().toISOString(),
        ok: validation.ok,
        failures: validation.failures,
        reportPath: reportOutPath,
        contractPath
      },
      null,
      2
    )
  );

  return {
    ok: validation.ok,
    reportPath: reportOutPath,
    validationPath: validationOutPath,
    failureCount: validation.failures.length
  };
}
