#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { generateProofReport } from "./lib/proof-harness.mjs";
import { validateConformanceReport } from "./lib/contract-validate.mjs";
import { runConformanceKit } from "./lib/conformance-kit.mjs";
import { runIndustryGate } from "./lib/industry-gate.mjs";

function parseArg(argv, flag, fallback = undefined) {
  const idx = argv.indexOf(flag);
  if (idx === -1) return fallback;
  return argv[idx + 1] ?? fallback;
}

function parseBooleanFlag(argv, flag) {
  return argv.includes(flag);
}

function usage() {
  console.log(`atp-conformance commands:
  run [--openclaw-frames <path>] [--allow-local-artifacts]
  validate --contract <path> --report <path>
  kit
  industry
`);
}

async function main() {
  const argv = process.argv.slice(2);
  const command = argv[0];

  if (!command || command === "-h" || command === "--help") {
    usage();
    return;
  }

  if (command === "run") {
    const report = await generateProofReport({
      openclawFramesPath: parseArg(argv, "--openclaw-frames", "conformance-kit/fixtures/openclaw/gateway-frames-live.json"),
      allowLocalArtifacts: parseBooleanFlag(argv, "--allow-local-artifacts")
    });
    console.log(JSON.stringify(report, null, 2));
    return;
  }

  if (command === "validate") {
    const contractPath = parseArg(argv, "--contract");
    const reportPath = parseArg(argv, "--report");
    if (!contractPath || !reportPath) {
      throw new Error("validate requires --contract and --report");
    }
    const contract = JSON.parse(await readFile(resolve(process.cwd(), contractPath), "utf8"));
    const report = JSON.parse(await readFile(resolve(process.cwd(), reportPath), "utf8"));
    const result = validateConformanceReport(report, contract);
    console.log(JSON.stringify(result, null, 2));
    if (!result.ok) process.exitCode = 1;
    return;
  }

  if (command === "kit") {
    const result = await runConformanceKit();
    console.log(JSON.stringify(result, null, 2));
    if (!result.ok) process.exitCode = 1;
    return;
  }

  if (command === "industry") {
    const result = await runIndustryGate({
      industryContractPath: parseArg(argv, "--industry-contract", "conformance-kit/expected/industry-gate.json")
    });
    console.log(JSON.stringify(result, null, 2));
    if (!result.ok) process.exitCode = 1;
    return;
  }

  throw new Error(`Unknown command '${command}'`);
}

main().catch((error) => {
  console.error("atp-conformance failed:", error);
  process.exitCode = 1;
});
