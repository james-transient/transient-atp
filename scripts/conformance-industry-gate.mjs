import { runIndustryGate } from "../packages/conformance-cli/src/lib/industry-gate.mjs";

function parseArgs(argv) {
  const args = {
    industryContractPath: "conformance-kit/expected/industry-gate.json"
  };
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token === "--industry-contract") {
      args.industryContractPath = String(argv[i + 1] ?? args.industryContractPath);
    }
  }
  return args;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const result = await runIndustryGate({
    industryContractPath: args.industryContractPath
  });
  console.log(JSON.stringify(result, null, 2));
  if (!result.ok) process.exitCode = 1;
}

main().catch((error) => {
  console.error("conformance-industry-gate failed:", error);
  process.exitCode = 1;
});
