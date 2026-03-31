import { generateProofReport } from "../packages/conformance-cli/src/lib/proof-harness.mjs";

function parseArgs(argv) {
  const args = {
    openclawFramesPath: "conformance-kit/fixtures/openclaw/gateway-frames-live.json",
    allowLocalArtifacts: false
  };
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token === "--openclaw-frames") args.openclawFramesPath = String(argv[i + 1] ?? args.openclawFramesPath);
    if (token === "--allow-local-artifacts") args.allowLocalArtifacts = true;
  }
  return args;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const report = await generateProofReport(args);
  console.log(JSON.stringify(report, null, 2));
}

main().catch((error) => {
  console.error("conformance-proof-harness failed:", error);
  process.exitCode = 1;
});
