import { runReleaseGovernanceProfile } from "../packages/conformance-cli/src/lib/release-governance.mjs";

async function main() {
  const result = await runReleaseGovernanceProfile();
  console.log(JSON.stringify(result, null, 2));
  if (!result.ok) process.exitCode = 1;
}

main().catch((error) => {
  console.error("conformance-release-governance failed:", error);
  process.exitCode = 1;
});
