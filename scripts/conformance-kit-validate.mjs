import { runConformanceKit } from "../packages/conformance-cli/src/lib/conformance-kit.mjs";

async function main() {
  const result = await runConformanceKit();
  console.log(JSON.stringify(result, null, 2));
  if (!result.ok) process.exitCode = 1;
}

main().catch((error) => {
  console.error("conformance-kit validation failed:", error);
  process.exitCode = 1;
});
