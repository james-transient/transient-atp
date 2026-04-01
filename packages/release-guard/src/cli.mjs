#!/usr/bin/env node
import {
  runCheckCommand,
  runDecideCommand,
  runPublishCommand
} from "./release-guard.mjs";

function usage() {
  console.log(`atp-release-guard commands:
  check --package-dir <path> [--blocked-paths "<prefix1,prefix2>"] [--out <path>]
  decide --check-report <path> [--require-approval] [--out <path>]
  publish --check-report <path> --decision <path> [--approved] [--execute] [--package-dir <path>] [--out <path>]
`);
}

async function main() {
  const argv = process.argv.slice(2);
  const command = argv[0];
  if (!command || command === "-h" || command === "--help") {
    usage();
    return;
  }

  const args = argv.slice(1);
  if (command === "check") {
    const result = await runCheckCommand(args);
    console.log(JSON.stringify(result, null, 2));
    if (!result.ok) process.exitCode = 1;
    return;
  }
  if (command === "decide") {
    const result = await runDecideCommand(args);
    console.log(JSON.stringify(result, null, 2));
    if (!result.ok) process.exitCode = 1;
    return;
  }
  if (command === "publish") {
    const result = await runPublishCommand(args);
    console.log(JSON.stringify(result, null, 2));
    if (!result.ok) process.exitCode = 1;
    return;
  }

  throw new Error(`Unknown command '${command}'`);
}

main().catch((error) => {
  console.error("atp-release-guard failed:", error);
  process.exitCode = 1;
});
