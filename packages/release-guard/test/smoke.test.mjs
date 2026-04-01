import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import {
  runCheckCommand,
  runDecideCommand,
  runPublishCommand
} from "../src/release-guard.mjs";

async function createFixturePackage() {
  const dir = await mkdtemp(resolve(tmpdir(), "atp-release-guard-pkg-"));
  await writeFile(
    resolve(dir, "package.json"),
    JSON.stringify(
      {
        name: "@atp/test-release-guard-package",
        version: "0.0.1",
        type: "module",
        files: ["dist", "README.md"],
        scripts: {}
      },
      null,
      2
    )
  );
  await mkdir(resolve(dir, "dist"), { recursive: true });
  await writeFile(resolve(dir, "dist/index.mjs"), "export const ok = true;\n");
  await writeFile(resolve(dir, "README.md"), "# fixture\n");
  return dir;
}

test("check command emits manifest and digest evidence", async () => {
  const packageDir = await createFixturePackage();
  const reportPath = resolve(packageDir, ".atp-check.json");
  const result = await runCheckCommand(["--package-dir", packageDir, "--out", reportPath]);
  assert.equal(result.ok, true);
  assert.equal(typeof result.release.tarball_sha256, "string");
  assert.equal(result.release.tarball_sha256.length, 64);
  assert.equal(typeof result.release.manifest_sha256, "string");
  assert.equal(result.release.manifest_sha256.length, 64);
  const saved = JSON.parse(await readFile(reportPath, "utf8"));
  assert.equal(saved.ok, true);
  assert.ok(Array.isArray(saved.release.manifest_paths));
});

test("check command fails on blocked path prefixes", async () => {
  const packageDir = await createFixturePackage();
  const report = await runCheckCommand(["--package-dir", packageDir, "--blocked-paths", "dist/"]);
  assert.equal(report.ok, false);
  assert.ok(report.policy.violations.length > 0);
});

test("check command fails on blocked path glob patterns", async () => {
  const packageDir = await createFixturePackage();
  await writeFile(resolve(packageDir, "dist/index.js.map"), "{\"version\":3}\n");
  const report = await runCheckCommand(["--package-dir", packageDir, "--blocked-paths", "**/*.map"]);
  assert.equal(report.ok, false);
  assert.ok(report.policy.violations.includes("dist/index.js.map"));
});

test("decide command emits deny when check report is not ok", async () => {
  const packageDir = await createFixturePackage();
  const checkPath = resolve(packageDir, ".atp-check.json");
  const decidePath = resolve(packageDir, ".atp-decision.json");
  await writeFile(
    checkPath,
    JSON.stringify(
      {
        ok: false,
        package: { name: "@atp/example", version: "1.0.0" },
        release: {
          tarball_sha256: "a".repeat(64),
          manifest_sha256: "b".repeat(64),
          manifest_paths: ["dist/index.mjs"]
        }
      },
      null,
      2
    )
  );
  const decision = await runDecideCommand(["--check-report", checkPath, "--out", decidePath]);
  assert.equal(decision.ok, false);
  assert.equal(decision.decision.outcome, "deny");
  const saved = JSON.parse(await readFile(decidePath, "utf8"));
  assert.equal(saved.decision.outcome, "deny");
});

test("publish command rejects deny decision", async () => {
  const packageDir = await createFixturePackage();
  const checkPath = resolve(packageDir, ".atp-check.json");
  const decisionPath = resolve(packageDir, ".atp-decision.json");
  await writeFile(
    checkPath,
    JSON.stringify(
      {
        ok: true,
        package: { name: "@atp/example", version: "1.0.0" },
        release: {
          tarball_sha256: "a".repeat(64),
          manifest_sha256: "b".repeat(64),
          manifest_paths: ["dist/index.mjs"]
        },
        policy: { blocked_paths: [], violations: [] }
      },
      null,
      2
    )
  );
  await writeFile(
    decisionPath,
    JSON.stringify(
      {
        intent: {
          intent_id: "TI-123",
          context: {
            package_name: "@atp/example",
            package_version: "1.0.0",
            expected_tarball_sha256: "a".repeat(64),
            expected_manifest_sha256: "b".repeat(64)
          }
        },
        decision: { decision_id: "TD-123", intent_id: "TI-123", outcome: "deny" }
      },
      null,
      2
    )
  );
  await assert.rejects(
    () => runPublishCommand(["--package-dir", packageDir, "--check-report", checkPath, "--decision", decisionPath]),
    /blocked by deny decision/i
  );
});

test("publish command enforces explicit approval for approve decisions", async () => {
  const packageDir = await createFixturePackage();
  const checkPath = resolve(packageDir, ".atp-check.json");
  const decisionPath = resolve(packageDir, ".atp-decision.json");
  await writeFile(
    checkPath,
    JSON.stringify(
      {
        ok: true,
        package: { name: "@atp/example", version: "1.0.0" },
        release: {
          tarball_sha256: "a".repeat(64),
          manifest_sha256: "b".repeat(64),
          manifest_paths: ["dist/index.mjs"]
        },
        policy: { blocked_paths: [], violations: [] }
      },
      null,
      2
    )
  );
  await writeFile(
    decisionPath,
    JSON.stringify(
      {
        intent: {
          intent_id: "TI-123",
          context: {
            package_name: "@atp/example",
            package_version: "1.0.0",
            expected_tarball_sha256: "a".repeat(64),
            expected_manifest_sha256: "b".repeat(64)
          }
        },
        decision: { decision_id: "TD-123", intent_id: "TI-123", outcome: "approve" }
      },
      null,
      2
    )
  );
  await assert.rejects(
    () => runPublishCommand(["--package-dir", packageDir, "--check-report", checkPath, "--decision", decisionPath]),
    /requires explicit --approved/i
  );
});

test("publish command emits receipt bound to check digests", async () => {
  const packageDir = await createFixturePackage();
  const checkPath = resolve(packageDir, ".atp-check.json");
  const decisionPath = resolve(packageDir, ".atp-decision.json");
  const outPath = resolve(packageDir, ".atp-publish.json");

  await writeFile(
    checkPath,
    JSON.stringify(
      {
        ok: true,
        package: { name: "@atp/example", version: "1.0.0" },
        release: {
          tarball_sha256: "a".repeat(64),
          manifest_sha256: "b".repeat(64),
          manifest_paths: ["dist/index.mjs"]
        },
        policy: { blocked_paths: [], violations: [] }
      },
      null,
      2
    )
  );
  await writeFile(
    decisionPath,
    JSON.stringify(
      {
        intent: {
          intent_id: "TI-123",
          context: {
            package_name: "@atp/example",
            package_version: "1.0.0",
            expected_tarball_sha256: "a".repeat(64),
            expected_manifest_sha256: "b".repeat(64)
          }
        },
        decision: { decision_id: "TD-123", intent_id: "TI-123", outcome: "allow" }
      },
      null,
      2
    )
  );

  const result = await runPublishCommand([
    "--package-dir",
    packageDir,
    "--check-report",
    checkPath,
    "--decision",
    decisionPath,
    "--out",
    outPath
  ]);
  assert.equal(result.ok, true);
  assert.equal(result.receipt.receipt_id, "TR-123");
  assert.equal(result.receipt.event_snapshot.release.tarball_sha256, "a".repeat(64));
  assert.equal(result.receipt.event_snapshot.release.manifest_sha256, "b".repeat(64));
  const saved = JSON.parse(await readFile(outPath, "utf8"));
  assert.equal(saved.receipt.decision_id, "TD-123");
});

test("publish command rejects digest mismatch between decision intent and check report", async () => {
  const packageDir = await createFixturePackage();
  const checkPath = resolve(packageDir, ".atp-check.json");
  const decisionPath = resolve(packageDir, ".atp-decision.json");
  await writeFile(
    checkPath,
    JSON.stringify(
      {
        ok: true,
        package: { name: "@atp/example", version: "1.0.0" },
        release: {
          tarball_sha256: "a".repeat(64),
          manifest_sha256: "b".repeat(64),
          manifest_paths: ["dist/index.mjs"]
        },
        policy: { blocked_paths: [], violations: [] }
      },
      null,
      2
    )
  );
  await writeFile(
    decisionPath,
    JSON.stringify(
      {
        intent: {
          intent_id: "TI-456",
          context: {
            package_name: "@atp/example",
            package_version: "1.0.0",
            expected_tarball_sha256: "c".repeat(64),
            expected_manifest_sha256: "b".repeat(64)
          }
        },
        decision: { decision_id: "TD-456", intent_id: "TI-456", outcome: "allow" }
      },
      null,
      2
    )
  );
  await assert.rejects(
    () => runPublishCommand(["--package-dir", packageDir, "--check-report", checkPath, "--decision", decisionPath]),
    /tarball digest does not match/i
  );
});

test("publish command rejects malformed decision payload intent linkage", async () => {
  const packageDir = await createFixturePackage();
  const checkPath = resolve(packageDir, ".atp-check.json");
  const decisionPath = resolve(packageDir, ".atp-decision.json");
  await writeFile(
    checkPath,
    JSON.stringify(
      {
        ok: true,
        package: { name: "@atp/example", version: "1.0.0" },
        release: {
          tarball_sha256: "a".repeat(64),
          manifest_sha256: "b".repeat(64),
          manifest_paths: ["dist/index.mjs"]
        },
        policy: { blocked_paths: [], violations: [] }
      },
      null,
      2
    )
  );
  await writeFile(
    decisionPath,
    JSON.stringify(
      {
        intent: {
          intent_id: "TI-111",
          context: {
            package_name: "@atp/example",
            package_version: "1.0.0",
            expected_tarball_sha256: "a".repeat(64),
            expected_manifest_sha256: "b".repeat(64)
          }
        },
        decision: { decision_id: "TD-111", intent_id: "TI-999", outcome: "allow" }
      },
      null,
      2
    )
  );
  await assert.rejects(
    () => runPublishCommand(["--package-dir", packageDir, "--check-report", checkPath, "--decision", decisionPath]),
    /decision.intent_id must match intent.intent_id/i
  );
});

test("publish command rejects check report with policy violations even if ok is true", async () => {
  const packageDir = await createFixturePackage();
  const checkPath = resolve(packageDir, ".atp-check.json");
  const decisionPath = resolve(packageDir, ".atp-decision.json");
  await writeFile(
    checkPath,
    JSON.stringify(
      {
        ok: true,
        package: { name: "@atp/example", version: "1.0.0" },
        release: {
          tarball_sha256: "a".repeat(64),
          manifest_sha256: "b".repeat(64),
          manifest_paths: ["dist/index.mjs"]
        },
        policy: { blocked_paths: ["dist/"], violations: ["dist/index.mjs"] }
      },
      null,
      2
    )
  );
  await writeFile(
    decisionPath,
    JSON.stringify(
      {
        intent: {
          intent_id: "TI-222",
          context: {
            package_name: "@atp/example",
            package_version: "1.0.0",
            expected_tarball_sha256: "a".repeat(64),
            expected_manifest_sha256: "b".repeat(64)
          }
        },
        decision: { decision_id: "TD-222", intent_id: "TI-222", outcome: "allow" }
      },
      null,
      2
    )
  );
  await assert.rejects(
    () => runPublishCommand(["--package-dir", packageDir, "--check-report", checkPath, "--decision", decisionPath]),
    /did not pass policy gate/i
  );
});
