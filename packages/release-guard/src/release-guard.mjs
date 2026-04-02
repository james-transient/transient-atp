import { spawnSync } from "node:child_process";
import { createHash, randomInt } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { generateSigningKeyPair, signReceipt } from "@atp/spec";

function stableStringify(value) {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  if (value && typeof value === "object") {
    const keys = Object.keys(value).sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function sha256Hex(input) {
  return createHash("sha256").update(input).digest("hex");
}

function nowIso() {
  return new Date().toISOString();
}

function numericId() {
  return `${Date.now()}${randomInt(1000, 9999)}`;
}

function parseArg(argv, flag, fallback = undefined) {
  const idx = argv.indexOf(flag);
  if (idx === -1) return fallback;
  return argv[idx + 1] ?? fallback;
}

function parseFlag(argv, flag) {
  return argv.includes(flag);
}

function parseBlockedPaths(argValue) {
  if (!argValue) return [];
  return String(argValue)
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function isHexSha256(value) {
  return typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
}

function escapeRegex(value) {
  return value.replace(/[.+?^${}()|[\]\\]/g, "\\$&");
}

function globToRegex(pattern) {
  const placeholder = "\u0000DOUBLE_STAR\u0000";
  const withPlaceholders = pattern.replace(/\*\*/g, placeholder);
  const escaped = escapeRegex(withPlaceholders);
  const singleStar = escaped.replace(/\*/g, "[^/]*");
  const doubleStar = singleStar.replaceAll(placeholder, ".*");
  return new RegExp(`^${doubleStar}$`);
}

function pathMatchesPolicy(path, policyPattern) {
  const pattern = String(policyPattern ?? "");
  if (!pattern) return false;
  if (pattern.includes("*")) {
    return globToRegex(pattern).test(path);
  }
  return String(path).startsWith(pattern);
}

function validateCheckReport(checkReport) {
  const failures = [];
  if (!checkReport || typeof checkReport !== "object") failures.push("check report must be an object");
  if (typeof checkReport?.package?.name !== "string" || checkReport.package.name.trim().length === 0) {
    failures.push("check report package.name is required");
  }
  if (typeof checkReport?.package?.version !== "string" || checkReport.package.version.trim().length === 0) {
    failures.push("check report package.version is required");
  }
  if (!isHexSha256(checkReport?.release?.tarball_sha256)) failures.push("check report release.tarball_sha256 must be 64-hex");
  if (!isHexSha256(checkReport?.release?.manifest_sha256)) failures.push("check report release.manifest_sha256 must be 64-hex");
  if (!Array.isArray(checkReport?.release?.manifest_paths)) failures.push("check report release.manifest_paths must be an array");
  if (checkReport?.policy && !Array.isArray(checkReport.policy.violations)) {
    failures.push("check report policy.violations must be an array when policy exists");
  }
  return { ok: failures.length === 0, failures };
}

function validateDecisionPayload(decisionPayload) {
  const failures = [];
  if (!decisionPayload || typeof decisionPayload !== "object") failures.push("decision payload must be an object");
  if (typeof decisionPayload?.intent?.intent_id !== "string" || !/^TI-\d+$/.test(decisionPayload.intent.intent_id)) {
    failures.push("decision payload intent.intent_id must match TI-<numeric>");
  }
  if (typeof decisionPayload?.decision?.decision_id !== "string" || !/^TD-\d+$/.test(decisionPayload.decision.decision_id)) {
    failures.push("decision payload decision.decision_id must match TD-<numeric>");
  }
  if (String(decisionPayload?.decision?.intent_id ?? "") !== String(decisionPayload?.intent?.intent_id ?? "")) {
    failures.push("decision payload decision.intent_id must match intent.intent_id");
  }
  const outcome = String(decisionPayload?.decision?.outcome ?? "");
  if (!["allow", "approve", "deny"].includes(outcome)) {
    failures.push("decision payload decision.outcome must be allow, approve, or deny");
  }
  return { ok: failures.length === 0, failures };
}

async function writeOutput(path, payload) {
  if (!path) return;
  await writeFile(resolve(process.cwd(), path), JSON.stringify(payload, null, 2));
}

async function collectPackData(packageDir) {
  const tempDir = await mkdtemp(join(tmpdir(), "atp-release-guard-"));
  try {
    const pack = spawnSync(
      "npm",
      ["pack", "--json", "--pack-destination", tempDir],
      { cwd: packageDir, encoding: "utf8" }
    );
    if (pack.status !== 0) {
      throw new Error(`npm pack failed: ${String(pack.stderr ?? pack.stdout ?? "").trim()}`);
    }
    const parsed = JSON.parse(String(pack.stdout ?? "[]"));
    const first = parsed?.[0];
    if (!first || typeof first !== "object") {
      throw new Error("npm pack did not produce package metadata");
    }
    const tarballPath = resolve(tempDir, String(first.filename));
    const tarballBuffer = await readFile(tarballPath);
    const tarballSha256 = sha256Hex(tarballBuffer);
    const manifestPaths = (Array.isArray(first.files) ? first.files : [])
      .map((entry) => String(entry?.path ?? ""))
      .filter(Boolean)
      .sort();
    const manifestSha256 = sha256Hex(manifestPaths.join("\n"));

    return {
      packageName: String(first.name ?? ""),
      packageVersion: String(first.version ?? ""),
      tarballSha256,
      manifestSha256,
      manifestPaths
    };
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
}

export async function runCheckCommand(argv = process.argv.slice(2)) {
  const packageDir = resolve(process.cwd(), parseArg(argv, "--package-dir", "."));
  const blockedPaths = parseBlockedPaths(parseArg(argv, "--blocked-paths", ""));
  const outputPath = parseArg(argv, "--out");
  const packData = await collectPackData(packageDir);
  const blockedPathHits = packData.manifestPaths.filter((item) =>
    blockedPaths.some((pattern) => pathMatchesPolicy(item, pattern))
  );

  const report = {
    generatedAt: nowIso(),
    mode: "check",
    ok: blockedPathHits.length === 0,
    package: {
      name: packData.packageName,
      version: packData.packageVersion
    },
    release: {
      tarball_sha256: packData.tarballSha256,
      manifest_sha256: packData.manifestSha256,
      manifest_paths: packData.manifestPaths
    },
    policy: {
      blocked_paths: blockedPaths,
      violations: blockedPathHits
    }
  };

  await writeOutput(outputPath, report);
  return report;
}

export async function runDecideCommand(argv = process.argv.slice(2)) {
  const checkReportPath = parseArg(argv, "--check-report");
  const requireApproval = parseFlag(argv, "--require-approval");
  const outputPath = parseArg(argv, "--out");
  if (!checkReportPath) {
    throw new Error("decide requires --check-report");
  }
  const checkReport = JSON.parse(await readFile(resolve(process.cwd(), checkReportPath), "utf8"));
  const checkShape = validateCheckReport(checkReport);
  if (!checkShape.ok) {
    throw new Error(`invalid check report: ${checkShape.failures.join("; ")}`);
  }
  const id = numericId();
  const occurredAt = nowIso();
  const hasViolations = (checkReport?.policy?.violations ?? []).length > 0;
  const policyPass = checkReport.ok === true && !hasViolations;
  const outcome = policyPass ? (requireApproval ? "approve" : "allow") : "deny";

  const intent = {
    intent_id: `TI-${id}`,
    actor_id: "release-guard",
    connector: "@atp/release-guard",
    action: "registry.publish",
    action_class: "write_high",
    target: { registry: "npm" },
    context: {
      package_name: checkReport?.package?.name,
      package_version: checkReport?.package?.version,
      expected_tarball_sha256: checkReport?.release?.tarball_sha256,
      expected_manifest_sha256: checkReport?.release?.manifest_sha256
    },
    governance_profile: "release_governance_profile",
    requested_at: occurredAt
  };

  const decision = {
    decision_id: `TD-${id}`,
    intent_id: intent.intent_id,
    outcome,
    reason_code: policyPass ? (requireApproval ? "approval_required_by_policy" : "policy_pass") : "policy_check_failed",
    decided_at: occurredAt
  };

  const result = {
    generatedAt: occurredAt,
    mode: "decide",
    ok: outcome !== "deny",
    intent,
    decision
  };
  await writeOutput(outputPath, result);
  return result;
}

export async function runPublishCommand(argv = process.argv.slice(2)) {
  const packageDir = resolve(process.cwd(), parseArg(argv, "--package-dir", "."));
  const checkReportPath = parseArg(argv, "--check-report");
  const decisionPath = parseArg(argv, "--decision");
  const execute = parseFlag(argv, "--execute");
  const approved = parseFlag(argv, "--approved");
  const outputPath = parseArg(argv, "--out");
  if (!checkReportPath || !decisionPath) {
    throw new Error("publish requires --check-report and --decision");
  }

  const checkReport = JSON.parse(await readFile(resolve(process.cwd(), checkReportPath), "utf8"));
  const decisionPayload = JSON.parse(await readFile(resolve(process.cwd(), decisionPath), "utf8"));
  const checkShape = validateCheckReport(checkReport);
  if (!checkShape.ok) {
    throw new Error(`invalid check report: ${checkShape.failures.join("; ")}`);
  }
  const decisionShape = validateDecisionPayload(decisionPayload);
  if (!decisionShape.ok) {
    throw new Error(`invalid decision payload: ${decisionShape.failures.join("; ")}`);
  }
  const intent = decisionPayload.intent;
  const decision = decisionPayload.decision;
  const outcome = String(decision?.outcome ?? "");
  const hasViolations = (checkReport?.policy?.violations ?? []).length > 0;
  if (checkReport.ok !== true || hasViolations) {
    throw new Error("publish blocked: check report did not pass policy gate");
  }
  if (String(intent?.context?.package_name ?? "") !== String(checkReport?.package?.name ?? "")) {
    throw new Error("publish blocked: intent package_name does not match check report");
  }
  if (String(intent?.context?.package_version ?? "") !== String(checkReport?.package?.version ?? "")) {
    throw new Error("publish blocked: intent package_version does not match check report");
  }
  if (String(intent?.context?.expected_tarball_sha256 ?? "") !== String(checkReport?.release?.tarball_sha256 ?? "")) {
    throw new Error("publish blocked: intent tarball digest does not match check report");
  }
  if (String(intent?.context?.expected_manifest_sha256 ?? "") !== String(checkReport?.release?.manifest_sha256 ?? "")) {
    throw new Error("publish blocked: intent manifest digest does not match check report");
  }
  const publishPackData = await collectPackData(packageDir);
  if (String(checkReport?.package?.name ?? "") !== publishPackData.packageName) {
    throw new Error("publish blocked: package name changed since check report (stale evidence)");
  }
  if (String(checkReport?.package?.version ?? "") !== publishPackData.packageVersion) {
    throw new Error("publish blocked: package version changed since check report (stale evidence)");
  }
  if (String(checkReport?.release?.tarball_sha256 ?? "") !== publishPackData.tarballSha256) {
    throw new Error("publish blocked: tarball digest changed since check report (stale evidence)");
  }
  if (String(checkReport?.release?.manifest_sha256 ?? "") !== publishPackData.manifestSha256) {
    throw new Error("publish blocked: manifest digest changed since check report (stale evidence)");
  }

  if (outcome === "deny") {
    throw new Error("publish blocked by deny decision");
  }
  if (outcome === "approve" && !approved) {
    throw new Error("publish requires explicit --approved for approve decisions");
  }

  let publishExecuted = false;
  if (execute) {
    const publish = spawnSync("npm", ["publish"], { cwd: packageDir, encoding: "utf8" });
    if (publish.status !== 0) {
      throw new Error(`npm publish failed: ${String(publish.stderr ?? publish.stdout ?? "").trim()}`);
    }
    publishExecuted = true;
  }

  const id = String(intent?.intent_id ?? "").replace(/^TI-/, "") || numericId();
  const occurredAt = nowIso();
  const snapshot = {
    release: {
      tarball_sha256: publishPackData.tarballSha256,
      manifest_sha256: publishPackData.manifestSha256,
      manifest_paths: publishPackData.manifestPaths,
      publish_attempted: publishExecuted
    },
    policy: {
      blocked_paths: checkReport?.policy?.blocked_paths ?? [],
      violations: checkReport?.policy?.violations ?? []
    }
  };
  const snapshotHash = sha256Hex(stableStringify(snapshot));

  const receipt = {
    schemaVersion: "1.0.0",
    receipt_id: `TR-${id}`,
    intent_id: intent.intent_id,
    decision_id: decision.decision_id,
    execution_status: publishExecuted ? "executed" : "blocked",
    captured_at: occurredAt,
    occurred_at: occurredAt,
    received_at: occurredAt,
    sealed_at: occurredAt,
    event_snapshot: snapshot,
    event_snapshot_hash: snapshotHash,
    correlation_id: `${intent.intent_id}:${decision.decision_id}:0`,
    intent,
    decision
  };
  const keyPair = generateSigningKeyPair();
  const signedReceipt = signReceipt(receipt, keyPair.privateKey, `release-guard-${id}`);

  const result = {
    generatedAt: occurredAt,
    mode: "publish",
    ok: true,
    executed: publishExecuted,
    intent,
    decision,
    receipt: signedReceipt
  };
  await writeOutput(outputPath, result);
  return result;
}
