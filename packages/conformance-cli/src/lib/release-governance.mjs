import { readFile, writeFile, mkdir } from "node:fs/promises";
import { resolve } from "node:path";
import { hashEventSnapshot, createSampleReceipt, validateReceiptATP } from "./receipt.mjs";
import { generateSigningKeyPair, signReceipt } from "@atp/spec";

const REQUIRED_LIFECYCLE_STAGES = Object.freeze([
  "preflight_declaration",
  "policy_evaluation",
  "execution_authorization",
  "post_execution_attestation"
]);

function isHexSha256(value) {
  return typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
}

function hasBlockedPath(manifestPaths, blockedPrefixes) {
  const paths = Array.isArray(manifestPaths) ? manifestPaths : [];
  const blocked = Array.isArray(blockedPrefixes) ? blockedPrefixes : [];
  return paths.some((item) => blocked.some((prefix) => pathMatchesPolicy(String(item), String(prefix))));
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
  if (!policyPattern) return false;
  if (policyPattern.includes("*")) {
    return globToRegex(policyPattern).test(path);
  }
  return path.startsWith(policyPattern);
}

function buildReleaseReceipt(evidence) {
  const baseReceipt = createSampleReceipt({
    runId: evidence.runId,
    sessionId: evidence.sessionId,
    runStatus: evidence.runStatus,
    haltReason: evidence.haltReason,
    events: evidence.events,
    action: "registry.publish"
  });

  baseReceipt.intent.context = {
    package_name: evidence.intentContext?.package_name,
    package_version: evidence.intentContext?.package_version,
    expected_tarball_sha256: evidence.intentContext?.expected_tarball_sha256,
    expected_manifest_sha256: evidence.intentContext?.expected_manifest_sha256,
    commit_sha: evidence.intentContext?.commit_sha,
    tag: evidence.intentContext?.tag,
    publish_target: evidence.intentContext?.publish_target
  };

  baseReceipt.event_snapshot.release = {
    tarball_sha256: evidence.release?.tarball_sha256,
    manifest_sha256: evidence.release?.manifest_sha256,
    manifest_paths: Array.isArray(evidence.release?.manifest_paths) ? evidence.release.manifest_paths : [],
    publish_attempted: Boolean(evidence.release?.publish_attempted)
  };

  baseReceipt.event_snapshot_hash = hashEventSnapshot(baseReceipt.event_snapshot);
  const keyPair = generateSigningKeyPair();
  return signReceipt(baseReceipt, keyPair.privateKey, "release-governance-profile-key");
}

function evaluateCheck(id, ok, message) {
  return { id, ok: Boolean(ok), message };
}

export function evaluateReleaseGovernanceEvidence(evidence) {
  const checks = [];
  const receipt = buildReleaseReceipt(evidence);
  const lifecycle = Array.isArray(evidence?.lifecycle) ? evidence.lifecycle.map((item) => String(item?.stage ?? "")) : [];
  const outcome = String(receipt?.decision?.outcome ?? "");
  const executionStatus = String(receipt?.execution_status ?? "");

  checks.push(
    evaluateCheck(
      "RGP-INTENT-ACTION",
      String(receipt?.intent?.action ?? "") === "registry.publish",
      "intent.action must equal registry.publish"
    )
  );

  checks.push(
    evaluateCheck(
      "RGP-LIFECYCLE-REQUIRED",
      REQUIRED_LIFECYCLE_STAGES.every((stage) => lifecycle.includes(stage)),
      "required lifecycle stages must be present"
    )
  );

  const requiresApproval = Boolean(evidence?.policy?.require_approval === true);
  checks.push(
    evaluateCheck(
      "RGP-LIFECYCLE-APPROVAL-GATE",
      !requiresApproval || lifecycle.includes("approval_gate"),
      "approval_gate lifecycle stage is required when policy requires approval"
    )
  );

  const expectedTarball = String(receipt?.intent?.context?.expected_tarball_sha256 ?? "");
  const expectedManifest = String(receipt?.intent?.context?.expected_manifest_sha256 ?? "");
  const actualTarball = String(receipt?.event_snapshot?.release?.tarball_sha256 ?? "");
  const actualManifest = String(receipt?.event_snapshot?.release?.manifest_sha256 ?? "");

  checks.push(
    evaluateCheck(
      "RGP-DIGEST-FORMAT",
      isHexSha256(expectedTarball) && isHexSha256(expectedManifest) && isHexSha256(actualTarball) && isHexSha256(actualManifest),
      "tarball and manifest digests must be sha256 hex strings"
    )
  );

  checks.push(
    evaluateCheck(
      "RGP-DIGEST-BINDING",
      expectedTarball === actualTarball && expectedManifest === actualManifest,
      "expected digests in intent must match release digests in receipt snapshot"
    )
  );

  checks.push(
    evaluateCheck(
      "RGP-BLOCKED-PATHS",
      !hasBlockedPath(receipt?.event_snapshot?.release?.manifest_paths, evidence?.policy?.blocked_paths),
      "manifest paths must not include blocked path policy matches"
    )
  );

  const publishAttempted = Boolean(receipt?.event_snapshot?.release?.publish_attempted);
  const gateSatisfied = outcome === "allow" || outcome === "approve";
  const gateStatusSatisfied =
    (gateSatisfied && executionStatus === "executed" && publishAttempted) ||
    (!gateSatisfied && executionStatus === "blocked" && !publishAttempted);

  checks.push(
    evaluateCheck(
      "RGP-DECISION-GATE",
      gateStatusSatisfied,
      "publish attempt must align with decision outcome and execution status"
    )
  );

  const atpValidation = validateReceiptATP(receipt);
  checks.push(
    evaluateCheck(
      "RGP-ATP-L1-RECEIPT",
      atpValidation.ok,
      atpValidation.ok ? "receipt satisfies ATP-L1 invariants" : "receipt violates ATP-L1 invariants"
    )
  );
  checks.push(
    evaluateCheck(
      "RGP-NONDEPRECATED-SIGNING",
      typeof receipt?.signature === "object" &&
        receipt?.signature?.alg === "Ed25519" &&
        atpValidation.warnings.length === 0,
      "release profile receipts must use Ed25519 object signature with no deprecation warnings"
    )
  );

  const failures = checks.filter((entry) => !entry.ok).map((entry) => `${entry.id}: ${entry.message}`);

  return {
    profile: "ATP_1_0_RELEASE_GOVERNANCE",
    generatedAt: new Date().toISOString(),
    lifecycleStages: lifecycle,
    receipt,
    checks,
    failures,
    overall: failures.length === 0 ? "PASS" : "FAIL"
  };
}

export function validateReleaseGovernanceReport(report, contract) {
  const failures = [];
  const requiredChecks = Array.isArray(contract?.requiredChecks) ? contract.requiredChecks : [];
  if (typeof contract?.requiredOverall !== "string") {
    failures.push("contract.requiredOverall must be a string");
  }
  if (!Array.isArray(contract?.requiredLifecycleStages)) {
    failures.push("contract.requiredLifecycleStages must be an array");
  }
  if (!Array.isArray(contract?.requiredChecks)) {
    failures.push("contract.requiredChecks must be an array");
  }
  if (failures.length > 0) return { ok: false, failures };

  if (String(report?.overall ?? "") !== String(contract.requiredOverall)) {
    failures.push(`overall expected '${contract.requiredOverall}' but got '${report?.overall}'`);
  }

  const reportStages = new Set(Array.isArray(report?.lifecycleStages) ? report.lifecycleStages : []);
  for (const stage of contract.requiredLifecycleStages) {
    if (!reportStages.has(stage)) failures.push(`missing lifecycle stage '${stage}'`);
  }

  const checkById = new Map((Array.isArray(report?.checks) ? report.checks : []).map((item) => [String(item?.id ?? ""), item]));
  for (const checkId of requiredChecks) {
    const check = checkById.get(String(checkId));
    if (!check) {
      failures.push(`missing required check '${checkId}'`);
      continue;
    }
    if (check.ok !== true) failures.push(`required check '${checkId}' failed`);
  }

  return { ok: failures.length === 0, failures };
}

export async function runReleaseGovernanceProfile({
  cwd = process.cwd(),
  evidencePath = "conformance-kit/fixtures/release-governance/publish-evidence.json",
  reportOutPath = "conformance-kit/artifacts/latest-release-governance.json"
} = {}) {
  const evidenceAbs = resolve(cwd, evidencePath);
  const reportAbs = resolve(cwd, reportOutPath);
  const artifactsDir = resolve(cwd, "conformance-kit/artifacts");
  const evidence = JSON.parse(await readFile(evidenceAbs, "utf8"));
  const report = evaluateReleaseGovernanceEvidence(evidence);
  await mkdir(artifactsDir, { recursive: true });
  await writeFile(reportAbs, JSON.stringify(report, null, 2));
  return {
    ok: report.overall === "PASS",
    reportPath: reportOutPath,
    failureCount: report.failures.length
  };
}
