import { createHash } from "node:crypto";
import {
  ATP_DECISION_OUTCOMES,
  ATP_EXECUTION_STATUSES,
  ATP_RECEIPT_VALIDATION_CODES,
  ATP_DEPRECATED,
  canonicalBytes
} from "@atp/spec";

export function hashEventSnapshot(snapshot) {
  return createHash("sha256").update(canonicalBytes(snapshot)).digest("hex");
}

function mapExecutionStatus(runStatus, haltReason) {
  const rs = String(runStatus ?? "").toLowerCase();
  const hr = String(haltReason ?? "").toLowerCase();
  if (rs === "success") return "executed";
  if (hr.includes("approval") || hr.includes("blocked")) return "blocked";
  if (hr.includes("timeout") || hr.includes("expired")) return "expired";
  return "error";
}

function mapDecisionOutcome(executionStatus, haltReason) {
  const hr = String(haltReason ?? "").toLowerCase();
  if (hr.includes("approval")) return "approve";
  if (executionStatus === "executed") return "allow";
  return "deny";
}

export function createSampleReceipt({
  runId,
  sessionId,
  runStatus,
  haltReason,
  events,
  action = "runtime_run"
}) {
  const occurredAt = String(events?.[0]?.capturedAt ?? "2026-03-31T00:00:00.000Z");
  const sealedAt = String(events?.[events.length - 1]?.capturedAt ?? occurredAt);
  const receivedAt = occurredAt <= sealedAt ? occurredAt : sealedAt;
  const eventSnapshot = {
    runId,
    sessionId,
    runStatus,
    haltReason,
    events: Array.isArray(events) ? events : []
  };
  const eventSnapshotHash = hashEventSnapshot(eventSnapshot);
  const seed = `${String(runId ?? "")}:${String(sessionId ?? "")}:${String(action ?? "runtime_run")}`;
  const numericId = String(BigInt(`0x${createHash("sha256").update(seed).digest("hex").slice(0, 16)}`));
  const executionStatus = mapExecutionStatus(runStatus, haltReason);
  const decisionOutcome = mapDecisionOutcome(executionStatus, haltReason);

  return {
    schemaVersion: "1.0.0",
    receipt_id: `TR-${numericId}`,
    intent_id: `TI-${numericId}`,
    decision_id: `TD-${numericId}`,
    execution_status: executionStatus,
    captured_at: sealedAt,
    signature: `sha256:${eventSnapshotHash}`,
    occurred_at: occurredAt,
    received_at: receivedAt,
    sealed_at: sealedAt,
    event_snapshot: eventSnapshot,
    event_snapshot_hash: eventSnapshotHash,
    correlation_id: `${runId}:${sessionId}:0`,
    intent: {
      intent_id: `TI-${numericId}`,
      actor_id: "runtime-orchestrator",
      connector: "transient-atp",
      action,
      action_class: "write_high",
      target: { runtime: "external" },
      context: {},
      governance_profile: "default",
      requested_at: occurredAt
    },
    decision: {
      decision_id: `TD-${numericId}`,
      intent_id: `TI-${numericId}`,
      outcome: decisionOutcome,
      reason_code: haltReason ?? "none",
      decided_at: sealedAt
    }
  };
}

export function validateReceiptATP(receipt) {
  const issues = [];
  const warnings = [];
  const add = (code, message) => issues.push({ code, message });
  const warn = (code, message) => warnings.push({ code, message });
  const isObject = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
  const isStrictDateTime = (value) => {
    const input = String(value ?? "");
    const pattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;
    return pattern.test(input) && Number.isFinite(Date.parse(input));
  };
  const requireNonEmptyString = (value, path) => {
    if (typeof value !== "string" || !value.trim()) {
      add(ATP_RECEIPT_VALIDATION_CODES.MISSING_REQUIRED_FIELD, `${path} is required`);
      return false;
    }
    return true;
  };
  const requireDateTime = (value, path, code = ATP_RECEIPT_VALIDATION_CODES.INVALID_DATETIME_FORMAT) => {
    if (!isStrictDateTime(value)) add(code, `${path} must be RFC3339 date-time`);
  };

  const required = [
    "schemaVersion",
    "receipt_id",
    "intent_id",
    "decision_id",
    "execution_status",
    "captured_at",
    "occurred_at",
    "received_at",
    "sealed_at",
    "event_snapshot_hash",
    "correlation_id"
  ];
  for (const field of required) {
    requireNonEmptyString(receipt?.[field], field);
  }
  if (receipt?.signature === undefined || receipt?.signature === null) {
    add(ATP_RECEIPT_VALIDATION_CODES.MISSING_REQUIRED_FIELD, "signature is required");
  }
  if (String(receipt?.schemaVersion ?? "") !== "1.0.0") {
    add(ATP_RECEIPT_VALIDATION_CODES.INVALID_SCHEMA_VERSION, "schemaVersion must be '1.0.0'");
  }
  if (!isObject(receipt?.intent)) {
    add(ATP_RECEIPT_VALIDATION_CODES.MISSING_REQUIRED_OBJECT, "intent object is required");
  }
  if (!isObject(receipt?.decision)) {
    add(ATP_RECEIPT_VALIDATION_CODES.MISSING_REQUIRED_OBJECT, "decision object is required");
  }
  if (!isObject(receipt?.event_snapshot)) {
    add(ATP_RECEIPT_VALIDATION_CODES.MISSING_REQUIRED_OBJECT, "event_snapshot object is required");
  }
  if (!/^TR-\d+$/.test(String(receipt?.receipt_id ?? ""))) {
    add(ATP_RECEIPT_VALIDATION_CODES.INVALID_RECEIPT_ID_FORMAT, "receipt_id format invalid");
  }
  if (!/^TI-\d+$/.test(String(receipt?.intent_id ?? ""))) {
    add(ATP_RECEIPT_VALIDATION_CODES.INVALID_INTENT_ID_FORMAT, "intent_id format invalid");
  }
  if (!/^TD-\d+$/.test(String(receipt?.decision_id ?? ""))) {
    add(ATP_RECEIPT_VALIDATION_CODES.INVALID_DECISION_ID_FORMAT, "decision_id format invalid");
  }
  const sig = receipt?.signature;
  const isEd25519Sig = (s) =>
    isObject(s) &&
    s.alg === "Ed25519" &&
    typeof s.kid === "string" && s.kid.trim().length > 0 &&
    typeof s.sig === "string" && /^[A-Za-z0-9_-]+$/.test(s.sig) &&
    s.canonicalization === "RFC8785-JCS";
  const isLegacySig = (s) => typeof s === "string" && /^sha256:[a-f0-9]{64}$/.test(s);
  if (!isEd25519Sig(sig) && !isLegacySig(sig)) {
    add(
      ATP_RECEIPT_VALIDATION_CODES.INVALID_SIGNATURE_FORMAT,
      "signature must be Ed25519 object {alg, kid, sig, canonicalization} or legacy sha256:<64-hex>"
    );
  } else if (isLegacySig(sig)) {
    warn(ATP_DEPRECATED.LEGACY_SHA256_SIGNATURE.code, ATP_DEPRECATED.LEGACY_SHA256_SIGNATURE.message);
  }
  if (!ATP_EXECUTION_STATUSES.includes(String(receipt?.execution_status ?? ""))) {
    add(ATP_RECEIPT_VALIDATION_CODES.INVALID_EXECUTION_STATUS, "execution_status invalid");
  }
  requireDateTime(receipt?.captured_at, "captured_at", ATP_RECEIPT_VALIDATION_CODES.INVALID_CAPTURED_AT);
  requireDateTime(receipt?.occurred_at, "occurred_at");
  requireDateTime(receipt?.received_at, "received_at");
  requireDateTime(receipt?.sealed_at, "sealed_at");
  if (!ATP_DECISION_OUTCOMES.includes(String(receipt?.decision?.outcome ?? ""))) {
    add(ATP_RECEIPT_VALIDATION_CODES.INVALID_DECISION_OUTCOME, "decision.outcome invalid");
  }
  if (isObject(receipt?.intent)) {
    requireNonEmptyString(receipt.intent.intent_id, "intent.intent_id");
    requireNonEmptyString(receipt.intent.actor_id, "intent.actor_id");
    requireNonEmptyString(receipt.intent.connector, "intent.connector");
    requireNonEmptyString(receipt.intent.action, "intent.action");
    requireNonEmptyString(receipt.intent.action_class, "intent.action_class");
    if (!isObject(receipt.intent.target)) add(ATP_RECEIPT_VALIDATION_CODES.MISSING_REQUIRED_OBJECT, "intent.target object is required");
    if (!isObject(receipt.intent.context)) add(ATP_RECEIPT_VALIDATION_CODES.MISSING_REQUIRED_OBJECT, "intent.context object is required");
    requireNonEmptyString(receipt.intent.governance_profile, "intent.governance_profile");
    requireDateTime(receipt.intent.requested_at, "intent.requested_at");
  }
  if (isObject(receipt?.decision)) {
    requireNonEmptyString(receipt.decision.decision_id, "decision.decision_id");
    requireNonEmptyString(receipt.decision.intent_id, "decision.intent_id");
    requireNonEmptyString(receipt.decision.reason_code, "decision.reason_code");
    requireDateTime(receipt.decision.decided_at, "decision.decided_at");
  }
  if (String(receipt?.intent?.intent_id ?? "") && String(receipt?.intent_id ?? "") !== String(receipt.intent.intent_id)) {
    add(ATP_RECEIPT_VALIDATION_CODES.INTENT_ID_MISMATCH, "intent.intent_id must match top-level intent_id");
  }
  if (String(receipt?.decision?.decision_id ?? "") && String(receipt?.decision_id ?? "") !== String(receipt.decision.decision_id)) {
    add(ATP_RECEIPT_VALIDATION_CODES.DECISION_ID_MISMATCH, "decision.decision_id must match top-level decision_id");
  }
  if (String(receipt?.decision?.intent_id ?? "") && String(receipt?.intent_id ?? "") !== String(receipt.decision.intent_id)) {
    add(ATP_RECEIPT_VALIDATION_CODES.INTENT_ID_MISMATCH, "decision.intent_id must match top-level intent_id");
  }
  if (isObject(receipt?.event_snapshot)) {
    const recalculated = hashEventSnapshot(receipt.event_snapshot);
    if (String(receipt?.event_snapshot_hash ?? "") !== recalculated) {
      add(ATP_RECEIPT_VALIDATION_CODES.INVALID_SNAPSHOT_HASH, "event snapshot hash mismatch");
    }
  }
  const t1 = Date.parse(String(receipt?.occurred_at ?? ""));
  const t2 = Date.parse(String(receipt?.received_at ?? ""));
  const t3 = Date.parse(String(receipt?.sealed_at ?? ""));
  if (!(Number.isFinite(t1) && Number.isFinite(t2) && Number.isFinite(t3) && t1 <= t2 && t2 <= t3)) {
    add(ATP_RECEIPT_VALIDATION_CODES.INVALID_TIMESTAMP_ORDER, "timestamp ordering invalid");
  }
  return { ok: issues.length === 0, issues, warnings };
}
