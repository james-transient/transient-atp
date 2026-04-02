import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

export const ATP_PROTOCOL = "ATP";
export const ATP_VERSION = "1.0";

export const ATP_SIGNING_MODES = Object.freeze({
  ED25519: "Ed25519",
  LEGACY_SHA256: "legacy-sha256"
});

export const ATP_DEPRECATED = Object.freeze({
  LEGACY_SHA256_SIGNATURE: {
    code: "receipt_deprecated_legacy_signature",
    message:
      "sha256: string signature is deprecated. Implementations MUST migrate to Ed25519 object form. This form will not be accepted in ATP 2.0."
  }
});

export const ATP_ID_PATTERNS = Object.freeze({
  receipt: "^TR-\\d+$",
  intent: "^TI-\\d+$",
  decision: "^TD-\\d+$"
});

export const ATP_DECISION_OUTCOMES = Object.freeze(["allow", "approve", "deny"]);
export const ATP_EXECUTION_STATUSES = Object.freeze(["executed", "blocked", "expired", "error"]);

export const ATP_RECEIPT_VALIDATION_CODES = Object.freeze({
  MISSING_REQUIRED_FIELD: "receipt_missing_required_field",
  MISSING_REQUIRED_OBJECT: "receipt_missing_required_object",
  INVALID_RECEIPT_ID_FORMAT: "receipt_invalid_id_format",
  INVALID_INTENT_ID_FORMAT: "intent_invalid_id_format",
  INVALID_DECISION_ID_FORMAT: "decision_invalid_id_format",
  INTENT_ID_MISMATCH: "receipt_intent_id_mismatch",
  DECISION_ID_MISMATCH: "receipt_decision_id_mismatch",
  INVALID_SCHEMA_VERSION: "receipt_invalid_schema_version",
  INVALID_SIGNATURE_FORMAT: "receipt_invalid_signature_format",
  SIGNATURE_VERIFICATION_FAILED: "receipt_signature_verification_failed",
  INVALID_DATETIME_FORMAT: "receipt_invalid_datetime_format",
  INVALID_CAPTURED_AT: "receipt_invalid_captured_at",
  INVALID_EXECUTION_STATUS: "receipt_invalid_execution_status",
  INVALID_DECISION_OUTCOME: "decision_invalid_outcome",
  INVALID_SNAPSHOT_HASH: "receipt_invalid_snapshot_hash",
  INVALID_TIMESTAMP_ORDER: "receipt_invalid_timestamp_order",
  REPLAY_DETECTED: "receipt_replay_detected",
  OUTSIDE_WINDOW: "receipt_outside_window",
  KEY_NOT_FOUND: "receipt_key_not_found"
});

export {
  ATP_SIGNING_ALGORITHM,
  ATP_SIGNING_VERSION,
  generateSigningKeyPair,
  signReceipt,
  verifyReceiptSignature,
  receiptFingerprint,
  canonicalJSONString,
  canonicalBytes,
  exportPublicKeyAsJwk,
  buildJwks
} from "./signing.mjs";

export { ReplayGuard } from "./replay.mjs";

export function getSchemaPath(name) {
  if (!["intent", "decision", "receipt"].includes(name)) {
    throw new Error(`Unknown ATP schema '${name}'`);
  }
  return resolve(__dirname, `../schemas/${name}.schema.json`);
}
