const ATP_RECEIPT_VALIDATION_CODES = {
  MISSING_REQUIRED_FIELD: "receipt_missing_required_field",
  INVALID_DATETIME_FORMAT: "receipt_invalid_datetime_format",
  REPLAY_DETECTED: "receipt_replay_detected",
  OUTSIDE_WINDOW: "receipt_outside_window"
};

const DEFAULT_WINDOW_MS = 5 * 60 * 1000;
const DEFAULT_SKEW_MS = 30 * 1000;

export class ReplayGuard {
  #seen = new Map();
  #windowMs;
  #skewMs;

  constructor({ windowMs = DEFAULT_WINDOW_MS, skewMs = DEFAULT_SKEW_MS } = {}) {
    this.#windowMs = windowMs;
    this.#skewMs = skewMs;
  }

  check(receipt) {
    const now = Date.now();
    this.#evict(now);

    const receiptId = String(receipt?.receipt_id ?? "");
    if (!receiptId) {
      return { ok: false, reason: ATP_RECEIPT_VALIDATION_CODES.MISSING_REQUIRED_FIELD, detail: "receipt_id missing" };
    }

    const sealedAt = Date.parse(String(receipt?.sealed_at ?? ""));
    if (!Number.isFinite(sealedAt)) {
      return {
        ok: false,
        reason: ATP_RECEIPT_VALIDATION_CODES.INVALID_DATETIME_FORMAT,
        detail: `sealed_at ${String(receipt?.sealed_at ?? "")} must be a valid date-time`
      };
    }
    const earliest = now - this.#windowMs;
    const latest = now + this.#skewMs;
    if (sealedAt < earliest || sealedAt > latest) {
      return {
        ok: false,
        reason: ATP_RECEIPT_VALIDATION_CODES.OUTSIDE_WINDOW,
        detail: `sealed_at ${receipt.sealed_at} is outside observation window`
      };
    }

    if (this.#seen.has(receiptId)) {
      return {
        ok: false,
        reason: ATP_RECEIPT_VALIDATION_CODES.REPLAY_DETECTED,
        detail: `receipt_id ${receiptId} already observed`
      };
    }

    this.#seen.set(receiptId, now);
    return { ok: true };
  }

  #evict(now) {
    const cutoff = now - this.#windowMs;
    for (const [id, observedAt] of this.#seen) {
      if (observedAt < cutoff) this.#seen.delete(id);
    }
  }

  get size() {
    return this.#seen.size;
  }
}
