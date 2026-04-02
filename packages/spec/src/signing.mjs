import { sign as cryptoSign, verify as cryptoVerify, generateKeyPairSync, createHash, createPublicKey } from "node:crypto";
import canonicalize from "canonicalize";

export const ATP_SIGNING_ALGORITHM = "Ed25519";
export const ATP_SIGNING_VERSION = "ATP-ED25519-1";

export function generateSigningKeyPair() {
  return generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" }
  });
}

export function canonicalJSONString(receipt) {
  const clone = structuredClone(receipt);
  delete clone.signature;
  return canonicalize(clone);
}

export function canonicalBytes(receipt) {
  return Buffer.from(canonicalJSONString(receipt), "utf8");
}

export function signReceipt(receipt, privateKeyPem, keyId) {
  const payload = canonicalBytes(receipt);
  const sigBuffer = cryptoSign(null, payload, privateKeyPem);
  const sig = sigBuffer.toString("base64url");
  return {
    ...receipt,
    signature: {
      alg: ATP_SIGNING_ALGORITHM,
      version: ATP_SIGNING_VERSION,
      kid: keyId,
      sig,
      canonicalization: "RFC8785-JCS"
    }
  };
}

export function verifyReceiptSignature(receipt, publicKeyPem, options = {}) {
  const sig = receipt?.signature;
  if (!sig || typeof sig !== "object") {
    return { ok: false, reason: "receipt_invalid_signature", detail: "signature object missing" };
  }
  if (sig.alg !== ATP_SIGNING_ALGORITHM) {
    return { ok: false, reason: "receipt_invalid_signature", detail: `unsupported algorithm '${sig.alg}'` };
  }
  if (sig.canonicalization !== "RFC8785-JCS") {
    return {
      ok: false,
      reason: "receipt_invalid_signature",
      detail: "canonicalization must be RFC8785-JCS"
    };
  }
  if (typeof sig.kid !== "string" || sig.kid.trim().length === 0) {
    return { ok: false, reason: "receipt_invalid_signature", detail: "kid field missing or empty" };
  }
  if (typeof options?.expectedKid === "string" && options.expectedKid.trim().length > 0 && sig.kid !== options.expectedKid) {
    return {
      ok: false,
      reason: "receipt_invalid_signature",
      detail: `kid mismatch expected '${options.expectedKid}' but got '${sig.kid}'`
    };
  }
  if (typeof sig.sig !== "string" || !sig.sig.trim()) {
    return { ok: false, reason: "receipt_invalid_signature", detail: "sig field missing or empty" };
  }
  try {
    const payload = canonicalBytes(receipt);
    const sigBuffer = Buffer.from(sig.sig, "base64url");
    const valid = cryptoVerify(null, payload, publicKeyPem, sigBuffer);
    if (!valid) return { ok: false, reason: "receipt_signature_verification_failed", detail: "signature mismatch" };
    return { ok: true };
  } catch (error) {
    return { ok: false, reason: "receipt_signature_verification_failed", detail: String(error?.message ?? error) };
  }
}

export function exportPublicKeyAsJwk(publicKeyPem, kid) {
  const keyObj = createPublicKey(publicKeyPem);
  const raw = keyObj.export({ format: "jwk" });
  return {
    kty: "OKP",
    crv: "Ed25519",
    kid,
    use: "sig",
    x: raw.x
  };
}

export function buildJwks(entries) {
  return { keys: entries };
}

export function receiptFingerprint(receipt) {
  const payload = canonicalBytes(receipt);
  return createHash("sha256").update(payload).digest("hex");
}
