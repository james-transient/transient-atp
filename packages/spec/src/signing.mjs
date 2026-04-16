import { sign as cryptoSign, verify as cryptoVerify, generateKeyPairSync, createHash, createPublicKey } from "node:crypto";
import canonicalize from "canonicalize";
import base64Url from "base64-url";

export const ATP_SIGNING_ALGORITHM = "Ed25519";
export const ATP_SIGNING_VERSION = "ATP-ED25519-1";

const BASE64_URL_PATTERN = /^[A-Za-z0-9_-]+$/;

function encodeBase64Url(buffer) {
  return base64Url.escape(buffer.toString("base64"));
}

function decodeBase64Url(value) {
  if (typeof value !== "string" || value.trim().length === 0 || !BASE64_URL_PATTERN.test(value)) {
    throw new Error("signature must be base64url (A-Z, a-z, 0-9, -, _)");
  }
  return Buffer.from(base64Url.unescape(value), "base64");
}

export function generateSigningKeyPair() {
  return generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" }
  });
}

export function canonicalJSONString(receipt) {
  if (!receipt || typeof receipt !== "object" || Array.isArray(receipt)) {
    throw new TypeError("receipt must be a non-null object");
  }
  const clone = structuredClone(receipt);
  delete clone.signature;
  const canonical = canonicalize(clone);
  if (typeof canonical !== "string") {
    throw new TypeError("failed to canonicalize receipt to RFC8785-JCS string");
  }
  return canonical;
}

export function canonicalBytes(receipt) {
  return Buffer.from(canonicalJSONString(receipt), "utf8");
}

export function signReceipt(receipt, privateKeyPem, keyId) {
  const payload = canonicalBytes(receipt);
  const sigBuffer = cryptoSign(null, payload, privateKeyPem);
  const sig = encodeBase64Url(sigBuffer);
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
  if (typeof publicKeyPem !== "string" || publicKeyPem.trim().length === 0) {
    return { ok: false, reason: "receipt_invalid_signature", detail: "public key missing or empty" };
  }
  if (sig.alg !== ATP_SIGNING_ALGORITHM) {
    return { ok: false, reason: "receipt_invalid_signature", detail: `unsupported algorithm '${sig.alg}'` };
  }
  if (sig.version !== undefined && sig.version !== ATP_SIGNING_VERSION) {
    return { ok: false, reason: "receipt_invalid_signature", detail: `unsupported signature version '${sig.version}'` };
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
    const sigBuffer = decodeBase64Url(sig.sig);
    if (sigBuffer.length !== 64) {
      return { ok: false, reason: "receipt_invalid_signature", detail: "Ed25519 signature must be exactly 64 bytes" };
    }
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
