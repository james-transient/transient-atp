import { readFile } from "node:fs/promises";
import { relative, resolve } from "node:path";
import { createSampleReceipt } from "./receipt.mjs";
import { runConformanceProofHarness } from "./conformance.mjs";
import { generateSigningKeyPair, signReceipt } from "@atp/spec";

function sampleRuntimes(frames) {
  const baseEvents = frames
    .filter((frame) => frame?.type === "event")
    .map((frame, idx) => ({
      eventType: String(frame?.payload?.eventType ?? "unknown"),
      capturedAt: new Date(Date.UTC(2026, 2, 31, 0, 0, idx)).toISOString()
    }));

  const withStatus = (runId, sessionId, runStatus, haltReason, action) => {
    const keyPair = generateSigningKeyPair();
    const baseReceipt = createSampleReceipt({
      runId,
      sessionId,
      runStatus,
      haltReason,
      events: baseEvents,
      action
    });
    const signedReceipt = signReceipt(baseReceipt, keyPair.privateKey, `harness-${runId}`);
    return {
      runtimeId: runId,
      requiredLevel: "CLASSIFY_ONLY",
      requiredAtpL1: true,
      evidence: {
        events: baseEvents,
        attestation: {
          trustReceiptSigned: true,
          trustReceiptPublicKey: keyPair.publicKey,
          trustReceiptKeyId: `harness-${runId}`,
          keyDistribution: {
            published: true,
            endpoint: "/.well-known/atp-keys"
          },
          replayProtection: {
            enabled: true,
            observationWindowSeconds: 300
          },
          trustReceipt: signedReceipt
        },
      }
    };
  };

  return [
    withStatus("financial-flowers-allow-under-budget", "sess-a", "success", "none", "purchase_flowers"),
    withStatus("financial-flowers-approve-over-budget", "sess-b", "halted", "critical_approval_required", "purchase_flowers"),
    withStatus("financial-flowers-deny-blocked-merchant", "sess-c", "halted", "merchant_blocked_by_policy", "purchase_flowers"),
    withStatus("scenario-expired-approval-window", "sess-d", "halted", "timeout", "purchase_flowers"),
    withStatus("scenario-error-runtime-failure", "sess-e", "halted", "runtime_exception", "purchase_flowers")
  ];
}

export async function loadRuntimeFixture(pathLike, cwd = process.cwd()) {
  const absolutePath = resolve(cwd, pathLike);
  const raw = await readFile(absolutePath, "utf8");
  const parsed = JSON.parse(raw);
  const runtimes = Array.isArray(parsed) ? parsed : parsed?.runtimes;
  if (!Array.isArray(runtimes) || runtimes.length === 0) {
    throw new Error("Runtime fixture must be an array or object with non-empty 'runtimes' array.");
  }
  return runtimes;
}

export async function loadOpenclawFrames(pathLike, cwd = process.cwd()) {
  const absolutePath = resolve(cwd, pathLike);
  const raw = await readFile(absolutePath, "utf8");
  const parsed = JSON.parse(raw);
  if (!Array.isArray(parsed?.frames)) {
    throw new Error("OpenClaw frames payload must include a 'frames' array.");
  }
  const eventFrames = parsed.frames.filter((frame) => frame?.type === "event");
  if (eventFrames.length === 0) {
    throw new Error("OpenClaw frames payload must include at least one event frame.");
  }
  const eventTypes = new Set(eventFrames.map((frame) => String(frame?.payload?.eventType ?? "")));
  const requiredEventTypes = ["tool_call_requested", "tool_call_executed", "run_end"];
  const missingEventTypes = requiredEventTypes.filter((eventType) => !eventTypes.has(eventType));
  if (missingEventTypes.length > 0) {
    throw new Error(
      `OpenClaw frames payload missing required event types: ${missingEventTypes.join(", ")}.`
    );
  }
  return parsed.frames;
}

export async function generateProofReport({
  openclawFramesPath = "conformance-kit/fixtures/openclaw/gateway-frames-live.json",
  runtimesFixturePath,
  allowLocalArtifacts = false,
  cwd = process.cwd()
} = {}) {
  if (runtimesFixturePath) {
    const runtimes = await loadRuntimeFixture(runtimesFixturePath, cwd);
    return runConformanceProofHarness({ runtimes });
  }
  if (!allowLocalArtifacts) {
    const rawPath = String(openclawFramesPath ?? "");
    const loweredPath = rawPath.toLowerCase();
    const absolutePath = resolve(cwd, rawPath);
    const relPath = relative(cwd, absolutePath);
    const outsideWorkspace = relPath.startsWith("..");
    const looksLocalArtifact = /(^|[\\/])\.?tt-local([\\/]|$)/i.test(rawPath) || loweredPath.includes("tt-local");
    if (outsideWorkspace || looksLocalArtifact) {
      throw new Error(
        "Conformance harness rejects local runtime artifact inputs by default. "
        + "Use committed fixtures within the repository, or pass --allow-local-artifacts to opt in."
      );
    }
  }
  const frames = await loadOpenclawFrames(openclawFramesPath, cwd);
  return runConformanceProofHarness({ runtimes: sampleRuntimes(frames) });
}
