#!/usr/bin/env node

/**
 * Generate valid ATP 1.0 test fixtures with proper Ed25519 signatures.
 *
 * Usage:
 *   node scripts/generate-fixtures.mjs
 *
 * This script creates valid test scenarios in conformance-kit/fixtures/external/runtimes.v1.json
 */

import { readFile, writeFile } from "node:fs/promises";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import {
  generateSigningKeyPair,
  signReceipt,
  exportPublicKeyAsJwk,
  canonicalBytes,
} from "../../packages/spec/src/index.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_PATH = resolve(__dirname, "../fixtures/external/runtimes.v1.json");

/**
 * Generate a test scenario with valid signature
 */
function createScenario(runtimeId, intent, decision, executionStatus, eventSnapshot, keyIndex, optionalFields = null) {
  const { publicKey, privateKey } = generateSigningKeyPair();
  const kid = `external-runtime-key-${String(keyIndex).padStart(3, "0")}`;

  const now = "2026-03-31T00:00:00.000Z";
  const sealed = "2026-03-31T00:00:02.000Z";

  // Create event snapshot hash (SHA256 of canonical JSON using RFC8785-JCS)
  const eventSnapshotHash = createHash("sha256")
    .update(canonicalBytes(eventSnapshot))
    .digest("hex");

  const unsignedReceipt = {
    schemaVersion: "1.0.0",
    receipt_id: `TR-${Date.now()}${Math.random().toString().slice(2, 9)}`,
    intent_id: intent.intent_id,
    decision_id: decision.decision_id,
    execution_status: executionStatus,
    captured_at: sealed,
    signature: undefined, // will be added by signReceipt
    occurred_at: now,
    received_at: now,
    sealed_at: sealed,
    event_snapshot: eventSnapshot,
    event_snapshot_hash: eventSnapshotHash,
    correlation_id: `${runtimeId}:sess-${keyIndex}:0`,
    intent,
    decision,
  };

  // Add optional fields if provided
  if (optionalFields) {
    Object.assign(unsignedReceipt, optionalFields);
  }

  // Sign the receipt
  const signedReceipt = signReceipt(unsignedReceipt, privateKey, kid);

  return {
    runtimeId,
    requiredLevel: "CLASSIFY_ONLY",
    requiredAtpL1: true,
    evidence: {
      attestation: {
        trustReceiptSigned: true,
        trustReceiptPublicKey: publicKey,
        trustReceiptKeyId: kid,
        keyDistribution: {
          published: true,
          endpoint: "/.well-known/atp-keys",
        },
        replayProtection: {
          enabled: true,
          observationWindowSeconds: 300,
        },
        trustReceipt: signedReceipt,
      },
    },
  };
}

/**
 * Main generator
 */
async function generateFixtures() {
  try {
    // Read existing fixtures to preserve decision outcomes and execution statuses
    let existing = { runtimes: [] };
    try {
      const content = await readFile(FIXTURES_PATH, "utf8");
      existing = JSON.parse(content);
    } catch (e) {
      console.log("Creating new fixtures file...");
    }

    const scenarios = [];
    let keyIndex = 1;

    // Helper to create decision
    const makeDecision = (outcomeStr, reason) => ({
      decision_id: `TD-${Date.now()}${Math.random().toString().slice(2, 9)}`,
      intent_id: "", // will be set in scenario
      outcome: outcomeStr,
      reason_code: reason,
      decided_at: "2026-03-31T00:00:02.000Z",
    });

    // Helper to create intent
    const makeIntent = (action, actionClass, target = {}) => ({
      intent_id: `TI-${Date.now()}${Math.random().toString().slice(2, 9)}`,
      actor_id: "runtime-orchestrator",
      connector: "transient-atp",
      action,
      action_class: actionClass,
      target,
      context: {},
      governance_profile: "default",
      requested_at: "2026-03-31T00:00:00.000Z",
    });

    console.log("Generating ATP 1.0 test fixtures...");

    // 1. Decision outcomes: allow
    const s1Intent = makeIntent("purchase_flowers", "write_high", { runtime: "external" });
    const s1Decision = makeDecision("allow", "none");
    s1Decision.intent_id = s1Intent.intent_id;
    scenarios.push(
      createScenario(
        "financial-flowers-allow-under-budget",
        s1Intent,
        s1Decision,
        "executed",
        {
          runId: "financial-flowers-allow-under-budget",
          sessionId: "sess-a",
          runStatus: "success",
          haltReason: "none",
          events: [
            { eventType: "tool_call_requested", capturedAt: "2026-03-31T00:00:00.000Z" },
            { eventType: "tool_call_executed", capturedAt: "2026-03-31T00:00:01.000Z" },
            { eventType: "run_end", capturedAt: "2026-03-31T00:00:02.000Z" },
          ],
        },
        keyIndex++
      )
    );

    // 2. Decision outcomes: approve
    const s2Intent = makeIntent("purchase_flowers", "write_high", { runtime: "external" });
    const s2Decision = makeDecision("approve", "critical_approval_required");
    s2Decision.intent_id = s2Intent.intent_id;
    scenarios.push(
      createScenario(
        "financial-flowers-approve-over-budget",
        s2Intent,
        s2Decision,
        "blocked",
        {
          runId: "financial-flowers-approve-over-budget",
          sessionId: "sess-b",
          runStatus: "halted",
          haltReason: "critical_approval_required",
          events: [
            { eventType: "tool_call_requested", capturedAt: "2026-03-31T00:00:00.000Z" },
            { eventType: "tool_call_executed", capturedAt: "2026-03-31T00:00:01.000Z" },
            { eventType: "run_end", capturedAt: "2026-03-31T00:00:02.000Z" },
          ],
        },
        keyIndex++
      )
    );

    // 3. Decision outcomes: deny
    const s3Intent = makeIntent("purchase_flowers", "write_high", { runtime: "external" });
    const s3Decision = makeDecision("deny", "merchant_blocked_by_policy");
    s3Decision.intent_id = s3Intent.intent_id;
    scenarios.push(
      createScenario(
        "financial-flowers-deny-blocked-merchant",
        s3Intent,
        s3Decision,
        "blocked",
        {
          runId: "financial-flowers-deny-blocked-merchant",
          sessionId: "sess-c",
          runStatus: "halted",
          haltReason: "merchant_blocked_by_policy",
          events: [
            { eventType: "tool_call_requested", capturedAt: "2026-03-31T00:00:00.000Z" },
            { eventType: "tool_call_executed", capturedAt: "2026-03-31T00:00:01.000Z" },
            { eventType: "run_end", capturedAt: "2026-03-31T00:00:02.000Z" },
          ],
        },
        keyIndex++
      )
    );

    // 4. Execution status: expired
    const s4Intent = makeIntent("purchase_flowers", "write_high", { runtime: "external" });
    const s4Decision = makeDecision("deny", "timeout");
    s4Decision.intent_id = s4Intent.intent_id;
    scenarios.push(
      createScenario(
        "scenario-expired-approval-window",
        s4Intent,
        s4Decision,
        "expired",
        {
          runId: "scenario-expired-approval-window",
          sessionId: "sess-d",
          runStatus: "halted",
          haltReason: "timeout",
          events: [
            { eventType: "tool_call_requested", capturedAt: "2026-03-31T00:00:00.000Z" },
            { eventType: "tool_call_executed", capturedAt: "2026-03-31T00:00:01.000Z" },
            { eventType: "run_end", capturedAt: "2026-03-31T00:00:02.000Z" },
          ],
        },
        keyIndex++
      )
    );

    // 5. Execution status: error
    const s5Intent = makeIntent("purchase_flowers", "write_high", { runtime: "external" });
    const s5Decision = makeDecision("deny", "runtime_exception");
    s5Decision.intent_id = s5Intent.intent_id;
    scenarios.push(
      createScenario(
        "scenario-error-runtime-failure",
        s5Intent,
        s5Decision,
        "error",
        {
          runId: "scenario-error-runtime-failure",
          sessionId: "sess-e",
          runStatus: "halted",
          haltReason: "runtime_exception",
          events: [
            { eventType: "tool_call_requested", capturedAt: "2026-03-31T00:00:00.000Z" },
            { eventType: "tool_call_executed", capturedAt: "2026-03-31T00:00:01.000Z" },
            { eventType: "run_end", capturedAt: "2026-03-31T00:00:02.000Z" },
          ],
        },
        keyIndex++
      )
    );

    // 6. Policy evaluation: read action class
    const s6Intent = makeIntent("query_audit_log", "read", { resource: "audit_log" });
    s6Intent.actor_id = "audit-agent";
    const s6Decision = makeDecision("allow", "read_not_restricted");
    s6Decision.intent_id = s6Intent.intent_id;
    scenarios.push(
      createScenario(
        "policy-eval-action-class-read",
        s6Intent,
        s6Decision,
        "executed",
        {
          runId: "policy-eval-action-class-read",
          sessionId: "sess-read",
          runStatus: "success",
          haltReason: "none",
          events: [
            { eventType: "tool_call_requested", capturedAt: "2026-03-31T00:00:00.000Z" },
            { eventType: "tool_call_executed", capturedAt: "2026-03-31T00:00:01.000Z" },
          ],
        },
        keyIndex++
      )
    );

    // 7. Policy evaluation: delete action class
    const s7Intent = makeIntent("delete_user_data", "delete", { resource: "user_data", id: "user-123" });
    s7Intent.actor_id = "cleanup-agent";
    const s7Decision = makeDecision("deny", "delete_requires_approval");
    s7Decision.intent_id = s7Intent.intent_id;
    scenarios.push(
      createScenario(
        "policy-eval-action-class-delete",
        s7Intent,
        s7Decision,
        "blocked",
        {
          runId: "policy-eval-action-class-delete",
          sessionId: "sess-delete",
          runStatus: "halted",
          haltReason: "critical_action_blocked",
          events: [
            { eventType: "tool_call_requested", capturedAt: "2026-03-31T00:00:00.000Z" },
          ],
        },
        keyIndex++
      )
    );

    // 8. Receipt with optional fields
    const s8Intent = makeIntent("process_payment", "write_high", { service: "payment-processor" });
    s8Intent.actor_id = "api-agent";
    s8Intent.context = { amount: 100, currency: "USD" };
    const s8Decision = makeDecision("allow", "payment_within_limit");
    s8Decision.intent_id = s8Intent.intent_id;

    const s8OptionalFields = {
      input_hash: "d".repeat(64),
      output_hash: "e".repeat(64),
      cost: {
        amount: "0.50",
        currency: "USD",
        unit: "request",
        payer: "user-123",
      },
      metadata: {
        client_id: "web-app-v2",
        deployment: "us-west-2",
        trace_id: "xyz-789-abc",
      },
    };

    scenarios.push(
      createScenario(
        "receipt-with-optional-fields",
        s8Intent,
        s8Decision,
        "executed",
        {
          runId: "receipt-with-optional-fields",
          sessionId: "sess-optional",
          input_size: 1024,
          output_size: 2048,
        },
        keyIndex++,
        s8OptionalFields
      )
    );

    // Write to file
    const output = { runtimes: scenarios };
    await writeFile(FIXTURES_PATH, JSON.stringify(output, null, 2));

    console.log(`✓ Generated ${scenarios.length} test fixtures`);
    console.log(`✓ Written to ${FIXTURES_PATH}`);
    console.log("\nFixture summary:");
    console.log("  - Decision outcomes: allow, approve, deny");
    console.log("  - Execution statuses: executed, blocked, expired, error");
    console.log("  - Policy evaluation: read, delete action classes");
    console.log("  - Optional fields: input_hash, output_hash, cost, metadata");

  } catch (error) {
    console.error("Error generating fixtures:", error.message);
    process.exit(1);
  }
}

generateFixtures();
