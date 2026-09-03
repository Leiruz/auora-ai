// packages/contracts/test/samples.ts
import type { ActionDescriptor, ApprovalRecord, Decision, EventEnvelope } from "../src/types.js";

export const FAKE_DIGEST = ("sha256:" + "a".repeat(64)) as ActionDescriptor["descriptor_digest"];
export const FAKE_SIGNATURE = "A".repeat(86);
export const FAKE_KEY_ID = "key_" + "0".repeat(32);
export const RUN = "run_01ARZ3NDEKTSV4RRFFQ69G5FAV";
export const ACT = "act_01ARZ3NDEKTSV4RRFFQ69G5FAW";
export const DEC = "dec_01ARZ3NDEKTSV4RRFFQ69G5FAX";
export const APR = "apr_01ARZ3NDEKTSV4RRFFQ69G5FAY";
export const EVT = "evt_01ARZ3NDEKTSV4RRFFQ69G5FAZ";

export function sampleAction(overrides: Partial<ActionDescriptor> = {}): ActionDescriptor {
  return {
    schema_version: "auora.action/1", action_id: ACT, run_id: RUN, seq: 3,
    agent: { kind: "claude-code", version: "2.1.84" }, source: "hook", effect_class: "send", risk_class: "medium",
    target: { kind: "command", value: "curl", scope: "external" },
    destination: { domain: "registry.npmjs.org", port: 443, class: "allowlisted" },
    labels: ["internal"], command_digest: FAKE_DIGEST, argument_digest: FAKE_DIGEST,
    run_state: { counters: { actions: 3, sends: 1, denials: 0, approvals: 0, retries: 0 }, spend_minor: 0, elapsed_ms: 1200, labels_read: ["internal"], signals: [] },
    descriptor_digest: FAKE_DIGEST,
    ...overrides,
  };
}

export function sampleDecision(overrides: Partial<Decision> = {}): Decision {
  return { schema_version: "auora.decision/1", decision_id: DEC, action_id: ACT, run_id: RUN, outcome: "allow", tier: "policy", reason_codes: ["POLICY_RULE_MATCHED"], matched_rule_ids: ["example:allow-npm-registry"], policy_digest: FAKE_DIGEST, obligations: [], ttl_ms: 5000, ...overrides };
}

export function sampleApproval(overrides: Partial<ApprovalRecord> = {}): ApprovalRecord {
  return { schema_version: "auora.approval/1", approval_id: APR, action_id: ACT, descriptor_digest: FAKE_DIGEST, run_id: RUN, policy_digest: FAKE_DIGEST, surface: "device", signer_key_id: FAKE_KEY_ID, issued_at: "2026-09-02T10:00:00Z", expires_at: "2026-09-02T10:05:00Z", nonce: "n".repeat(22), signature: FAKE_SIGNATURE, ...overrides };
}

export function sampleEvent(overrides: Partial<EventEnvelope> = {}): EventEnvelope {
  return { schema_version: "auora.event/1", event_id: EVT, run_id: RUN, seq: 0, type: "run.started", occurred_at: "2026-09-02T10:00:00Z", coverage: "protected", prev_hash: "GENESIS", payload: { profile_digest: FAKE_DIGEST, agent: { kind: "claude-code", version: "2.1.84" } }, event_hash: FAKE_DIGEST, key_id: FAKE_KEY_ID, signature: FAKE_SIGNATURE, ...overrides };
}
