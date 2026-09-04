import { describe, expect, it } from "vitest";
import type { EventEnvelope } from "@auora/contracts";
import { compileLayer, composeBundles, parseBundle } from "../src/compile.js";
import { explain } from "../src/explain.js";
import { simulate } from "../src/simulate.js";
import { descriptor } from "./helpers.js";

const bundle = composeBundles([compileLayer(parseBundle("version: 1\nrules:\n  - id: allow-read\n    priority: 5\n    match: { effect: read }\n    outcome: allow\n  - id: deny-workspace\n    priority: 5\n    match: { target_scope: workspace }\n    outcome: deny\n  - id: low\n    priority: 1\n    match: { effect: read }\n    outcome: throttle\n"), "t")]);
const stricter = composeBundles([compileLayer(parseBundle("version: 1\nrules:\n  - id: deny-all-reads\n    priority: 9\n    match: { effect: read }\n    outcome: deny\n"), "t")]);

function event(type: "action.requested" | "policy.decided", payload: Record<string, unknown>, seq: number): EventEnvelope {
  const D = "sha256:" + "a".repeat(64);
  return { schema_version: "auora.event/1", event_id: "evt_01ARZ3NDEKTSV4RRFFQ69G5FAZ", run_id: "run_01ARZ3NDEKTSV4RRFFQ69G5FAV", seq, type, occurred_at: "2026-09-02T10:00:00Z", coverage: "protected", prev_hash: "GENESIS", payload: payload as EventEnvelope["payload"], event_hash: D as never, key_id: "key_" + "0".repeat(32), signature: "A".repeat(86) };
}

describe("explain and simulate", () => {
  it("lists every candidate, the top priority and the conflict", () => {
    const e = explain(descriptor(), bundle);
    expect(e.candidates.map((c) => c.qualified_id)).toEqual(["t:allow-read", "t:deny-workspace", "t:low"]);
    expect(e.top_priority).toBe(5); expect(e.conflict).toBe(true); expect(e.decision.outcome).toBe("deny"); expect(e.guard).toBeNull();
  });
  it("replays stored events through a new bundle and reports what would change", () => {
    const d = descriptor({ target: { kind: "path", value: "src/a.ts", scope: "external" } });
    const decision = { schema_version: "auora.decision/1", decision_id: "dec_01ARZ3NDEKTSV4RRFFQ69G5FAX", action_id: d.action_id, run_id: d.run_id, outcome: "allow", tier: "policy", reason_codes: ["POLICY_RULE_MATCHED"], matched_rule_ids: ["t:allow-read"], policy_digest: bundle.digest, obligations: [], ttl_ms: 5000 };
    const rows = simulate([event("action.requested", { descriptor: d }, 1), event("policy.decided", { decision }, 2)], stricter);
    expect(rows.rows).toEqual([{ action_id: d.action_id, previous_outcome: "allow", new_outcome: "deny", changed: true }]);
    expect(rows.skipped).toBe(0);
    expect(simulate([event("action.requested", { descriptor: d }, 1)], bundle).rows).toEqual([{ action_id: d.action_id, previous_outcome: null, new_outcome: "allow", changed: true }]);
  });
  it("skips a malformed stored event instead of throwing out of guardTier (regression)", () => {
    const d = descriptor();
    const malformed = event("action.requested", { descriptor: { not: "a real descriptor" } }, 2);
    const result = simulate([event("action.requested", { descriptor: d }, 1), malformed], bundle);
    expect(result.rows).toEqual([{ action_id: d.action_id, previous_outcome: null, new_outcome: "deny", changed: true }]);
    expect(result.skipped).toBe(1);
  });
  it("does not report a conflict from two gated rules alone, matching a no-match decision (regression)", () => {
    const gatedOnly = composeBundles([compileLayer(parseBundle("version: 1\nrules:\n  - id: gated-deny\n    priority: 5\n    match: { labels_any: secret }\n    outcome: deny\n  - id: gated-approve\n    priority: 5\n    match: { signals_any: scope_drift }\n    outcome: require_approval\n"), "t")]);
    const d = descriptor({ labels: ["secret"], run_state: { counters: { actions: 1, sends: 0, denials: 0, approvals: 0, retries: 0 }, spend_minor: 0, elapsed_ms: 10, labels_read: [], signals: [{ code: "scope_drift", basis_points: 5000, reason: "test" }] } });
    const e = explain(d, gatedOnly);
    expect(e.decision.reason_codes).toEqual(["POLICY_NO_MATCH"]);
    expect(e.top_priority).toBeNull();
    expect(e.conflict).toBe(false);
    expect(e.candidates).toEqual([]);
    expect(e.gated_candidates.map((c) => c.qualified_id)).toEqual(["t:gated-deny", "t:gated-approve"]);
  });
  it("reports a real ungated conflict even though a higher-priority gated rule also matches (regression)", () => {
    const b = composeBundles([compileLayer(parseBundle("version: 1\nrules:\n  - id: allow-read\n    priority: 5\n    match: { effect: read }\n    outcome: allow\n  - id: deny-workspace\n    priority: 5\n    match: { target_scope: workspace }\n    outcome: deny\n  - id: gated-terminate\n    priority: 20\n    match: { labels_any: secret }\n    outcome: terminate\n"), "t")]);
    const d = descriptor({ labels: ["secret"] });
    const e = explain(d, b);
    expect(e.decision.reason_codes).toEqual(["POLICY_CONFLICT"]);
    expect(e.top_priority).toBe(5);
    expect(e.conflict).toBe(true);
    expect(e.candidates.map((c) => c.qualified_id)).toEqual(["t:allow-read", "t:deny-workspace"]);
    expect(e.gated_candidates.map((c) => c.qualified_id)).toEqual(["t:gated-terminate"]);
  });
  it("does not report a conflict when two same-priority candidates share one outcome (regression)", () => {
    const b = composeBundles([compileLayer(parseBundle("version: 1\nrules:\n  - id: allow-a\n    priority: 5\n    match: { effect: read }\n    outcome: allow\n  - id: allow-b\n    priority: 5\n    match: { effect: read, target_scope: workspace }\n    outcome: allow\n"), "t")]);
    const e = explain(descriptor(), b);
    expect(e.candidates.map((c) => c.qualified_id)).toEqual(["t:allow-a", "t:allow-b"]);
    expect(e.top_priority).toBe(5);
    expect(e.conflict).toBe(false);
    expect(e.decision.reason_codes).toEqual(["POLICY_RULE_MATCHED"]);
  });
  it("reports changed: false when replaying leaves an outcome unchanged (regression)", () => {
    const d = descriptor({ target: { kind: "path", value: "src/a.ts", scope: "external" } });
    const decision = { schema_version: "auora.decision/1", decision_id: "dec_01ARZ3NDEKTSV4RRFFQ69G5FAY", action_id: d.action_id, run_id: d.run_id, outcome: "allow", tier: "policy", reason_codes: ["POLICY_RULE_MATCHED"], matched_rule_ids: ["t:allow-read"], policy_digest: bundle.digest, obligations: [], ttl_ms: 5000 };
    const rows = simulate([event("action.requested", { descriptor: d }, 1), event("policy.decided", { decision }, 2)], bundle);
    expect(rows.rows).toEqual([{ action_id: d.action_id, previous_outcome: "allow", new_outcome: "allow", changed: false }]);
  });
});
