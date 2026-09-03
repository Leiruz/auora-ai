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
    expect(rows).toEqual([{ action_id: d.action_id, previous_outcome: "allow", new_outcome: "deny", changed: true }]);
    expect(simulate([event("action.requested", { descriptor: d }, 1)], bundle)).toEqual([{ action_id: d.action_id, previous_outcome: null, new_outcome: "allow", changed: true }]);
  });
});
