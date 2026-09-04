// packages/behavior/test/signals.test.ts
import { describe, expect, it } from "vitest";
import { validateAction, type ActionDescriptor, type Signal } from "@auora/contracts";
import { computeSignals, type CurrentAction, type HistoryEntry, type RunProfile } from "../src/signals.js";

const D = ("sha256:" + "a".repeat(64)) as HistoryEntry["descriptor_digest"];
const E = ("sha256:" + "e".repeat(64)) as HistoryEntry["descriptor_digest"];
const entry = (seq: number, over: Partial<HistoryEntry> = {}): HistoryEntry => ({ seq, elapsed_ms: seq * 1000, effect_class: "read", target_scope: "workspace", outcome: "allow", descriptor_digest: D, action_id: `act_${String(seq).padStart(26, "0")}`, ...over });
const current = (over: Partial<CurrentAction> = {}): CurrentAction => ({ effect_class: "read", target_scope: "workspace", is_lookup: false, labels_read: [], descriptor_digest: D, ...over });
const profile: RunProfile = { allowed_domains: ["registry.npmjs.org"], allowed_scopes: ["workspace", "external"] };
const codes = (s: { code: string }[]) => s.map((x) => x.code);
const descriptorCarrying = (signal: Signal): ActionDescriptor => ({
  schema_version: "auora.action/1", action_id: "act_01ARZ3NDEKTSV4RRFFQ69G5FAW", run_id: "run_01ARZ3NDEKTSV4RRFFQ69G5FAV", seq: 1,
  agent: { kind: "claude-code", version: "1" }, source: "resolver", effect_class: "read", risk_class: "medium",
  target: { kind: "name", value: "x.attacker.example", scope: "external" }, labels: [],
  command_digest: D, argument_digest: D,
  run_state: { counters: { actions: 1, sends: 0, denials: 0, approvals: 0, retries: 0 }, spend_minor: 0, elapsed_ms: 10, labels_read: [], signals: [signal] },
  descriptor_digest: D,
});

describe("behavior signals", () => {
  it("flags a destination or looked-up name not in the profile or the run so far, once", () => {
    expect(codes(computeSignals([], current({ effect_class: "send", destination: "example.org" }), profile))).toContain("new_destination");
    expect(codes(computeSignals([], current({ is_lookup: true, destination: "c2VjcmV0.attacker.example" }), profile))).toContain("new_destination");
    expect(codes(computeSignals([], current({ effect_class: "send", destination: "registry.npmjs.org" }), profile))).not.toContain("new_destination");
    expect(codes(computeSignals([entry(1, { destination: "example.org" })], current({ effect_class: "send", destination: "example.org" }), profile))).not.toContain("new_destination");
  });
  it("flags a send or lookup after a confidential or secret read", () => {
    expect(codes(computeSignals([], current({ effect_class: "send", labels_read: ["confidential"] }), profile))).toContain("sensitive_read_then_send");
    expect(codes(computeSignals([], current({ is_lookup: true, labels_read: ["secret"] }), profile))).toContain("sensitive_read_then_send");
    expect(codes(computeSignals([], current({ effect_class: "send", labels_read: ["internal"] }), profile))).not.toContain("sensitive_read_then_send");
    expect(codes(computeSignals([], current({ effect_class: "read", is_lookup: false, labels_read: ["secret"] }), profile))).not.toContain("sensitive_read_then_send");
  });
  it("scores denial velocity in the last twenty actions with integer basis points", () => {
    const history = [1, 2, 3, 4].map((i) => entry(i, { outcome: "deny" }));
    expect(computeSignals(history, current(), profile).find((x) => x.code === "denied_action_velocity")?.basis_points).toBe(8000);
    expect(computeSignals(history.slice(0, 2), current(), profile).find((x) => x.code === "denied_action_velocity")).toBeUndefined();
    const old = [...Array.from({ length: 4 }, (_, i) => entry(i + 1, { outcome: "deny" })), ...Array.from({ length: 20 }, (_, i) => entry(i + 5))];
    expect(codes(computeSignals(old, current(), profile))).not.toContain("denied_action_velocity");
    const exactlyThree = [1, 2, 3].map((i) => entry(i, { outcome: "deny" }));
    expect(computeSignals(exactlyThree, current(), profile).find((x) => x.code === "denied_action_velocity")?.basis_points).toBe(6000);
  });
  it("flags acceleration only when the last ten actions took less than half the time of the ten before", () => {
    const slow = Array.from({ length: 10 }, (_, i) => entry(i + 1, { elapsed_ms: (i + 1) * 10000 }));
    const fast = Array.from({ length: 10 }, (_, i) => entry(i + 11, { elapsed_ms: 100000 + (i + 1) * 1000 }));
    const s = computeSignals([...slow, ...fast], current(), profile).find((x) => x.code === "action_acceleration");
    expect(s?.basis_points).toBe(10000);
    const same = slow.map((e, i) => ({ ...e, seq: i + 11, elapsed_ms: 100000 + (i + 1) * 10000 }));
    expect(codes(computeSignals([...slow, ...same], current(), profile))).not.toContain("action_acceleration");
    const slightlyFaster = slow.map((e, i) => ({ ...e, seq: i + 11, elapsed_ms: 100000 + (i + 1) * 6000 }));
    expect(codes(computeSignals([...slow, ...slightlyFaster], current(), profile))).not.toContain("action_acceleration");
    const zeroSpanEarlier = Array.from({ length: 10 }, (_, i) => entry(i + 1, { elapsed_ms: 5000 }));
    expect(codes(computeSignals([...zeroSpanEarlier, ...fast], current(), profile))).not.toContain("action_acceleration");
    const earlierSpan = 100000;
    const fortyPercent = Array.from({ length: 10 }, (_, i) => entry(i + 11, { elapsed_ms: 100000 + (i + 1) * 4000 }));
    const s2 = computeSignals([...slow, ...fortyPercent], current(), profile).find((x) => x.code === "action_acceleration");
    expect(s2).toBeDefined();
    expect(s2?.basis_points).toBeGreaterThan(0);
  });
  it("flags scope drift as the share of actions outside the profile's allowed scopes", () => {
    const history = [entry(1, { target_scope: "outside_workspace" }), entry(2), entry(3, { target_scope: "system" }), entry(4, { target_scope: "external" })];
    const s = computeSignals(history, current({ target_scope: "unknown" }), profile).find((x) => x.code === "scope_drift");
    expect(s?.basis_points).toBe(6000);
    expect(codes(computeSignals([entry(1), entry(2)], current(), profile))).not.toContain("scope_drift");
    const exactlyTwoThousand = [entry(1), entry(2), entry(3), entry(4)];
    const s2 = computeSignals(exactlyTwoThousand, current({ target_scope: "unknown" }), profile).find((x) => x.code === "scope_drift");
    expect(s2?.basis_points).toBe(2000);
    const justBelow = [entry(1), entry(2), entry(3), entry(4), entry(5)];
    expect(codes(computeSignals(justBelow, current({ target_scope: "unknown" }), profile))).not.toContain("scope_drift");
  });
  it("flags the current action when it differs from the digest that was approved", () => {
    expect(codes(computeSignals([], current({ approved_digest: E }), profile))).toContain("post_approval_mutation");
    expect(codes(computeSignals([], current({ approved_digest: D }), profile))).not.toContain("post_approval_mutation");
    expect(codes(computeSignals([], current(), profile))).not.toContain("post_approval_mutation");
  });
  it("bounds a long looked-up destination's reason to the contracts schema cap (tunnelling shape)", () => {
    const longDestination = "a".repeat(300) + ".attacker.example";
    const signal = computeSignals([], current({ is_lookup: true, destination: longDestination }), profile).find((s) => s.code === "new_destination");
    expect(signal).toBeDefined();
    expect(signal!.reason.length).toBeLessThanOrEqual(256);
    expect(signal!.reason.startsWith("NEW_DESTINATION:")).toBe(true);
    expect(validateAction(descriptorCarrying(signal!)).ok).toBe(true);
  });
  it("is deterministic and never exceeds 10000 basis points", () => {
    const history = Array.from({ length: 30 }, (_, i) => entry(i + 1, { outcome: "deny", target_scope: "system" }));
    const a = computeSignals(history, current({ effect_class: "send", destination: "x.example", labels_read: ["secret"] }), profile);
    const b = computeSignals(history, current({ effect_class: "send", destination: "x.example", labels_read: ["secret"] }), profile);
    expect(a).toEqual(b);
    for (const s of a) { expect(Number.isInteger(s.basis_points)).toBe(true); expect(s.basis_points).toBeLessThanOrEqual(10000); }
  });
});
