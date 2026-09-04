// packages/contracts/test/schemas.test.ts
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { canonicalJson } from "../src/canonical.js";
import { validateAction, validateApproval, validateCapabilityCall, validateCapabilityResult, validateDecision, validateEvent, validateHookEvent, validateHookResponse } from "../src/schemas.js";
import type { JsonValue } from "../src/types.js";
import { ACT, APR, FAKE_DIGEST, sampleAction, sampleApproval, sampleDecision, sampleEvent } from "./samples.js";

const hookEvent = (tool_input: JsonValue) => ({ schema_version: "auora.hook/1", kind: "event", agent: "codex", event: "pre_tool", session_id: "s1", cwd: "/w", tool_name: "Bash", tool_input, tool_use_id: "t1", raw_digest: FAKE_DIGEST });

const { jsonValue } = fc.letrec<{ jsonValue: JsonValue }>((tie) => ({
  jsonValue: fc.oneof({ maxDepth: 4 }, fc.constant(null), fc.boolean(), fc.integer({ min: -1000000, max: 1000000 }), fc.stringMatching(/^[a-z0-9 ]{0,12}$/), fc.constantFrom("é", "日本語", "naïve café"), fc.array(tie("jsonValue"), { maxLength: 4 }), fc.dictionary(fc.stringMatching(/^[a-z]{1,6}$/), tie("jsonValue"), { maxKeys: 4 })),
}));

describe("contract validators", () => {
  it("accept the positive samples", () => {
    expect(validateAction(sampleAction()).ok).toBe(true);
    expect(validateDecision(sampleDecision()).ok).toBe(true);
    expect(validateApproval(sampleApproval()).ok).toBe(true);
    expect(validateEvent(sampleEvent()).ok).toBe(true);
    expect(validateHookEvent(hookEvent({ command: "ls", nested: { flags: ["-l", 1, true, null] } })).ok).toBe(true);
    expect(validateHookResponse({ schema_version: "auora.hook/1", kind: "response", decision: "deny", reason: "AUORA: rule x", action_id: ACT }).ok).toBe(true);
    expect(validateCapabilityCall({ schema_version: "auora.capability/1", kind: "call", run_id: sampleAction().run_id, capability: "support.ticket", method: "read", args: { ticketId: "T-1" }, seq: 1, isolate_execution_id: "x1" }).ok).toBe(true);
    expect(validateCapabilityResult({ schema_version: "auora.capability/1", kind: "result", ok: true, data: { a: 1 }, labels: ["internal"], size_bytes: 12 }).ok).toBe(true);
  });
  it("reject unknown fields, missing fields, bad enums, floats, unsafe integers and bad digests", () => {
    expect(validateAction({ ...sampleAction(), extra: 1 }).ok).toBe(false);
    const { labels: _omit, ...missing } = sampleAction();
    expect(validateAction(missing).ok).toBe(false);
    expect(validateAction(sampleAction({ effect_class: "launch" as never })).ok).toBe(false);
    expect(validateAction(sampleAction({ seq: 1.5 })).ok).toBe(false);
    expect(validateAction(sampleAction({ seq: 9007199254740992 })).ok).toBe(false);
    expect(validateAction(sampleAction({ command_digest: "sha256:zz" as never })).ok).toBe(false);
    expect(validateAction(sampleAction({ labels: ["internal", "internal"] })).ok).toBe(false);
    expect(validateDecision(sampleDecision({ obligations: [{ type: "max_response_bytes", max_bytes: 9007199254740992 }] })).ok).toBe(false);
  });
  it("bounds opaque JSON values so that schema-valid input always canonicalizes", () => {
    expect(validateHookEvent(hookEvent({ ratio: 0.5 })).ok).toBe(false);
    expect(validateHookEvent(hookEvent({ big: 9007199254740992 })).ok).toBe(false);
    expect(validateHookEvent(hookEvent({ text: "x".repeat(65537) })).ok).toBe(false);
    expect(validateHookEvent(hookEvent({ text: "e\u0301" })).ok).toBe(false);
    expect(validateHookEvent(hookEvent({ ["e\u0301"]: 1 })).ok).toBe(false);
    let deep: JsonValue = 1;
    for (let i = 0; i < 20; i++) deep = [deep];
    expect(validateHookEvent(hookEvent({ deep })).ok).toBe(true);
    for (let i = 0; i < 13; i++) deep = [deep];
    expect(validateHookEvent(hookEvent({ deep })).ok).toBe(false);
    const hostileValue = fc.oneof(
      jsonValue,
      fc.anything({ withDate: true, withBoxedValues: true, withMap: true, withSet: true, withTypedArray: true, withSparseArray: true, withNullPrototype: true, withUnicodeString: true }),
    );
    fc.assert(
      fc.property(hostileValue, (input) => {
        const v = validateHookEvent(hookEvent(input as JsonValue));
        if (v.ok) expect(() => canonicalJson(hookEvent(input as JsonValue))).not.toThrow();
      }),
      { numRuns: 300 },
    );
    fc.assert(
      fc.property(fc.dictionary(fc.stringMatching(/^[a-z]{1,6}$/), jsonValue, { maxKeys: 4 }), (input) => {
        const v = validateHookEvent(hookEvent(input));
        expect(v.ok).toBe(true);
        expect(() => canonicalJson(hookEvent(input))).not.toThrow();
      }),
      { numRuns: 300 },
    );
  });
  it("requires approval_request_id when the outcome is require_approval", () => {
    expect(validateDecision(sampleDecision({ outcome: "require_approval" })).ok).toBe(false);
    expect(validateDecision(sampleDecision({ outcome: "require_approval", approval_request_id: "apr_01ARZ3NDEKTSV4RRFFQ69G5FAY" })).ok).toBe(true);
  });
  it("forbids a non-empty obligations array on any outcome other than allow", () => {
    const obligation = { type: "record_payload_digest" as const };
    expect(validateDecision(sampleDecision({ outcome: "deny", obligations: [obligation] })).ok).toBe(false);
    expect(validateDecision(sampleDecision({ outcome: "require_approval", approval_request_id: APR, obligations: [obligation] })).ok).toBe(false);
    expect(validateDecision(sampleDecision({ outcome: "allow", obligations: [obligation] })).ok).toBe(true);
    expect(validateDecision(sampleDecision({ outcome: "deny", obligations: [] })).ok).toBe(true);
  });
  it("validates event payloads by type with closed shapes", () => {
    expect(validateEvent(sampleEvent({ payload: { profile_digest: FAKE_DIGEST, agent: { kind: "codex", version: "1" }, extra: true } })).ok).toBe(false);
    expect(validateEvent(sampleEvent({ type: "run.terminated", payload: { reason: "USER_ABORT" } })).ok).toBe(true);
    expect(validateEvent(sampleEvent({ type: "run.terminated", payload: {} })).ok).toBe(false);
    expect(validateEvent(sampleEvent({ occurred_at: "2026-09-02T10:00:00+08:00" })).ok).toBe(false);
  });
  it("rejects a non-object and a wrong kind for the hook and capability unions", () => {
    expect(validateHookEvent({ schema_version: "auora.hook/1", kind: "response", decision: "allow", reason: "" }).ok).toBe(false);
    expect(validateCapabilityResult("nope").ok).toBe(false);
  });
  it("ties capability result data and error to ok", () => {
    const base = { schema_version: "auora.capability/1", kind: "result", labels: ["internal"], size_bytes: 12 } as const;
    expect(validateCapabilityResult({ ...base, ok: true, error: { code: "BAD", message: "x" } }).ok).toBe(false);
    expect(validateCapabilityResult({ ...base, ok: false }).ok).toBe(false);
    expect(validateCapabilityResult({ ...base, ok: true, data: { a: 1 }, error: { code: "BAD", message: "x" } }).ok).toBe(false);
    expect(validateCapabilityResult({ ...base, ok: true }).ok).toBe(true);
    expect(validateCapabilityResult({ ...base, ok: false, error: { code: "BAD", message: "x" } }).ok).toBe(true);
  });
});
