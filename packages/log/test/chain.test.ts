// packages/log/test/chain.test.ts
import { describe, expect, it } from "vitest";
import { generateKeyPair, validateEvent, type EventEnvelope } from "@auora/contracts";
import { buildEvent, GENESIS } from "../src/chain.js";
import { verifyChain } from "../src/verify.js";

const RUN = "run_01ARZ3NDEKTSV4RRFFQ69G5FAV";
const RUN2 = "run_01ARZ3NDEKTSV4RRFFQ69G5FA2";
const D = "sha256:" + "a".repeat(64);

async function chain(n: number) {
  const pair = await generateKeyPair();
  const events: EventEnvelope[] = [];
  let prev: EventEnvelope["prev_hash"] = GENESIS;
  for (let i = 0; i < n; i++) {
    const draft = i === 0
      ? { run_id: RUN, type: "run.started" as const, occurred_at: "2026-09-02T10:00:00Z", coverage: "protected" as const, payload: { profile_digest: D, agent: { kind: "codex", version: "1" } } }
      : { run_id: RUN, type: "coverage.changed" as const, occurred_at: `2026-09-02T10:00:0${i}Z`, coverage: "protected" as const, payload: { from: "protected", to: "protected", reason: "HEARTBEAT" } };
    const ev = await buildEvent(draft, prev, i, pair);
    events.push(ev); prev = ev.event_hash;
  }
  return { pair, events, registry: new Map([[pair.keyId, pair.publicKey]]) };
}
const codesAt = (v: { errors: { seq: number; code: string }[] }) => v.errors.map((e) => `${e.seq}:${e.code}`);

describe("event chain", () => {
  it("builds schema-valid, verifiable events", async () => {
    const { events, registry } = await chain(5);
    for (const e of events) expect(validateEvent(e).ok).toBe(true);
    const v = await verifyChain(events, registry);
    expect(v.ok).toBe(true); expect(v.length).toBe(5); expect(v.head).toBe(events[4]!.event_hash);
    expect(events[0]!.prev_hash).toBe(GENESIS); expect(events[1]!.prev_hash).toBe(events[0]!.event_hash);
  });
  it("reports exactly the defects of a modified, deleted, duplicated or reordered chain", async () => {
    const { events, registry } = await chain(5);
    const [e0, e1, e2, e3, e4] = events as [EventEnvelope, EventEnvelope, EventEnvelope, EventEnvelope, EventEnvelope];
    const modified = [e0, e1, { ...e2, payload: { ...e2.payload, reason: "TAMPERED" } }, e3, e4];
    expect(codesAt(await verifyChain(modified, registry))).toEqual(["2:HASH_MISMATCH"]);
    expect(codesAt(await verifyChain([e0, e1, e3, e4], registry))).toEqual(["3:SEQ_GAP", "3:PREV_HASH_MISMATCH"]);
    expect(codesAt(await verifyChain([e0, e1, e2, e2, e3, e4], registry))).toEqual(["2:DUPLICATE_SEQ", "2:PREV_HASH_MISMATCH"]);
    expect(codesAt(await verifyChain([e0, e2, e1, e3, e4], registry))).toEqual(["2:SEQ_GAP", "2:PREV_HASH_MISMATCH", "1:OUT_OF_ORDER", "1:PREV_HASH_MISMATCH", "3:PREV_HASH_MISMATCH"]);
  });
  it("reports unknown keys, bad signatures, misplaced genesis and a spliced foreign run", async () => {
    const { pair, events, registry } = await chain(3);
    const [e0, e1, e2] = events as [EventEnvelope, EventEnvelope, EventEnvelope];
    expect(codesAt(await verifyChain(events, new Map()))).toEqual(["0:UNKNOWN_KEY", "1:UNKNOWN_KEY", "2:UNKNOWN_KEY"]);
    expect(codesAt(await verifyChain([e0, e1, { ...e2, signature: "B".repeat(86) }], registry))).toEqual(["2:SIGNATURE_INVALID"]);
    expect(codesAt(await verifyChain([{ ...e0, prev_hash: D as never }, e1, e2], registry))).toContain("0:GENESIS_MISPLACED");
    expect(codesAt(await verifyChain([e0, { ...e1, prev_hash: GENESIS }, e2], registry))).toContain("1:GENESIS_MISPLACED");
    const foreign = await buildEvent({ run_id: RUN2, type: "coverage.changed", occurred_at: "2026-09-02T10:00:09Z", coverage: "protected", payload: { from: "protected", to: "protected", reason: "SPLICE" } }, e1.event_hash, 2, pair);
    expect(codesAt(await verifyChain([e0, e1, foreign], registry))).toEqual(["2:RUN_MISMATCH"]);
  });
});
