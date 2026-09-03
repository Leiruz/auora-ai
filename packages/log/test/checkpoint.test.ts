import { describe, expect, it } from "vitest";
import { generateKeyPair } from "@auora/contracts";
import { buildEvent, GENESIS } from "../src/chain.js";
import { createCheckpoint, verifyAgainstCheckpoint } from "../src/checkpoint.js";
import { exportRunJsonl } from "../src/export.js";
import { EventStore } from "../src/store.js";

const RUN = "run_01ARZ3NDEKTSV4RRFFQ69G5FAV";
const D = "sha256:" + "a".repeat(64);

describe("checkpoints", () => {
  it("signs the head, detects truncation and appears in the export", async () => {
    const pair = await generateKeyPair();
    const registry = new Map([[pair.keyId, pair.publicKey]]);
    const store = EventStore.memory(registry);
    const e0 = await buildEvent({ run_id: RUN, type: "run.started", occurred_at: "2026-09-02T10:00:00Z", coverage: "protected", payload: { profile_digest: D, agent: { kind: "codex", version: "1" } } }, GENESIS, 0, pair);
    const e1 = await buildEvent({ run_id: RUN, type: "run.terminated", occurred_at: "2026-09-02T10:00:01Z", coverage: "protected", payload: { reason: "TEST" } }, e0.event_hash, 1, pair);
    await store.append(e0); await store.append(e1);
    const cp = await createCheckpoint(store, RUN, pair, "2026-09-02T10:00:02Z");
    expect(cp.seq).toBe(1); expect(cp.event_hash).toBe(e1.event_hash);
    expect(await verifyAgainstCheckpoint([e0, e1], cp, registry)).toEqual({ ok: true });
    expect(await verifyAgainstCheckpoint([e0], cp, registry)).toEqual({ ok: false, code: "TRUNCATED" });
    expect(await verifyAgainstCheckpoint([e0, { ...e1, event_hash: D as never }], cp, registry)).toEqual({ ok: false, code: "HASH_MISMATCH_AT_CHECKPOINT" });
    expect(await verifyAgainstCheckpoint([e0, e1], { ...cp, signed_at: "2026-09-02T11:00:00Z" }, registry)).toEqual({ ok: false, code: "CHECKPOINT_SIGNATURE_INVALID" });
    expect(await verifyAgainstCheckpoint([e0, e1], cp, new Map())).toEqual({ ok: false, code: "CHECKPOINT_UNKNOWN_KEY" });
    const lines = exportRunJsonl(store, RUN).trim().split("\n").map((l) => JSON.parse(l) as { record: string });
    expect(lines.map((l) => l.record)).toEqual(["event", "event", "checkpoint"]);
  });
});
