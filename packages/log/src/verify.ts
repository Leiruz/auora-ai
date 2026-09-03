// packages/log/src/verify.ts
import { validateEvent, verifyBytes, type Digest, type EventEnvelope, type PublicKeyRegistry } from "@auora/contracts";
import { GENESIS, hashOfEvent } from "./chain.js";

export const CHAIN_ERRORS = ["SCHEMA_INVALID", "RUN_MISMATCH", "SEQ_GAP", "DUPLICATE_SEQ", "OUT_OF_ORDER", "GENESIS_MISPLACED", "PREV_HASH_MISMATCH", "HASH_MISMATCH", "UNKNOWN_KEY", "SIGNATURE_INVALID"] as const;
export interface ChainError { seq: number; code: (typeof CHAIN_ERRORS)[number] }
export interface ChainVerification { ok: boolean; length: number; head: Digest | null; errors: ChainError[] }

export async function verifyChain(events: readonly EventEnvelope[], registry: PublicKeyRegistry): Promise<ChainVerification> {
  const errors: ChainError[] = [];
  const seen = new Set<number>();
  let runId: string | null = null;
  let prev: string = GENESIS;
  let expectedSeq = 0;
  let head: Digest | null = null;
  for (const ev of events) {
    const validated = validateEvent(ev);
    if (!validated.ok) { errors.push({ seq: ev.seq, code: "SCHEMA_INVALID" }); continue; }
    if (runId === null) runId = ev.run_id;
    if (ev.run_id !== runId) errors.push({ seq: ev.seq, code: "RUN_MISMATCH" });
    if (seen.has(ev.seq)) errors.push({ seq: ev.seq, code: "DUPLICATE_SEQ" });
    if (!seen.has(ev.seq) && ev.seq < expectedSeq) errors.push({ seq: ev.seq, code: "OUT_OF_ORDER" });
    if (!seen.has(ev.seq) && ev.seq > expectedSeq) errors.push({ seq: ev.seq, code: "SEQ_GAP" });
    seen.add(ev.seq);
    if (ev.seq === 0 && ev.prev_hash !== GENESIS) errors.push({ seq: ev.seq, code: "GENESIS_MISPLACED" });
    if (ev.seq !== 0 && ev.prev_hash === GENESIS) errors.push({ seq: ev.seq, code: "GENESIS_MISPLACED" });
    if (ev.prev_hash !== GENESIS && ev.prev_hash !== prev) errors.push({ seq: ev.seq, code: "PREV_HASH_MISMATCH" });
    if (hashOfEvent(ev) !== ev.event_hash) errors.push({ seq: ev.seq, code: "HASH_MISMATCH" });
    const key = registry.get(ev.key_id);
    if (!key) errors.push({ seq: ev.seq, code: "UNKNOWN_KEY" });
    if (key && !(await verifyBytes("auora.event/1", key, new TextEncoder().encode(ev.event_hash), ev.signature))) errors.push({ seq: ev.seq, code: "SIGNATURE_INVALID" });
    prev = ev.event_hash;
    head = ev.event_hash;
    if (ev.seq >= expectedSeq) expectedSeq = ev.seq + 1;
  }
  return { ok: errors.length === 0, length: events.length, head, errors };
}
