// packages/log/src/chain.ts
import { digestOf, digestWithout, newId, signBytes, type Coverage, type Digest, type EventEnvelope, type EventType, type Signer } from "@auora/contracts";

export const GENESIS = "GENESIS" as const;
export interface EventDraft { run_id: string; type: EventType; occurred_at: string; coverage: Coverage; payload: EventEnvelope["payload"] }

export function hashOfEvent(event: EventEnvelope): Digest {
  return digestWithout(event, ["event_hash", "signature"]);
}

export async function buildEvent(draft: EventDraft, prevHash: Digest | typeof GENESIS, seq: number, signer: Signer): Promise<EventEnvelope> {
  const unsigned = {
    schema_version: "auora.event/1" as const, event_id: newId("evt") as string, run_id: draft.run_id, seq, type: draft.type,
    occurred_at: draft.occurred_at, coverage: draft.coverage, prev_hash: prevHash, payload: draft.payload, key_id: signer.keyId,
  };
  const event_hash = digestOf(unsigned);
  const signature = await signBytes("auora.event/1", signer.privateKey, new TextEncoder().encode(event_hash));
  return { ...unsigned, event_hash, signature };
}
