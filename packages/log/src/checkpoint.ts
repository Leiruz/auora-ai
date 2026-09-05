import { canonicalBytes, signBytes, verifyBytes, type Digest, type EventEnvelope, type PublicKeyRegistry, type Signer } from "@auora/contracts";
import type { EventStore } from "./store.js";

export interface Checkpoint { schema_version: "auora.checkpoint/1"; run_id: string; seq: number; event_hash: Digest; signed_at: string; key_id: string; signature: string }
export type CheckpointVerdict = { ok: true } | { ok: false; code: "CHECKPOINT_UNKNOWN_KEY" | "CHECKPOINT_SIGNATURE_INVALID" | "TRUNCATED" | "HASH_MISMATCH_AT_CHECKPOINT" };

export async function createCheckpoint(store: EventStore, runId: string, signer: Signer, signedAt: string): Promise<Checkpoint> {
  const head = store.head(runId);
  if (!head) throw new Error(`no events for ${runId}`);
  const unsigned = { schema_version: "auora.checkpoint/1" as const, run_id: runId, seq: head.seq, event_hash: head.hash as Digest, signed_at: signedAt, key_id: signer.keyId };
  const signature = await signBytes("auora.checkpoint/1", signer.privateKey, canonicalBytes(unsigned));
  const checkpoint: Checkpoint = { ...unsigned, signature };
  store.saveCheckpoint(runId, checkpoint.seq, JSON.stringify(checkpoint));
  return checkpoint;
}

export async function verifyAgainstCheckpoint(events: readonly EventEnvelope[], checkpoint: Checkpoint, registry: PublicKeyRegistry): Promise<CheckpointVerdict> {
  const key = registry.get(checkpoint.key_id);
  if (!key) return { ok: false, code: "CHECKPOINT_UNKNOWN_KEY" };
  const { signature, ...unsigned } = checkpoint;
  if (!(await verifyBytes("auora.checkpoint/1", key, canonicalBytes(unsigned), signature))) return { ok: false, code: "CHECKPOINT_SIGNATURE_INVALID" };
  const at = events.find((e) => e.run_id === checkpoint.run_id && e.seq === checkpoint.seq);
  if (!at) return { ok: false, code: "TRUNCATED" };
  if (at.event_hash !== checkpoint.event_hash) return { ok: false, code: "HASH_MISMATCH_AT_CHECKPOINT" };
  return { ok: true };
}
