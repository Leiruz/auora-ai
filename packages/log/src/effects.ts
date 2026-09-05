// packages/log/src/effects.ts
import type { Coverage, EventEnvelope, Signer } from "@auora/contracts";
import { buildEvent, GENESIS } from "./chain.js";
import { encryptText } from "./crypto.js";
import type { KeyProvider } from "./keys.js";
import type { EventStore } from "./store.js";

export interface EffectObservedInput {
  run_id: string; action_id: string; status: "ok" | "error" | "timeout" | "out_of_memory" | "process_limit";
  command_text?: string; size_bytes?: number; code?: string; occurred_at: string; coverage: Coverage;
}

// The only path that turns command text into an event: it never stores plaintext.
export async function recordEffectObserved(store: EventStore, signer: Signer, provider: KeyProvider, input: EffectObservedInput): Promise<EventEnvelope> {
  const payload: Record<string, string | number> = { action_id: input.action_id, status: input.status };
  if (input.size_bytes !== undefined) payload["size_bytes"] = input.size_bytes;
  if (input.code !== undefined) payload["code"] = input.code;
  if (input.command_text !== undefined) payload["command_text_ciphertext"] = encryptText(await provider.getKey(), input.command_text);
  const head = store.head(input.run_id);
  const event = await buildEvent({ run_id: input.run_id, type: "effect.observed", occurred_at: input.occurred_at, coverage: input.coverage, payload }, head ? (head.hash as EventEnvelope["event_hash"]) : GENESIS, head ? head.seq + 1 : 0, signer);
  await store.append(event);
  return event;
}
