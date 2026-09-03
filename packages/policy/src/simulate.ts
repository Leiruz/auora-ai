import type { ActionDescriptor, Decision, EventEnvelope, Outcome } from "@auora/contracts";
import { evaluate } from "./evaluate.js";
import type { CompiledBundle } from "./types.js";

export interface SimulationRow { action_id: string; previous_outcome: Outcome | null; new_outcome: Outcome; changed: boolean }

export function simulate(events: readonly EventEnvelope[], bundle: CompiledBundle): SimulationRow[] {
  const decided = new Map<string, Outcome>();
  for (const e of events) {
    if (e.type === "policy.decided") {
      const decision = (e.payload as unknown as { decision: Decision }).decision;
      decided.set(decision.action_id, decision.outcome);
    }
  }
  const rows: SimulationRow[] = [];
  for (const e of events) {
    if (e.type !== "action.requested") continue;
    const d = (e.payload as unknown as { descriptor: ActionDescriptor }).descriptor;
    const next = evaluate(d, bundle).outcome;
    const previous = decided.get(d.action_id) ?? null;
    rows.push({ action_id: d.action_id, previous_outcome: previous, new_outcome: next, changed: previous !== next });
  }
  return rows;
}
