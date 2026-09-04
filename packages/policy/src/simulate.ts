import { validateAction, validateDecision, validateEvent, type EventEnvelope, type Outcome } from "@auora/contracts";
import { evaluate } from "./evaluate.js";
import type { CompiledBundle } from "./types.js";

export interface SimulationRow { action_id: string; previous_outcome: Outcome | null; new_outcome: Outcome; changed: boolean }

// `skipped` counts stored events that failed validation (malformed or forged log data) and were
// left out of `rows` rather than trusted; see packages/policy/test/explain.test.ts for the regression.
export interface SimulationResult { rows: SimulationRow[]; skipped: number }

export function simulate(events: readonly EventEnvelope[], bundle: CompiledBundle): SimulationResult {
  const decided = new Map<string, Outcome>();
  let skipped = 0;
  for (const e of events) {
    if (e.type !== "policy.decided") continue;
    if (!validateEvent(e).ok) { skipped++; continue; }
    const decision = validateDecision(e.payload["decision"]);
    if (!decision.ok) { skipped++; continue; }
    decided.set(decision.value.action_id, decision.value.outcome);
  }
  const rows: SimulationRow[] = [];
  for (const e of events) {
    if (e.type !== "action.requested") continue;
    if (!validateEvent(e).ok) { skipped++; continue; }
    const action = validateAction(e.payload["descriptor"]);
    if (!action.ok) { skipped++; continue; }
    const d = action.value;
    const next = evaluate(d, bundle).outcome;
    const previous = decided.get(d.action_id) ?? null;
    rows.push({ action_id: d.action_id, previous_outcome: previous, new_outcome: next, changed: previous !== next });
  }
  return { rows, skipped };
}
