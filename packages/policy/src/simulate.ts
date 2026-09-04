import { validateAction, validateDecision, validateEvent, type EventEnvelope, type Outcome } from "@auora/contracts";
import { evaluate } from "./evaluate.js";
import type { CompiledBundle } from "./types.js";

export interface SimulationRow { action_id: string; previous_outcome: Outcome | null; new_outcome: Outcome; changed: boolean }

// `skipped` counts stored events that failed validation (malformed or forged log data) and were
// left out of `rows` rather than trusted; see packages/policy/test/explain.test.ts for the regression.
// `skipped_decision_action_ids` names, best-effort, which action ids a skipped policy.decided event
// belonged to; without it, a row's previous_outcome: null is indistinguishable from an action that
// was genuinely never decided.
export interface SimulationResult { rows: SimulationRow[]; skipped: number; skipped_decision_action_ids: string[] }

// The value here has already failed validation, so this reads action_id defensively (it may be
// missing, or not even an object) rather than trusting its shape.
function peekActionId(value: unknown): string | undefined {
  if (typeof value !== "object" || value === null) return undefined;
  const id = (value as Record<string, unknown>)["action_id"];
  return typeof id === "string" ? id : undefined;
}

export function simulate(events: readonly EventEnvelope[], bundle: CompiledBundle): SimulationResult {
  const decided = new Map<string, Outcome>();
  const skippedDecisionActionIds: string[] = [];
  let skipped = 0;
  for (const e of events) {
    if (e.type !== "policy.decided") continue;
    if (!validateEvent(e).ok) { skipped++; const id = peekActionId(e.payload["decision"]); if (id !== undefined) skippedDecisionActionIds.push(id); continue; }
    const decision = validateDecision(e.payload["decision"]);
    if (!decision.ok) { skipped++; const id = peekActionId(e.payload["decision"]); if (id !== undefined) skippedDecisionActionIds.push(id); continue; }
    decided.set(decision.value.action_id, decision.value.outcome);
  }
  const rows: SimulationRow[] = [];
  for (const e of events) {
    if (e.type !== "action.requested") continue;
    if (!validateEvent(e).ok) { skipped++; continue; }
    // This second check's !ok branch is unreachable in practice: payload_action_requested.descriptor
    // in the event schema already $refs the exact auora.action.v1.json schema validateAction checks,
    // and validateEvent above already ran the same shapeErrors/assertSignable walk over the whole
    // envelope, descriptor included, so any envelope that got past validateEvent already carries a
    // valid descriptor. Kept so `action.value` is typed ActionDescriptor rather than JsonValue; the
    // regression test above ("skips a malformed stored event...") exercises the first check's skip
    // branch, not this one, since its malformed descriptor already fails validateEvent.
    const action = validateAction(e.payload["descriptor"]);
    if (!action.ok) { skipped++; continue; }
    const d = action.value;
    const next = evaluate(d, bundle).outcome;
    const previous = decided.get(d.action_id) ?? null;
    rows.push({ action_id: d.action_id, previous_outcome: previous, new_outcome: next, changed: previous !== next });
  }
  return { rows, skipped, skipped_decision_action_ids: skippedDecisionActionIds };
}
