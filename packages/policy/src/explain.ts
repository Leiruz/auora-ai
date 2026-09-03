import type { ActionDescriptor, Outcome } from "@auora/contracts";
import { evaluate, matches, type DecisionDraft } from "./evaluate.js";
import { guardTier, type GuardResult } from "./guard.js";
import type { CompiledBundle } from "./types.js";

export interface Candidate { qualified_id: string; layer: string; priority: number; outcome: Outcome }
export interface Explanation { guard: GuardResult | null; candidates: Candidate[]; top_priority: number | null; conflict: boolean; decision: DecisionDraft }

export function explain(d: ActionDescriptor, bundle: CompiledBundle): Explanation {
  const candidates = bundle.rules.filter((r) => matches(r.match, d)).map((r) => ({ qualified_id: r.qualified_id, layer: r.layer, priority: r.priority, outcome: r.outcome }));
  const top = candidates.length === 0 ? null : Math.max(...candidates.map((c) => c.priority));
  const conflict = top !== null && new Set(candidates.filter((c) => c.priority === top).map((c) => c.outcome)).size > 1;
  return { guard: guardTier(d), candidates, top_priority: top, conflict, decision: evaluate(d, bundle) };
}
