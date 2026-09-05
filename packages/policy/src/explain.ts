import type { ActionDescriptor, Outcome } from "@auora/contracts";
import { evaluate, isGated, matches, type DecisionDraft } from "./evaluate.js";
import { guardTier, type GuardResult } from "./guard.js";
import type { CompiledBundle, CompiledRule } from "./types.js";

export interface Candidate { qualified_id: string; layer: string; priority: number; outcome: Outcome }
export interface Explanation {
  guard: GuardResult | null;
  /** Ungated rules that matched: these compete on priority, so only they can win outright or produce a conflict. */
  candidates: Candidate[];
  /** Gated rules that matched (labels_any, labels_read_any or signals_any): excluded from the priority contest, so they can only raise the outcome, never win it or conflict. */
  gated_candidates: Candidate[];
  top_priority: number | null;
  conflict: boolean;
  decision: DecisionDraft;
}

function toCandidate(r: CompiledRule): Candidate {
  return { qualified_id: r.qualified_id, layer: r.layer, priority: r.priority, outcome: r.outcome };
}

export function explain(d: ActionDescriptor, bundle: CompiledBundle): Explanation {
  const matched = bundle.rules.filter((r) => matches(r.match, d));
  const candidates = matched.filter((r) => !isGated(r.match)).map(toCandidate);
  const gated_candidates = matched.filter((r) => isGated(r.match)).map(toCandidate);
  const top = candidates.length === 0 ? null : Math.max(...candidates.map((c) => c.priority));
  const conflict = top !== null && new Set(candidates.filter((c) => c.priority === top).map((c) => c.outcome)).size > 1;
  return { guard: guardTier(d), candidates, gated_candidates, top_priority: top, conflict, decision: evaluate(d, bundle) };
}
